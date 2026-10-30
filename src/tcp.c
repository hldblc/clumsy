// TCP aware impairments: drop SYNs or pure ACKs, delay retransmissions,
// clamp the advertised window, strip options from SYN segments. Everything
// here acts on packets already captured on this machine, in place or by
// dropping / briefly holding them.
#include <stdlib.h>
#include "common.h"

#define NAME "tcp"
#define TCP_FLOWS 4096                 // power of two
#define TCP_FLOW_IDLE_US 60000000LL    // forget a flow after a minute of silence
#define TCP_KEEP_AT_MOST 2000

typedef struct {
    uint64_t key;
    uint32_t seqEnd;      // highest sequence number seen (exclusive)
    uint32_t used;
    int64_t lastSeen;
} TcpFlow;

typedef struct {
    ScopeState scope;
    volatile short dropSyn;     // chance
    volatile short dropAck;     // chance, pure ACKs only
    volatile short retransMs;   // hold retransmitted segments this long, 0 off
    volatile LONG window;       // clamp advertised window to this, 0 off
    volatile short strip;       // strip options from SYN segments
    TcpFlow *flows;
    PacketList held;
} TcpState;

static const ParamDesc tcpParams[] = {
    SCOPE_PARAMS(TcpState),
    { "syn",     "Drop SYN(%)",       PT_CHANCE, offsetof(TcpState, dropSyn),   0, 10000, 0, NULL, 0 },
    { "ack",     "Drop pure ACK(%)",  PT_CHANCE, offsetof(TcpState, dropAck),   0, 10000, 0, NULL, 0 },
    { "retrans", "Delay retrans(ms)", PT_INT,    offsetof(TcpState, retransMs), 0, 15000, 0, NULL, 0 },
    { "window",  "Clamp window",      PT_INT32,  offsetof(TcpState, window),    0, 65535, 0, NULL, PF_ADVANCED },
    { "strip",   "Strip SYN options", PT_BOOL,   offsetof(TcpState, strip),     0, 1, 0, NULL, PF_ADVANCED },
};

static void tcpInit(ModuleInst *inst) {
    TcpState *st = (TcpState *)inst->state;
    st->flows = (TcpFlow *)calloc(TCP_FLOWS, sizeof(TcpFlow));
    listInit(&st->held);
}

static void tcpDestroy(ModuleInst *inst) {
    TcpState *st = (TcpState *)inst->state;
    free(st->flows);
    st->flows = NULL;
    listFreeAll(&st->held);
}

static void tcpStartUp(ModuleInst *inst, int64_t now) {
    TcpState *st = (TcpState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    if (st->flows) memset(st->flows, 0, sizeof(TcpFlow) * TCP_FLOWS);
    listEnsureInit(&st->held);
    assert(listEmpty(&st->held));
    LOG("tcp enabled");
}

static void tcpCloseDown(ModuleInst *inst, PacketList *list) {
    TcpState *st = (TcpState *)inst->state;
    listAppendAll(list, &st->held);
    atomicExch32(&inst->stats.queued, 0);
    LOG("tcp disabled");
}

static TcpFlow *flowLookup(TcpState *st, uint64_t key, int64_t now) {
    uint32_t h = (uint32_t)(key ^ (key >> 29) ^ (key >> 47)) & (TCP_FLOWS - 1);
    TcpFlow *victim = NULL;
    int i;
    if (st->flows == NULL) return NULL;
    for (i = 0; i < 8; ++i) {
        TcpFlow *f = &st->flows[(h + i) & (TCP_FLOWS - 1)];
        if (f->used && f->key == key) return f;
        if (!f->used || now - f->lastSeen > TCP_FLOW_IDLE_US) {
            if (victim == NULL || victim->used) victim = f;
        } else if (victim == NULL || (victim->used && f->lastSeen < victim->lastSeen)) {
            victim = f;
        }
    }
    victim->key = key;
    victim->used = 0;
    victim->seqEnd = 0;
    victim->lastSeen = now;
    return victim;
}

// true when every byte of this segment was already seen on the flow
static int isRetransmit(TcpState *st, PacketNode *pac, PWINDIVERT_TCPHDR tcp, UINT dataLen, int64_t now) {
    uint64_t key = pac->flowHash ^ (pac->addr.Outbound ? 0x9E3779B97F4A7C15ULL : 0x5851F42D4C957F2DULL);
    TcpFlow *f = flowLookup(st, key, now);
    uint32_t seq = WinDivertHelperNtohl(tcp->SeqNum);
    uint32_t seqEnd = seq + dataLen;
    if (f == NULL) return 0;
    f->lastSeen = now;
    if (tcp->Syn || tcp->Rst || !f->used) {
        f->used = 1;
        f->seqEnd = seqEnd;
        return 0;
    }
    if ((int32_t)(seqEnd - f->seqEnd) <= 0) {
        return 1;
    }
    f->seqEnd = seqEnd;
    return 0;
}

static void stripOptions(PacketNode *pac, PWINDIVERT_IPHDR ip, PWINDIVERT_IPV6HDR ip6, PWINDIVERT_TCPHDR tcp) {
    char *tcpStart = (char *)tcp;
    UINT hdrBytes = (UINT)tcp->HdrLength * 4;
    UINT remove = hdrBytes - 20;
    UINT tailOff = (UINT)(tcpStart - pac->packet) + hdrBytes;
    if (remove == 0 || tailOff > pac->packetLen) return;
    memmove(tcpStart + 20, tcpStart + hdrBytes, pac->packetLen - tailOff);
    tcp->HdrLength = 5;
    pac->packetLen -= remove;
    if (ip) {
        ip->Length = WinDivertHelperHtons((UINT16)(WinDivertHelperNtohs(ip->Length) - remove));
    } else if (ip6) {
        ip6->Length = WinDivertHelperHtons((UINT16)(WinDivertHelperNtohs(ip6->Length) - remove));
    }
}

static void holdSorted(PacketList *buf, PacketNode *pac) {
    PacketNode *q = listLast(buf);
    while (q != NULL && q->releaseTime > pac->releaseTime) q = listPrev(buf, q);
    if (q) listInsertAfter(buf, pac, q); else listPushFront(buf, pac);
}

static short tcpProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    TcpState *st = (TcpState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;

    for (pac = listFirst(list); pac != NULL; pac = next) {
        PWINDIVERT_IPHDR ip = NULL;
        PWINDIVERT_IPV6HDR ip6 = NULL;
        PWINDIVERT_TCPHDR tcp = NULL;
        PVOID data = NULL;
        UINT dataLen = 0;
        int pureAck, modified = 0;
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        WinDivertHelperParsePacket(pac->packet, pac->packetLen, &ip, &ip6, NULL, NULL, NULL, &tcp, NULL, &data, &dataLen, NULL, NULL);
        if (tcp == NULL) continue;
        pureAck = tcp->Ack && !tcp->Syn && !tcp->Fin && !tcp->Rst && dataLen == 0;

        if (tcp->Syn && rngChance(st->dropSyn)) {
            LOG("dropping SYN");
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.dropped, 1);
            packetFree(listUnlink(list, pac));
            acted = 1;
            continue;
        }
        if (pureAck && rngChance(st->dropAck)) {
            LOG("dropping pure ACK");
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.dropped, 1);
            packetFree(listUnlink(list, pac));
            acted = 1;
            continue;
        }
        if (st->retransMs > 0 && dataLen > 0 && listCount(&st->held) < TCP_KEEP_AT_MOST
                && isRetransmit(st, pac, tcp, dataLen, now)) {
            LOG("holding retransmission for %d ms", st->retransMs);
            listUnlink(list, pac);
            pac->releaseTime = now + MS_TO_US(st->retransMs);
            pac->flags |= PN_FLAG_TCPMOD | PN_FLAG_LAGGED;
            holdSorted(&st->held, pac);
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
            acted = 1;
            continue;
        }
        if (st->window > 0 && WinDivertHelperNtohs(tcp->Window) > (UINT16)st->window) {
            tcp->Window = WinDivertHelperHtons((UINT16)st->window);
            modified = 1;
        }
        if (st->strip && tcp->Syn && tcp->HdrLength > 5) {
            stripOptions(pac, ip, ip6, tcp);
            modified = 1;
        }
        if (modified) {
            WinDivertHelperCalcChecksums(pac->packet, pac->packetLen, &pac->addr, 0);
            pac->flags |= PN_FLAG_TCPMOD;
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
            acted = 1;
        }
    }

    while ((pac = listFirst(&st->held)) != NULL && pac->releaseTime <= now) {
        listUnlink(&st->held, pac);
        listPushBack(list, pac);
        acted = 1;
    }
    atomicExch32(&inst->stats.queued, listCount(&st->held));
    return acted;
}

static int64_t tcpNextDeadline(ModuleInst *inst, int64_t now) {
    TcpState *st = (TcpState *)inst->state;
    PacketNode *pac = listFirst(&st->held);
    UNREFERENCED_PARAMETER(now);
    return pac ? pac->releaseTime : -1;
}

const ModuleDesc tcpModuleDesc = {
    "TCP", NAME, sizeof(TcpState),
    tcpParams, (int)(sizeof(tcpParams) / sizeof(tcpParams[0])),
    NULL, tcpInit, tcpDestroy,
    tcpStartUp, tcpCloseDown, tcpProcess, tcpNextDeadline,
    NULL, NULL
};
