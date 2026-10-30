// Fragment / MTU stress: split IPv4 packets larger than a configured MTU into
// IP fragments, exercising the receiver's path-MTU discovery and reassembly.
// Optionally drop one fragment of each packet so reassembly never completes.
//
// IPv4 only: IPv6 fragmentation needs an extension header; those packets pass
// through untouched.
#include <stdlib.h>
#include "common.h"

#define NAME "fragment"
#define FRAG_MAX_PIECES 64

typedef struct {
    ScopeState scope;
    volatile short mtu;        // bytes, total IP size per fragment
    volatile short loseFrag;   // chance to drop one fragment of a packet
} FragState;

static const ParamDesc fragParams[] = {
    SCOPE_PARAMS(FragState),
    { "mtu",  "MTU(bytes)",      PT_INT,    offsetof(FragState, mtu),      28, 1500, 576, NULL, 0 },
    { "lose", "Lose a frag(%)",  PT_CHANCE, offsetof(FragState, loseFrag), 0, 10000, 0, NULL, PF_ADVANCED },
};

static void fragStartUp(ModuleInst *inst, int64_t now) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(now);
    LOG("fragment enabled");
}

static void fragCloseDown(ModuleInst *inst, PacketList *list) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(list);
    LOG("fragment disabled");
}

// 16-bit flags+offset field helpers (offset in 8-byte units, MF is bit 13)
static UINT16 makeFragField(int mf, UINT offUnits) {
    return WinDivertHelperHtons((UINT16)(((mf ? 1 : 0) << 13) | (offUnits & 0x1FFF)));
}

static short fragProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    FragState *st = (FragState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;
    int mtu = st->mtu;
    UNREFERENCED_PARAMETER(now);

    for (pac = listFirst(list); pac != NULL; pac = next) {
        PWINDIVERT_IPHDR ip = NULL;
        PWINDIVERT_IPV6HDR ip6 = NULL;
        UINT hlen, payloadLen, pieceMax, origFragField, baseOffUnits;
        int origMf, pieces, i, loseIx;
        const unsigned char *payload;
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        if ((UINT)mtu >= pac->packetLen) continue;
        WinDivertHelperParsePacket(pac->packet, pac->packetLen, &ip, &ip6, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        if (ip == NULL) continue;                    // IPv4 only
        hlen = (UINT)ip->HdrLength * 4;
        if (hlen < 20 || hlen >= (UINT)mtu || hlen > pac->packetLen) continue;
        payloadLen = pac->packetLen - hlen;
        pieceMax = ((UINT)mtu - hlen) & ~7u;         // multiple of 8 bytes
        if (pieceMax == 0) continue;
        pieces = (int)((payloadLen + pieceMax - 1) / pieceMax);
        if (pieces < 2 || pieces > FRAG_MAX_PIECES) continue;

        // keep the original packet's own offset and MF (usually 0 / clear)
        origFragField = WinDivertHelperNtohs(ip->FragOff0);
        baseOffUnits = origFragField & 0x1FFF;
        origMf = (origFragField >> 13) & 1;
        payload = (const unsigned char *)pac->packet + hlen;

        loseIx = rngChance(st->loseFrag) ? rngRange(0, pieces - 1) : -1;

        for (i = 0; i < pieces; ++i) {
            UINT off = (UINT)i * pieceMax;
            UINT sliceLen = payloadLen - off < pieceMax ? payloadLen - off : pieceMax;
            int lastPiece = (i == pieces - 1);
            PacketNode *frag;
            PWINDIVERT_IPHDR fip;
            if (i == loseIx) {
                atomicAdd64(&inst->stats.dropped, 1);
                continue;                            // this fragment never gets built
            }
            frag = packetAlloc(NULL, hlen + sliceLen, &pac->addr);
            if (frag == NULL) break;
            memcpy(frag->packet, pac->packet, hlen);
            memcpy(frag->packet + hlen, payload + off, sliceLen);
            fip = (PWINDIVERT_IPHDR)frag->packet;
            fip->Length = WinDivertHelperHtons((UINT16)(hlen + sliceLen));
            fip->FragOff0 = makeFragField(lastPiece ? origMf : 1, baseOffUnits + off / 8);
            WinDivertHelperCalcChecksums(frag->packet, frag->packetLen, &frag->addr, 0);
            frag->captureTime = pac->captureTime;
            frag->flowHash = pac->flowHash;
            frag->processId = pac->processId;
            frag->ruleIndex = pac->ruleIndex;
            frag->flags = (uint16_t)(pac->flags | PN_FLAG_FRAGMENT);
            listInsertBefore(list, frag, pac);
            atomicAdd64(&inst->stats.bytes, frag->packetLen);
        }
        atomicAdd64(&inst->stats.packets, 1);
        packetFree(listUnlink(list, pac));           // drop the oversized original
        acted = 1;
    }
    return acted;
}

const ModuleDesc fragmentModuleDesc = {
    "Fragment", NAME, sizeof(FragState),
    fragParams, (int)(sizeof(fragParams) / sizeof(fragParams[0])),
    NULL, NULL, NULL,
    fragStartUp, fragCloseDown, fragProcess, NULL,
    NULL, NULL
};
