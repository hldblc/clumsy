// Tamper: corrupt packets in several ways, over the payload or the whole packet.
//   xor      - xor a run of bytes with a rolling pattern (the classic clumsy mode)
//   bitflip  - flip N random bits
//   zero     - zero-fill a run of bytes
//   truncate - cut the payload down to N bytes (IP / UDP lengths fixed up)
// Checksum policy: redo (fix), leave (keep stale), or corrupt (flip the checksum).
#include "common.h"

#define NAME "tamper"

enum { TM_XOR = 0, TM_BITFLIP, TM_ZERO, TM_TRUNCATE };
enum { TM_REGION_PAYLOAD = 0, TM_REGION_ALL };
enum { TM_CK_REDO = 0, TM_CK_LEAVE, TM_CK_CORRUPT };

typedef struct {
    ScopeState scope;
    volatile short mode;
    volatile short region;
    volatile short amount;    // bitflip: bits; truncate: bytes to keep
    volatile short checksum;  // TM_CK_*
    volatile short chance[2]; // per direction
    int patIx;
} TamperState;

static const ParamDesc tamperParams[] = {
    { "mode",     "Mode",     PT_ENUM, offsetof(TamperState, mode),   0, 3, TM_XOR, "xor|bitflip|zero|truncate", 0 },
    SCOPE_PARAMS(TamperState),
    { "chance",   "Chance(%)", PT_CHANCE, offsetof(TamperState, chance), 0, 10000, 1000, NULL, PF_PERDIR },
    { "region",   "Region",   PT_ENUM, offsetof(TamperState, region), 0, 1, TM_REGION_PAYLOAD, "payload|all", PF_ADVANCED },
    { "amount",   "Amount",   PT_INT,  offsetof(TamperState, amount), 0, 1400, 8, NULL, PF_ADVANCED },
    { "checksum", "Checksum", PT_ENUM, offsetof(TamperState, checksum), 0, 2, TM_CK_REDO, "redo|leave|corrupt", PF_ADVANCED },
};

#define PATTERN_CNT 8
static const unsigned char patterns[PATTERN_CNT] = {
    0x64, 0x13, 0x88, 0x40, 0x1F, 0xA0, 0xAA, 0x55
};

static void tamperStartUp(ModuleInst *inst, int64_t now) {
    TamperState *st = (TamperState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    st->patIx = 0;
    LOG("tamper enabled");
}

static void tamperCloseDown(ModuleInst *inst, PacketList *list) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(list);
    LOG("tamper disabled");
}

// corrupt [buf, buf+len) per the current mode (not truncate, handled separately)
static void corrupt(TamperState *st, unsigned char *buf, UINT len) {
    UINT i;
    if (len == 0) return;
    switch (st->mode) {
    case TM_BITFLIP: {
        int n = st->amount > 0 ? st->amount : 1;
        while (n-- > 0) {
            UINT bit = (UINT)rngRange(0, (int)(len * 8 - 1));
            buf[bit >> 3] ^= (unsigned char)(1u << (bit & 7));
        }
        break;
    }
    case TM_ZERO:
        memset(buf, 0, len);
        break;
    case TM_XOR:
    default:
        for (i = 0; i < len; ++i) buf[i] ^= patterns[st->patIx++ & (PATTERN_CNT - 1)];
        break;
    }
}

// truncate an IPv4 TCP/UDP packet's payload to keepBytes, fixing lengths
static int truncatePacket(PacketNode *pac, UINT keepBytes) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    unsigned char *data = NULL;
    UINT dataLen = 0, hdrBytes, newLen;
    WinDivertHelperParsePacket(pac->packet, pac->packetLen, &ip, NULL, NULL, NULL, NULL, &tcp, &udp,
                               (PVOID *)&data, &dataLen, NULL, NULL);
    if (ip == NULL || data == NULL || dataLen <= keepBytes) return 0;
    hdrBytes = (UINT)(data - (unsigned char *)pac->packet);
    newLen = hdrBytes + keepBytes;
    pac->packetLen = newLen;
    ip->Length = WinDivertHelperHtons((UINT16)newLen);
    if (udp) udp->Length = WinDivertHelperHtons((UINT16)(newLen - hdrBytes + sizeof(WINDIVERT_UDPHDR)));
    UNREFERENCED_PARAMETER(tcp);
    return 1;
}

static void applyChecksum(TamperState *st, PacketNode *pac) {
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    switch (st->checksum) {
    case TM_CK_LEAVE:
        pac->addr.IPChecksum = 1;
        pac->addr.TCPChecksum = 1;
        pac->addr.UDPChecksum = 1;
        break;
    case TM_CK_CORRUPT:
        WinDivertHelperCalcChecksums(pac->packet, pac->packetLen, &pac->addr, 0);
        WinDivertHelperParsePacket(pac->packet, pac->packetLen, NULL, NULL, NULL, NULL, NULL, &tcp, &udp, NULL, NULL, NULL, NULL);
        if (tcp) tcp->Checksum = (UINT16)~tcp->Checksum;
        else if (udp) udp->Checksum = (UINT16)(udp->Checksum ^ 0xFFFF);
        pac->addr.TCPChecksum = 1;
        pac->addr.UDPChecksum = 1;
        break;
    case TM_CK_REDO:
    default:
        WinDivertHelperCalcChecksums(pac->packet, pac->packetLen, &pac->addr, 0);
        break;
    }
}

static short tamperProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    TamperState *st = (TamperState *)inst->state;
    PacketNode *pac;
    short tampered = 0;
    UNREFERENCED_PARAMETER(now);
    for (pac = listFirst(list); pac != NULL; pac = listNext(list, pac)) {
        unsigned char *data = NULL;
        UINT dataLen = 0;
        int did = 0;
        if (!scopeMatch(&st->scope, pac) || !rngChance(PERDIR(st->chance, pac))) continue;

        if (st->mode == TM_TRUNCATE) {
            did = truncatePacket(pac, st->amount >= 0 ? (UINT)st->amount : 0);
        } else if (st->region == TM_REGION_ALL) {
            corrupt(st, (unsigned char *)pac->packet, pac->packetLen);
            did = 1;
        } else {
            if (WinDivertHelperParsePacket(pac->packet, pac->packetLen, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                    (PVOID *)&data, &dataLen, NULL, NULL) && data != NULL && dataLen != 0) {
                if (st->mode == TM_XOR && dataLen > 4) {
                    // classic behaviour: a quarter in the middle
                    UINT quarter = dataLen / 4;
                    corrupt(st, data + dataLen / 2 - quarter / 2 + 1, quarter);
                } else {
                    corrupt(st, data, dataLen);
                }
                did = 1;
            }
        }
        if (!did) continue;
        applyChecksum(st, pac);
        pac->flags |= PN_FLAG_TAMPERED;
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);
        tampered = 1;
    }
    return tampered;
}

const ModuleDesc tamperModuleDesc = {
    "Tamper", NAME, sizeof(TamperState),
    tamperParams, (int)(sizeof(tamperParams) / sizeof(tamperParams[0])),
    NULL, NULL, NULL,
    tamperStartUp, tamperCloseDown, tamperProcess, NULL,
    NULL, NULL
};
