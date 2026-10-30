// Tamper: corrupt part of the payload.
#include "common.h"

#define NAME "tamper"

typedef struct {
    ScopeState scope;
    volatile short checksum;  // recompute checksums after tampering
    volatile short chance[2]; // [0, 10000], per direction
    int patIx;
} TamperState;

static const ParamDesc tamperParams[] = {
    { "checksum", "Redo Checksum", PT_BOOL, offsetof(TamperState, checksum), 0, 1, 1, NULL, 0 },
    SCOPE_PARAMS(TamperState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(TamperState, chance), 0, 10000, 1000, NULL, PF_PERDIR },
};

// patterns cover every bit
#define PATTERN_CNT 8
static const unsigned char patterns[PATTERN_CNT] = {
    0x64, 0x13, 0x88,
    0x40, 0x1F, 0xA0,
    0xAA, 0x55
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

static void tamperBuf(TamperState *st, unsigned char *buf, UINT len) {
    UINT ix;
    for (ix = 0; ix < len; ++ix) {
        buf[ix] ^= patterns[st->patIx++ & (PATTERN_CNT - 1)];
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
        if (!scopeMatch(&st->scope, pac) || !rngChance(PERDIR(st->chance, pac))) continue;
        if (!WinDivertHelperParsePacket(pac->packet, pac->packetLen, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                (PVOID *)&data, &dataLen, NULL, NULL) || data == NULL || dataLen == 0) {
            continue;
        }
        // corrupt the middle of the payload: protocols tend to keep checksums at either end
        if (dataLen <= 4) {
            tamperBuf(st, data, dataLen);
        } else {
            UINT quarter = dataLen / 4;
            tamperBuf(st, data + dataLen / 2 - quarter / 2 + 1, quarter);
        }
        if (st->checksum) {
            WinDivertHelperCalcChecksums(pac->packet, pac->packetLen, &pac->addr, 0);
        } else {
            // claim the checksums are valid so the driver does not repair them on reinjection
            pac->addr.IPChecksum = 1;
            pac->addr.TCPChecksum = 1;
            pac->addr.UDPChecksum = 1;
        }
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
