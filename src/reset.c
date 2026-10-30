// Set TCP RST: flag TCP packets with RST, by chance or on demand.
#include "common.h"

#define NAME "reset"

typedef struct {
    ScopeState scope;
    volatile short chance[2];     // [0, 10000], per direction
    volatile short setNextCount;  // RST the next N matching packets (button)
} ResetState;

static const ParamDesc resetParams[] = {
    SCOPE_PARAMS(ResetState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(ResetState, chance), 0, 10000, 0, NULL, PF_PERDIR },
};

static void resetAction(ModuleInst *inst) {
    ResetState *st = (ResetState *)inst->state;
    if (!inst->enabled) return;
    atomicInc16(&st->setNextCount);
}

static void resetStartUp(ModuleInst *inst, int64_t now) {
    ResetState *st = (ResetState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    atomicExch16(&st->setNextCount, 0);
    LOG("reset enabled");
}

static void resetCloseDown(ModuleInst *inst, PacketList *list) {
    ResetState *st = (ResetState *)inst->state;
    UNREFERENCED_PARAMETER(list);
    atomicExch16(&st->setNextCount, 0);
    LOG("reset disabled");
}

static short resetProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    ResetState *st = (ResetState *)inst->state;
    PacketNode *pac;
    short reset = 0;
    UNREFERENCED_PARAMETER(now);
    for (pac = listFirst(list); pac != NULL; pac = listNext(list, pac)) {
        PWINDIVERT_TCPHDR tcp = NULL;
        if (!scopeMatch(&st->scope, pac)) continue;
        if (!(st->setNextCount > 0 || rngChance(PERDIR(st->chance, pac)))) continue;
        WinDivertHelperParsePacket(pac->packet, pac->packetLen, NULL, NULL, NULL, NULL, NULL, &tcp, NULL, NULL, NULL, NULL, NULL);
        if (tcp == NULL) continue;
        LOG("injecting RST");
        tcp->Rst = 1;
        WinDivertHelperCalcChecksums(pac->packet, pac->packetLen, &pac->addr, 0);
        pac->flags |= PN_FLAG_RST;
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);
        reset = 1;
        if (st->setNextCount > 0) {
            atomicDec16(&st->setNextCount);
        }
    }
    return reset;
}

const ModuleDesc resetModuleDesc = {
    "Set TCP RST", NAME, sizeof(ResetState),
    resetParams, (int)(sizeof(resetParams) / sizeof(resetParams[0])),
    NULL, NULL, NULL,
    resetStartUp, resetCloseDown, resetProcess, NULL,
    "RST next packet", resetAction
};
