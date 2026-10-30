// Set TCP RST: flag TCP packets with RST, by chance or on demand.
#include "iup.h"
#include "common.h"
#include "uibind.h"

#define NAME "reset"

typedef struct {
    ScopeState scope;
    volatile short chance;        // [0, 10000]
    volatile short setNextCount;  // RST the next N matching packets (button)
} ResetState;

static const ParamDesc resetParams[] = {
    SCOPE_PARAMS(ResetState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(ResetState, chance), 0, 10000, 0, NULL, 0 },
};

static int resetNextButtonCb(Ihandle *ih) {
    ModuleInst *inst = (ModuleInst *)IupGetAttribute(ih, UI_ATTR_INST);
    ResetState *st = (ResetState *)inst->state;
    if (!inst->enabled) return IUP_DEFAULT;
    atomicInc16(&st->setNextCount);
    return IUP_DEFAULT;
}

static Ihandle *resetSetupUI(ModuleInst *inst) {
    Ihandle *row = uiBuildParamRow(inst, 0);
    Ihandle *button = IupButton("RST next packet", NULL);
    IupSetAttribute(button, UI_ATTR_INST, (char *)inst);
    IupSetAttribute(button, "PADDING", "4x");
    IupSetCallback(button, "ACTION", resetNextButtonCb);
    IupInsert(row, IupGetChild(row, 0), button);
    return row;
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
        if (!(st->setNextCount > 0 || rngChance(st->chance))) continue;
        WinDivertHelperParsePacket(pac->packet, pac->packetLen, NULL, NULL, NULL, NULL, NULL, &tcp, NULL, NULL, NULL, NULL, NULL);
        if (tcp == NULL) continue;
        LOG("injecting RST with chance %.1f%%", st->chance / 100.0);
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
    resetSetupUI, NULL, NULL,
    resetStartUp, resetCloseDown, resetProcess, NULL
};
