// Drop: discard packets with a given chance.
#include "common.h"

#define NAME "drop"

typedef struct {
    ScopeState scope;
    volatile short chance;    // [0, 10000]
} DropState;

static const ParamDesc dropParams[] = {
    SCOPE_PARAMS(DropState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(DropState, chance), 0, 10000, 1000, NULL, 0 },
};

static void dropStartUp(ModuleInst *inst, int64_t now) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(now);
    LOG("drop enabled");
}

static void dropCloseDown(ModuleInst *inst, PacketList *list) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(list);
    LOG("drop disabled");
}

static short dropProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    DropState *st = (DropState *)inst->state;
    PacketNode *pac, *next;
    short dropped = 0;
    UNREFERENCED_PARAMETER(now);
    for (pac = listFirst(list); pac != NULL; pac = next) {
        next = listNext(list, pac);
        if (scopeMatch(&st->scope, pac) && rngChance(st->chance)) {
            LOG("dropped with chance %.1f%%, %s", st->chance / 100.0, pac->addr.Outbound ? "outbound" : "inbound");
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
            atomicAdd64(&inst->stats.dropped, 1);
            packetFree(listUnlink(list, pac));
            dropped = 1;
        }
    }
    return dropped;
}

const ModuleDesc dropModuleDesc = {
    "Drop", NAME, sizeof(DropState),
    dropParams, (int)(sizeof(dropParams) / sizeof(dropParams[0])),
    NULL, NULL, NULL,
    dropStartUp, dropCloseDown, dropProcess, NULL
};
