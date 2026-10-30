// Duplicate: send extra copies of a packet.
#include "common.h"

#define NAME "duplicate"

typedef struct {
    ScopeState scope;
    volatile short count;     // total copies including the original
    volatile short chance;    // [0, 10000]
} DupState;

static const ParamDesc dupParams[] = {
    { "count", "Count", PT_INT, offsetof(DupState, count), 2, 50, 2, NULL, 0 },
    SCOPE_PARAMS(DupState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(DupState, chance), 0, 10000, 1000, NULL, 0 },
};

static void dupStartUp(ModuleInst *inst, int64_t now) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(now);
    LOG("dup enabled");
}

static void dupCloseDown(ModuleInst *inst, PacketList *list) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(list);
    LOG("dup disabled");
}

static short dupProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    DupState *st = (DupState *)inst->state;
    PacketNode *pac, *next;
    short duped = 0;
    UNREFERENCED_PARAMETER(now);
    for (pac = listFirst(list); pac != NULL; pac = next) {
        next = listNext(list, pac);   // taken before inserting so copies are skipped
        if (scopeMatch(&st->scope, pac) && rngChance(st->chance)) {
            int copies = st->count - 1;
            LOG("duplicating with chance %.1f%%, %d extra copies", st->chance / 100.0, copies);
            while (copies-- > 0) {
                PacketNode *copy = packetClone(pac);
                if (copy == NULL) break;
                listInsertAfter(list, copy, pac);
                atomicAdd64(&inst->stats.bytes, copy->packetLen);
            }
            atomicAdd64(&inst->stats.packets, 1);
            duped = 1;
        }
    }
    return duped;
}

const ModuleDesc dupModuleDesc = {
    "Duplicate", NAME, sizeof(DupState),
    dupParams, (int)(sizeof(dupParams) / sizeof(dupParams[0])),
    NULL, NULL, NULL,
    dupStartUp, dupCloseDown, dupProcess, NULL
};
