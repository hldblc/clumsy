// Drop: discard packets with a given chance, independently or in bursts.
//
// Bursty mode is a two-state Gilbert-Elliott model: a "good" state that never
// drops and a "bad" state that drops with the burst loss rate. The transition
// probabilities are derived so the long-run loss still equals the chance field
// and the average bad run lasts "burst length" packets.
#include "common.h"

#define NAME "drop"

typedef struct {
    ScopeState scope;
    volatile short chance[2];   // overall loss, [0, 10000], per direction
    volatile short burst;       // use the Gilbert-Elliott model
    volatile short burstLen;    // mean packets per bad run
    volatile short burstLoss;   // loss inside a bad run, [0, 10000]
    int inBad;
} DropState;

static const ParamDesc dropParams[] = {
    SCOPE_PARAMS(DropState),
    { "chance",    "Chance(%)",        PT_CHANCE, offsetof(DropState, chance),    0, 10000, 1000, NULL, PF_PERDIR },
    { "burst",     "Bursty",           PT_BOOL,   offsetof(DropState, burst),     0, 1, 0, NULL, PF_ADVANCED },
    { "burstlen",  "Burst len(pkts)",  PT_INT,    offsetof(DropState, burstLen),  1, 1000, 5, NULL, PF_ADVANCED },
    { "burstloss", "Loss in burst(%)", PT_CHANCE, offsetof(DropState, burstLoss), 0, 10000, 10000, NULL, PF_ADVANCED },
};

static void dropStartUp(ModuleInst *inst, int64_t now) {
    DropState *st = (DropState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    st->inBad = 0;
    LOG("drop enabled");
}

static void dropCloseDown(ModuleInst *inst, PacketList *list) {
    UNREFERENCED_PARAMETER(inst);
    UNREFERENCED_PARAMETER(list);
    LOG("drop disabled");
}

static int burstShouldDrop(DropState *st, short chance) {
    double p = chance / 10000.0;                 // target overall loss
    double h = st->burstLoss / 10000.0;          // loss while bad
    double len = st->burstLen < 1 ? 1.0 : (double)st->burstLen;
    double stayBad = 1.0 - 1.0 / len;            // P(bad -> bad)
    double badShare = h > 0.0 ? p / h : 1.0;     // stationary share of time in bad
    double toBad;
    if (badShare >= 1.0) {
        badShare = 1.0;
        toBad = 1.0;
    } else {
        toBad = badShare * (1.0 - stayBad) / (1.0 - badShare);  // P(good -> bad)
    }
    if (!st->inBad) {
        if (rngUniform() < toBad) st->inBad = 1;
    } else {
        if (rngUniform() >= stayBad) st->inBad = 0;
    }
    return st->inBad && rngUniform() < h;
}

static short dropProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    DropState *st = (DropState *)inst->state;
    PacketNode *pac, *next;
    short dropped = 0;
    UNREFERENCED_PARAMETER(now);
    for (pac = listFirst(list); pac != NULL; pac = next) {
        int hit;
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        hit = st->burst ? burstShouldDrop(st, PERDIR(st->chance, pac)) : rngChance(PERDIR(st->chance, pac));
        if (!hit) continue;
        LOG("dropped, %s", pac->addr.Outbound ? "outbound" : "inbound");
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);
        atomicAdd64(&inst->stats.dropped, 1);
        packetFree(listUnlink(list, pac));
        dropped = 1;
    }
    return dropped;
}

const ModuleDesc dropModuleDesc = {
    "Drop", NAME, sizeof(DropState),
    dropParams, (int)(sizeof(dropParams) / sizeof(dropParams[0])),
    NULL, NULL, NULL,
    dropStartUp, dropCloseDown, dropProcess, NULL,
    NULL, NULL
};
