// Out of order: hold a lone packet until the next one arrives, or swap
// neighbouring packets when several are queued.
#include "common.h"

#define NAME "ood"
#define OOD_HOLD_MAX_US 400000   // give up holding after this long

typedef struct {
    ScopeState scope;
    volatile short chance;    // [0, 10000]
    PacketNode *held;
    int64_t heldSince;
} OodState;

static const ParamDesc oodParams[] = {
    SCOPE_PARAMS(OodState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(OodState, chance), 0, 10000, 1000, NULL, 0 },
};

static void oodStartUp(ModuleInst *inst, int64_t now) {
    OodState *st = (OodState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    assert(st->held == NULL);
    st->held = NULL;
    LOG("ood enabled");
}

static void oodCloseDown(ModuleInst *inst, PacketList *list) {
    OodState *st = (OodState *)inst->state;
    if (st->held != NULL) {
        listPushBack(list, st->held);
        st->held = NULL;
    }
    atomicExch32(&inst->stats.queued, 0);
    LOG("ood disabled");
}

static PacketNode *nextMatching(OodState *st, PacketList *list, PacketNode *from) {
    PacketNode *p = from ? listNext(list, from) : listFirst(list);
    while (p != NULL && !scopeMatch(&st->scope, p)) {
        p = listNext(list, p);
    }
    return p;
}

static short oodProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    OodState *st = (OodState *)inst->state;
    PacketNode *pac, *first, *second;
    short acted = 0;

    if (st->held != NULL) {
        // release behind whatever arrived since, or give up after a while
        if (!listEmpty(list) || now - st->heldSince >= OOD_HOLD_MAX_US) {
            LOG("ood releasing held %s packet", st->held->addr.Outbound ? "outbound" : "inbound");
            listPushBack(list, st->held);
            st->held = NULL;
            atomicExch32(&inst->stats.queued, 0);
        }
        return 1;
    }

    if (listEmpty(list)) {
        return 0;
    }

    if (listCount(list) == 1) {
        pac = listFirst(list);
        if (scopeMatch(&st->scope, pac) && rngChance(st->chance)) {
            listUnlink(list, pac);
            pac->flags |= PN_FLAG_REORDERED;
            st->held = pac;
            st->heldSince = now;
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
            atomicExch32(&inst->stats.queued, 1);
            LOG("ood holding one packet");
            return 1;
        }
        return 0;
    }

    // several packets queued: swapping neighbours is enough
    if (!rngChance(st->chance)) {
        return 0;
    }
    first = nextMatching(st, list, NULL);
    while (first != NULL) {
        second = nextMatching(st, list, first);
        if (second == NULL) break;
        if (rngChance(st->chance)) {
            listSwap(list, first, second);
            first->flags |= PN_FLAG_REORDERED;
            second->flags |= PN_FLAG_REORDERED;
            atomicAdd64(&inst->stats.packets, 2);
            acted = 1;
            first = nextMatching(st, list, first);
        } else {
            first = second;
        }
    }
    return acted;
}

static int64_t oodNextDeadline(ModuleInst *inst, int64_t now) {
    OodState *st = (OodState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    return st->held ? st->heldSince + OOD_HOLD_MAX_US : -1;
}

const ModuleDesc oodModuleDesc = {
    "Out of order", NAME, sizeof(OodState),
    oodParams, (int)(sizeof(oodParams) / sizeof(oodParams[0])),
    NULL, NULL, NULL,
    oodStartUp, oodCloseDown, oodProcess, oodNextDeadline
};
