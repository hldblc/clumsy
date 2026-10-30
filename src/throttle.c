// Throttle: with some chance, start holding packets for a time frame, then
// release them all at once (or drop them).
#include "common.h"

#define NAME "throttle"
#define THROTTLE_KEEP_AT_MOST 1000

typedef struct {
    ScopeState scope;
    volatile short dropThrottled;
    volatile short frame;     // ms
    volatile short chance;    // [0, 10000]
    PacketList buf;
    int64_t startTime;        // 0 when not throttling
} ThrottleState;

static const ParamDesc throttleParams[] = {
    { "drop",  "Drop Throttled", PT_BOOL, offsetof(ThrottleState, dropThrottled), 0, 1, 0, NULL, 0 },
    { "frame", "Timeframe(ms)",  PT_INT,  offsetof(ThrottleState, frame), 0, 1000, 30, NULL, 0 },
    SCOPE_PARAMS(ThrottleState),
    { "chance", "Chance(%)", PT_CHANCE, offsetof(ThrottleState, chance), 0, 10000, 1000, NULL, 0 },
};

static void throttleInit(ModuleInst *inst) {
    ThrottleState *st = (ThrottleState *)inst->state;
    listInit(&st->buf);
}

static void throttleStartUp(ModuleInst *inst, int64_t now) {
    ThrottleState *st = (ThrottleState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    listEnsureInit(&st->buf);
    assert(listEmpty(&st->buf));
    st->startTime = 0;
}

static void throttleCloseDown(ModuleInst *inst, PacketList *list) {
    ThrottleState *st = (ThrottleState *)inst->state;
    LOG("closing throttle, releasing %d packets", listCount(&st->buf));
    listAppendAll(list, &st->buf);
    st->startTime = 0;
    atomicExch32(&inst->stats.queued, 0);
}

static short throttleProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    ThrottleState *st = (ThrottleState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;

    if (st->startTime == 0) {
        if (!listEmpty(list) && rngChance(st->chance)) {
            LOG("start throttling, chance %.1f%%, frame %d ms", st->chance / 100.0, st->frame);
            st->startTime = now;
        }
    }

    if (st->startTime != 0) {
        for (pac = listFirst(list); pac != NULL; pac = next) {
            next = listNext(list, pac);
            if (listCount(&st->buf) >= THROTTLE_KEEP_AT_MOST) break;
            if (!scopeMatch(&st->scope, pac)) continue;
            listUnlink(list, pac);
            pac->flags |= PN_FLAG_THROTTLED;
            listPushBack(&st->buf, pac);
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
        }
        if (listCount(&st->buf) >= THROTTLE_KEEP_AT_MOST || now - st->startTime > MS_TO_US(st->frame)) {
            if (st->dropThrottled) {
                LOG("throttle ended, dropping %d packets", listCount(&st->buf));
                atomicAdd64(&inst->stats.dropped, listCount(&st->buf));
                listFreeAll(&st->buf);
            } else {
                LOG("throttle ended, releasing %d packets", listCount(&st->buf));
                listAppendAll(list, &st->buf);
            }
            st->startTime = 0;
        }
        acted = 1;
    }

    atomicExch32(&inst->stats.queued, listCount(&st->buf));
    return acted;
}

static int64_t throttleNextDeadline(ModuleInst *inst, int64_t now) {
    ThrottleState *st = (ThrottleState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    return st->startTime ? st->startTime + MS_TO_US(st->frame) : -1;
}

const ModuleDesc throttleModuleDesc = {
    "Throttle", NAME, sizeof(ThrottleState),
    throttleParams, (int)(sizeof(throttleParams) / sizeof(throttleParams[0])),
    NULL, throttleInit, NULL,
    throttleStartUp, throttleCloseDown, throttleProcess, throttleNextDeadline
};
