// Lag: hold packets for a delay, release them in order of their release time.
#include "common.h"

#define NAME "lag"
#define LAG_KEEP_AT_MOST 2000
#define LAG_FLUSH_WHEN_FULL 800

typedef struct {
    ScopeState scope;
    volatile short time[2];   // delay in ms, per direction
    PacketList buf;           // held packets ordered by releaseTime
} LagState;

static const ParamDesc lagParams[] = {
    SCOPE_PARAMS(LagState),
    { "time", "Delay(ms)", PT_INT, offsetof(LagState, time), 0, 15000, 50, NULL, PF_PERDIR },
};

static void lagInit(ModuleInst *inst) {
    LagState *st = (LagState *)inst->state;
    listInit(&st->buf);
}

static void lagStartUp(ModuleInst *inst, int64_t now) {
    LagState *st = (LagState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    listEnsureInit(&st->buf);
    assert(listEmpty(&st->buf));
}

static void lagCloseDown(ModuleInst *inst, PacketList *list) {
    LagState *st = (LagState *)inst->state;
    LOG("closing lag, flushing %d packets", listCount(&st->buf));
    listAppendAll(list, &st->buf);
    atomicExch32(&inst->stats.queued, 0);
}

static void lagInsertSorted(PacketList *buf, PacketNode *pac) {
    PacketNode *q = listLast(buf);
    while (q != NULL && q->releaseTime > pac->releaseTime) {
        q = listPrev(buf, q);
    }
    if (q != NULL) {
        listInsertAfter(buf, pac, q);
    } else {
        listPushFront(buf, pac);
    }
}

static short lagProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    LagState *st = (LagState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;

    // pick up matching packets and stamp their release time
    for (pac = listFirst(list); pac != NULL; pac = next) {
        next = listNext(list, pac);
        if (listCount(&st->buf) >= LAG_KEEP_AT_MOST) break;
        if (!scopeMatch(&st->scope, pac)) continue;
        listUnlink(list, pac);
        pac->releaseTime = pac->captureTime + MS_TO_US(PERDIR(st->time, pac));
        pac->flags |= PN_FLAG_LAGGED;
        lagInsertSorted(&st->buf, pac);
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);
        acted = 1;
    }

    // release everything that is due
    while ((pac = listFirst(&st->buf)) != NULL && pac->releaseTime <= now) {
        listUnlink(&st->buf, pac);
        listPushBack(list, pac);
        acted = 1;
    }

    // buffer full: push out the oldest batch rather than grow without bound
    if (listCount(&st->buf) >= LAG_KEEP_AT_MOST) {
        int n = LAG_FLUSH_WHEN_FULL;
        LOG("lag buffer full, flushing %d packets", n);
        while (n-- > 0 && (pac = listFirst(&st->buf)) != NULL) {
            listUnlink(&st->buf, pac);
            listPushBack(list, pac);
        }
    }

    atomicExch32(&inst->stats.queued, listCount(&st->buf));
    return (short)(acted || !listEmpty(&st->buf));
}

static int64_t lagNextDeadline(ModuleInst *inst, int64_t now) {
    LagState *st = (LagState *)inst->state;
    PacketNode *pac = listFirst(&st->buf);
    UNREFERENCED_PARAMETER(now);
    return pac ? pac->releaseTime : -1;
}

const ModuleDesc lagModuleDesc = {
    "Lag", NAME, sizeof(LagState),
    lagParams, (int)(sizeof(lagParams) / sizeof(lagParams[0])),
    NULL, lagInit, NULL,
    lagStartUp, lagCloseDown, lagProcess, lagNextDeadline
};
