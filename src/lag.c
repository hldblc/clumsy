// Lag: hold packets for a delay drawn from a distribution, release them when due.
#include <math.h>
#include "common.h"

#define NAME "lag"
#define LAG_KEEP_AT_MOST 2000
#define LAG_FLUSH_WHEN_FULL 800
#define LAG_MAX_MS 15000

enum { LAG_DIST_FIXED = 0, LAG_DIST_UNIFORM, LAG_DIST_NORMAL, LAG_DIST_SPIKY };

typedef struct {
    ScopeState scope;
    volatile short time[2];      // base delay in ms, per direction
    volatile short jitter[2];    // ms, per direction: half-width (uniform), deviation (normal), scale (spiky)
    volatile short dist;         // LAG_DIST_*
    volatile short keepOrder;    // never release a packet before an earlier one
    PacketList buf;              // held packets ordered by releaseTime
    int64_t lastRelease[2];      // for keepOrder, per direction
} LagState;

static const ParamDesc lagParams[] = {
    SCOPE_PARAMS(LagState),
    { "time",   "Delay(ms)",  PT_INT,  offsetof(LagState, time),   0, LAG_MAX_MS, 50, NULL, PF_PERDIR },
    { "jitter", "Jitter(ms)", PT_INT,  offsetof(LagState, jitter), 0, LAG_MAX_MS, 0, NULL, PF_PERDIR },
    { "dist",   "Dist",       PT_ENUM, offsetof(LagState, dist),   0, 3, 0, "fixed|uniform|normal|spiky", 0 },
    { "order",  "Keep order", PT_BOOL, offsetof(LagState, keepOrder), 0, 1, 1, NULL, PF_ADVANCED },
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
    st->lastRelease[0] = st->lastRelease[1] = 0;
}

static void lagCloseDown(ModuleInst *inst, PacketList *list) {
    LagState *st = (LagState *)inst->state;
    LOG("closing lag, flushing %d packets", listCount(&st->buf));
    listAppendAll(list, &st->buf);
    atomicExch32(&inst->stats.queued, 0);
}

// delay sample in microseconds for one direction
static int64_t lagSampleUs(const LagState *st, int dir) {
    double base = (double)st->time[dir];
    double j = (double)st->jitter[dir];
    double d;
    switch (st->dist) {
    case LAG_DIST_UNIFORM:
        d = base + (rngUniform() * 2.0 - 1.0) * j;
        break;
    case LAG_DIST_NORMAL:
        d = base + rngNormal() * j;
        break;
    case LAG_DIST_SPIKY:
        // heavy tail: mostly small additions, occasionally several times the jitter
        d = base + j * (rngPareto(1.5) - 1.0);
        break;
    default:
        d = base;
        break;
    }
    if (d < 0.0) d = 0.0;
    if (d > LAG_MAX_MS) d = LAG_MAX_MS;
    return (int64_t)(d * 1000.0 + 0.5);
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
        int dir;
        int64_t rt;
        next = listNext(list, pac);
        if (listCount(&st->buf) >= LAG_KEEP_AT_MOST) break;
        if (!scopeMatch(&st->scope, pac)) continue;
        dir = pac->addr.Outbound ? 1 : 0;
        listUnlink(list, pac);
        rt = pac->captureTime + lagSampleUs(st, dir);
        if (st->keepOrder && rt < st->lastRelease[dir]) {
            rt = st->lastRelease[dir];
        }
        st->lastRelease[dir] = rt;
        pac->releaseTime = rt;
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
    lagStartUp, lagCloseDown, lagProcess, lagNextDeadline,
    NULL, NULL
};
