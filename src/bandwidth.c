// Bandwidth: rate limiter per direction, as a shaper (queue) or a policer (drop).
//
// The link is modelled with a virtual clock: linkFree is the time at which the
// link finishes everything scheduled so far. A packet of S bytes occupies the
// link for S/rate. While the queue is empty the clock may lag behind "now" by at
// most the burst allowance, which is the token bucket depth. While packets are
// queued the clock is exact, so late wakeups never lose or invent credit.
//
// Shape mode queues packets and releases them when the link is free, so TCP
// sees added delay instead of loss until the queue overflows; a long queue
// reproduces bufferbloat. Police mode drops whatever is not conforming.
#include <stdlib.h>
#include "common.h"

#define NAME "bandwidth"
#define BW_MIN_BURST_BYTES 2048.0   // always allow one full sized packet
#define BW_MIN_QUEUE_BYTES 4096.0
#define BW_NEVER (INT64_MAX / 4)

enum { BW_MODE_SHAPE = 0, BW_MODE_POLICE };
enum { BW_AQM_TAIL = 0, BW_AQM_HEAD, BW_AQM_RED };

typedef struct {
    ScopeState scope;
    volatile LONG limit[2];      // KB/s per direction
    volatile short mode;         // BW_MODE_*
    volatile short queueMs;      // max queue depth expressed as ms at the rate
    volatile short aqm;          // what to do with a full queue
    volatile short burstMs;      // allowed burst as ms at the rate
    PacketList q[2];
    double qBytes[2];
    int64_t linkFree[2];         // virtual time the link becomes free
} BwState;

static const ParamDesc bwParams[] = {
    SCOPE_PARAMS(BwState),
    { "limit", "Limit(KB/s)", PT_INT32, offsetof(BwState, limit),   0, 999999, 100, NULL, PF_PERDIR },
    { "mode",  "Mode",        PT_ENUM,  offsetof(BwState, mode),    0, 1, BW_MODE_SHAPE, "shape|police", 0 },
    { "queue", "Queue(ms)",   PT_INT,   offsetof(BwState, queueMs), 1, 5000, 200, NULL, PF_ADVANCED },
    { "full",  "When full",   PT_ENUM,  offsetof(BwState, aqm),     0, 2, BW_AQM_TAIL, "tail-drop|head-drop|random-early", PF_ADVANCED },
    { "burst", "Burst(ms)",   PT_INT,   offsetof(BwState, burstMs), 1, 1000, 10, NULL, PF_ADVANCED },
};

static double rateBytesPerUs(const BwState *st, int dir) {
    return (double)st->limit[dir] * 1024.0 / 1000000.0;
}

// time the link needs for S bytes
static int64_t txTimeUs(const BwState *st, int dir, UINT size) {
    double rate = rateBytesPerUs(st, dir);
    if (rate <= 0.0) return BW_NEVER;
    return (int64_t)((double)size / rate + 0.5);
}

// how far the clock may lag behind now while idle: the burst allowance
static int64_t burstUs(const BwState *st, int dir) {
    double rate = rateBytesPerUs(st, dir);
    int64_t b = (int64_t)st->burstMs * 1000;
    if (rate > 0.0) {
        int64_t minBurst = (int64_t)(BW_MIN_BURST_BYTES / rate);
        if (minBurst > b) b = minBurst;
    }
    return b;
}

static double queueLimit(const BwState *st, int dir) {
    double q = rateBytesPerUs(st, dir) * (double)st->queueMs * 1000.0;
    return q < BW_MIN_QUEUE_BYTES ? BW_MIN_QUEUE_BYTES : q;
}

// an idle link banks at most the burst allowance
static void capIdleCredit(BwState *st, int dir, int64_t now) {
    if (listEmpty(&st->q[dir])) {
        int64_t floor = now - burstUs(st, dir);
        if (st->linkFree[dir] < floor) st->linkFree[dir] = floor;
    }
}

static void bwInit(ModuleInst *inst) {
    BwState *st = (BwState *)inst->state;
    listInit(&st->q[0]);
    listInit(&st->q[1]);
}

static void bwStartUp(ModuleInst *inst, int64_t now) {
    BwState *st = (BwState *)inst->state;
    int d;
    for (d = 0; d < 2; ++d) {
        listEnsureInit(&st->q[d]);
        assert(listEmpty(&st->q[d]));
        st->qBytes[d] = 0;
        st->linkFree[d] = now - burstUs(st, d);   // start with a full bucket
    }
    LOG("bandwidth enabled");
}

static void bwCloseDown(ModuleInst *inst, PacketList *list) {
    BwState *st = (BwState *)inst->state;
    int d;
    for (d = 0; d < 2; ++d) {
        listAppendAll(list, &st->q[d]);
        st->qBytes[d] = 0;
    }
    atomicExch32(&inst->stats.queued, 0);
    LOG("bandwidth disabled");
}

static void dropPacket(ModuleInst *inst, PacketList *from, PacketNode *pac) {
    atomicAdd64(&inst->stats.dropped, 1);
    packetFree(listUnlink(from, pac));
}

static short bwProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    BwState *st = (BwState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;
    int d;

    capIdleCredit(st, 0, now);
    capIdleCredit(st, 1, now);

    for (pac = listFirst(list); pac != NULL; pac = next) {
        int64_t tx;
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        d = pac->addr.Outbound ? 1 : 0;
        tx = txTimeUs(st, d, pac->packetLen);
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);

        if (st->mode == BW_MODE_POLICE) {
            if (tx != BW_NEVER && st->linkFree[d] + tx <= now) {
                st->linkFree[d] += tx;          // conforming
            } else {
                dropPacket(inst, list, pac);
                acted = 1;
            }
            continue;
        }

        // shape: pass straight through if nothing waits and the link is free
        if (listEmpty(&st->q[d]) && tx != BW_NEVER && st->linkFree[d] + tx <= now) {
            st->linkFree[d] += tx;
            continue;
        }
        {
            double size = (double)pac->packetLen;
            double limit = queueLimit(st, d);
            int drop = 0;
            if (st->qBytes[d] + size > limit) {
                if (st->aqm == BW_AQM_HEAD) {
                    while (!listEmpty(&st->q[d]) && st->qBytes[d] + size > limit) {
                        PacketNode *old = listFirst(&st->q[d]);
                        st->qBytes[d] -= (double)old->packetLen;
                        dropPacket(inst, &st->q[d], old);
                    }
                    drop = st->qBytes[d] + size > limit;
                } else {
                    drop = 1;
                }
            } else if (st->aqm == BW_AQM_RED) {
                // random early drop: probability rises from 0 at half full to 1 at full
                double fill = st->qBytes[d] / limit;
                if (fill > 0.5 && rngUniform() < (fill - 0.5) * 2.0) drop = 1;
            }
            if (drop) {
                dropPacket(inst, list, pac);
                acted = 1;
                continue;
            }
            listUnlink(list, pac);
            pac->flags |= PN_FLAG_SHAPED;
            listPushBack(&st->q[d], pac);
            st->qBytes[d] += size;
            acted = 1;
        }
    }

    // release what the link has had time for, oldest first, per direction
    for (d = 0; d < 2; ++d) {
        while ((pac = listFirst(&st->q[d])) != NULL) {
            int64_t tx = txTimeUs(st, d, pac->packetLen);
            if (tx == BW_NEVER || st->linkFree[d] + tx > now) break;
            st->linkFree[d] += tx;
            st->qBytes[d] -= (double)pac->packetLen;
            listUnlink(&st->q[d], pac);
            listPushBack(list, pac);
            acted = 1;
        }
        if (listEmpty(&st->q[d])) {
            st->qBytes[d] = 0;
            capIdleCredit(st, d, now);   // the link went idle: stop banking credit
        }
    }

    atomicExch32(&inst->stats.queued, listCount(&st->q[0]) + listCount(&st->q[1]));
    return acted;
}

static int64_t bwNextDeadline(ModuleInst *inst, int64_t now) {
    BwState *st = (BwState *)inst->state;
    int64_t best = -1;
    int d;
    UNREFERENCED_PARAMETER(now);
    for (d = 0; d < 2; ++d) {
        PacketNode *head = listFirst(&st->q[d]);
        int64_t tx, t;
        if (head == NULL) continue;
        tx = txTimeUs(st, d, head->packetLen);
        if (tx == BW_NEVER) continue;          // rate 0: the queue only drains by dropping
        t = st->linkFree[d] + tx;
        if (best < 0 || t < best) best = t;
    }
    return best;
}

const ModuleDesc bandwidthModuleDesc = {
    "Bandwidth", NAME, sizeof(BwState),
    bwParams, (int)(sizeof(bwParams) / sizeof(bwParams[0])),
    NULL, bwInit, NULL,
    bwStartUp, bwCloseDown, bwProcess, bwNextDeadline,
    NULL, NULL
};
