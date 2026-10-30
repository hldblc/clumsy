// Outage: the link drops all matching traffic for a while, then recovers,
// either on a fixed period or at random intervals. This reproduces blackouts,
// tunnels, elevators and flapping links. Dropping is the standard way to
// simulate a down link (the sender then sees a timeout, exactly as it would
// on a real outage).
#include <math.h>
#include "common.h"

#define NAME "outage"
#define OUTAGE_MIN_PHASE_US 1000LL

enum { OUT_PERIODIC = 0, OUT_RANDOM };

typedef struct {
    ScopeState scope;
    volatile short mode;
    volatile LONG downMs;
    volatile LONG upMs;
    volatile short startDown;
    int started;
    int isDown;
    int64_t phaseEnd;
} OutageState;

static const ParamDesc outageParams[] = {
    SCOPE_PARAMS(OutageState),
    { "mode",      "Mode",       PT_ENUM,  offsetof(OutageState, mode),      0, 1, OUT_PERIODIC, "periodic|random", 0 },
    { "down",      "Down(ms)",   PT_INT32, offsetof(OutageState, downMs),    1, 600000, 3000, NULL, 0 },
    { "up",        "Up(ms)",     PT_INT32, offsetof(OutageState, upMs),      1, 600000, 10000, NULL, 0 },
    { "startdown", "Start down", PT_BOOL,  offsetof(OutageState, startDown), 0, 1, 0, NULL, PF_ADVANCED },
};

// length of the next up or down phase, in microseconds
static int64_t phaseLength(const OutageState *st, int down) {
    double mean = (double)(down ? st->downMs : st->upMs) * 1000.0;
    double d = mean;
    if (st->mode == OUT_RANDOM) {
        // exponential around the mean, bounded so one draw cannot stall for ages
        d = -mean * log(1.0 - rngUniform());
        if (d > mean * 10.0) d = mean * 10.0;
    }
    if (d < (double)OUTAGE_MIN_PHASE_US) d = (double)OUTAGE_MIN_PHASE_US;
    return (int64_t)d;
}

static void outageStartUp(ModuleInst *inst, int64_t now) {
    OutageState *st = (OutageState *)inst->state;
    st->started = 1;
    st->isDown = st->startDown ? 1 : 0;
    st->phaseEnd = now + phaseLength(st, st->isDown);
    LOG("outage enabled, starting %s", st->isDown ? "down" : "up");
}

static void outageCloseDown(ModuleInst *inst, PacketList *list) {
    OutageState *st = (OutageState *)inst->state;
    UNREFERENCED_PARAMETER(list);
    st->started = 0;
    st->isDown = 0;
    LOG("outage disabled");
}

// advance through any phases that have already elapsed
static void advance(OutageState *st, int64_t now) {
    int guard = 0;
    while (now >= st->phaseEnd && guard++ < 1000) {
        st->isDown = !st->isDown;
        st->phaseEnd += phaseLength(st, st->isDown);
    }
    if (guard >= 1000) {
        // parameters imply absurdly short phases: resync to now
        st->phaseEnd = now + phaseLength(st, st->isDown);
    }
}

static short outageProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    OutageState *st = (OutageState *)inst->state;
    PacketNode *pac, *next;
    short acted = 0;
    advance(st, now);
    if (!st->isDown) {
        return 0;
    }
    for (pac = listFirst(list); pac != NULL; pac = next) {
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        atomicAdd64(&inst->stats.packets, 1);
        atomicAdd64(&inst->stats.bytes, pac->packetLen);
        atomicAdd64(&inst->stats.dropped, 1);
        packetFree(listUnlink(list, pac));
        acted = 1;
    }
    return acted;
}

static int64_t outageNextDeadline(ModuleInst *inst, int64_t now) {
    OutageState *st = (OutageState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    // wake at the end of a down phase so recovery is prompt; during an up phase
    // packets arriving will wake us anyway, but ask for the transition too
    return st->started ? st->phaseEnd : -1;
}

const ModuleDesc outageModuleDesc = {
    "Outage", NAME, sizeof(OutageState),
    outageParams, (int)(sizeof(outageParams) / sizeof(outageParams[0])),
    NULL, NULL, NULL,
    outageStartUp, outageCloseDown, outageProcess, outageNextDeadline,
    NULL, NULL
};
