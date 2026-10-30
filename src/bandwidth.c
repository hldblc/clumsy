// Bandwidth cap: drop whatever exceeds a byte rate measured over a sliding window.
#include <stdlib.h>
#include <stdint.h>
#include "common.h"

#define NAME "bandwidth"

//---------------------------------------------------------------------
// sliding window rate stats
//---------------------------------------------------------------------
typedef struct {
    int32_t initialized;
    uint32_t oldest_index;
    uint32_t oldest_ts;
    int64_t accumulated_count;
    int32_t sample_num;
    int window_size;
    float scale;
    uint32_t *array_sum;
    uint32_t *array_sample;
} CRateStats;

static CRateStats *crate_stats_new(int window_size, float scale);
static void crate_stats_delete(CRateStats *rate);
static void crate_stats_reset(CRateStats *rate);
static void crate_stats_update(CRateStats *rate, int32_t count, uint32_t now_ts);
static int32_t crate_stats_calculate(CRateStats *rate, uint32_t now_ts);

//---------------------------------------------------------------------
// module
//---------------------------------------------------------------------
typedef struct {
    ScopeState scope;
    volatile LONG limit;      // KB/s
    CRateStats *rateStats;
} BandwidthState;

static const ParamDesc bandwidthParams[] = {
    SCOPE_PARAMS(BandwidthState),
    { "limit", "Limit(KB/s)", PT_INT32, offsetof(BandwidthState, limit), 0, 99999, 10, NULL, 0 },
};

static void bandwidthStartUp(ModuleInst *inst, int64_t now) {
    BandwidthState *st = (BandwidthState *)inst->state;
    UNREFERENCED_PARAMETER(now);
    if (st->rateStats) crate_stats_delete(st->rateStats);
    st->rateStats = crate_stats_new(1000, 1000);
    LOG("bandwidth enabled");
}

static void bandwidthCloseDown(ModuleInst *inst, PacketList *list) {
    BandwidthState *st = (BandwidthState *)inst->state;
    UNREFERENCED_PARAMETER(list);
    if (st->rateStats) crate_stats_delete(st->rateStats);
    st->rateStats = NULL;
    LOG("bandwidth disabled");
}

static void bandwidthDestroy(ModuleInst *inst) {
    BandwidthState *st = (BandwidthState *)inst->state;
    if (st->rateStats) crate_stats_delete(st->rateStats);
    st->rateStats = NULL;
}

static short bandwidthProcess(ModuleInst *inst, PacketList *list, int64_t now) {
    BandwidthState *st = (BandwidthState *)inst->state;
    PacketNode *pac, *next;
    uint32_t now_ts = (uint32_t)US_TO_MS(now);
    int limit = st->limit * 1024;
    short dropped = 0;

    // 0 is allowed and drops everything in scope
    if (limit < 0 || st->rateStats == NULL) {
        return 0;
    }
    for (pac = listFirst(list); pac != NULL; pac = next) {
        int rate, size;
        next = listNext(list, pac);
        if (!scopeMatch(&st->scope, pac)) continue;
        rate = crate_stats_calculate(st->rateStats, now_ts);
        size = (int)pac->packetLen;
        if (rate + size > limit) {
            LOG("dropped over bandwidth %d KB/s, %s", (int)st->limit, pac->addr.Outbound ? "outbound" : "inbound");
            atomicAdd64(&inst->stats.packets, 1);
            atomicAdd64(&inst->stats.bytes, pac->packetLen);
            atomicAdd64(&inst->stats.dropped, 1);
            packetFree(listUnlink(list, pac));
            dropped = 1;
        } else {
            crate_stats_update(st->rateStats, size, now_ts);
        }
    }
    return dropped;
}

const ModuleDesc bandwidthModuleDesc = {
    "Bandwidth", NAME, sizeof(BandwidthState),
    bandwidthParams, (int)(sizeof(bandwidthParams) / sizeof(bandwidthParams[0])),
    NULL, NULL, bandwidthDestroy,
    bandwidthStartUp, bandwidthCloseDown, bandwidthProcess, NULL
};

//---------------------------------------------------------------------
// rate stats implementation
//---------------------------------------------------------------------
static CRateStats *crate_stats_new(int window_size, float scale) {
    CRateStats *rate = (CRateStats *)malloc(sizeof(CRateStats));
    assert(rate);
    rate->array_sum = (uint32_t *)malloc(sizeof(uint32_t) * window_size);
    assert(rate->array_sum);
    rate->array_sample = (uint32_t *)malloc(sizeof(uint32_t) * window_size);
    assert(rate->array_sample);
    rate->window_size = window_size;
    rate->scale = scale;
    crate_stats_reset(rate);
    return rate;
}

static void crate_stats_delete(CRateStats *rate) {
    if (rate) {
        rate->window_size = 0;
        if (rate->array_sum) free(rate->array_sum);
        if (rate->array_sample) free(rate->array_sample);
        rate->array_sum = NULL;
        rate->array_sample = NULL;
        rate->initialized = 0;
        free(rate);
    }
}

static void crate_stats_reset(CRateStats *rate) {
    int i;
    for (i = 0; i < rate->window_size; i++) {
        rate->array_sum[i] = 0;
        rate->array_sample[i] = 0;
    }
    rate->initialized = 0;
    rate->sample_num = 0;
    rate->accumulated_count = 0;
    rate->oldest_ts = 0;
    rate->oldest_index = 0;
}

static void crate_stats_evict(CRateStats *rate, uint32_t now_ts) {
    uint32_t new_oldest_ts;
    if (rate->initialized == 0)
        return;
    new_oldest_ts = now_ts - ((uint32_t)rate->window_size) + 1;
    if (((int32_t)(new_oldest_ts - rate->oldest_ts)) < 0)
        return;
    while (((int32_t)(rate->oldest_ts - new_oldest_ts)) < 0) {
        uint32_t index = rate->oldest_index;
        if (rate->sample_num == 0) break;
        rate->sample_num -= rate->array_sample[index];
        rate->accumulated_count -= rate->array_sum[index];
        rate->array_sample[index] = 0;
        rate->array_sum[index] = 0;
        rate->oldest_index++;
        if (rate->oldest_index >= (uint32_t)rate->window_size) {
            rate->oldest_index = 0;
        }
        rate->oldest_ts++;
    }
    assert(rate->sample_num >= 0);
    assert(rate->accumulated_count >= 0);
    rate->oldest_ts = new_oldest_ts;
}

static void crate_stats_update(CRateStats *rate, int32_t count, uint32_t now_ts) {
    int32_t offset, index;
    if (rate->initialized == 0) {
        rate->oldest_ts = now_ts;
        rate->oldest_index = 0;
        rate->accumulated_count = 0;
        rate->sample_num = 0;
        rate->initialized = 1;
    }
    if (((int32_t)(now_ts - rate->oldest_ts)) < 0) {
        return;
    }
    crate_stats_evict(rate, now_ts);
    offset = (int32_t)(now_ts - rate->oldest_ts);
    index = (rate->oldest_index + offset) % rate->window_size;
    rate->sample_num++;
    rate->accumulated_count += count;
    rate->array_sum[index] += count;
    rate->array_sample[index] += 1;
}

static int32_t crate_stats_calculate(CRateStats *rate, uint32_t now_ts) {
    int32_t active_size = (int32_t)(now_ts - rate->oldest_ts + 1);
    float r;
    crate_stats_evict(rate, now_ts);
    if (rate->initialized == 0 ||
        rate->sample_num <= 0 ||
        active_size <= 1 ||
        active_size < rate->window_size) {
        return -1;
    }
    r = ((((float)rate->accumulated_count) * rate->scale) / rate->window_size) + 0.5f;
    return (int32_t)r;
}
