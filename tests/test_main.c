// Unit tests for the driver-free parts of clumsy. Built and run by `zig build test`.
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "packet.h"
#include "module.h"
#include "rng.h"
#include "clock.h"

static int checks = 0, failures = 0;
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); ++checks; if (_a != _b) { ++failures; printf("FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); } } while (0)

// The test binary needs a module table because params.c references it.
const ModuleDesc *const moduleDescs[] = { NULL };
const int moduleDescCount = 0;

static PacketNode *mk(int tag) {
    char buf[64];
    WINDIVERT_ADDRESS addr;
    PacketNode *n;
    memset(buf, tag, sizeof(buf));
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = (tag & 1) ? 1 : 0;
    n = packetAlloc(buf, sizeof(buf), &addr);
    n->flowHash = (uint64_t)tag;
    return n;
}

static int tagOf(PacketNode *n) {
    return (unsigned char)n->packet[0];
}

static void checkOrder(PacketList *l, const int *tags, int count) {
    PacketNode *n = listFirst(l);
    int i = 0;
    while (n && i < count) {
        CHECK_EQ(tagOf(n), tags[i]);
        n = listNext(l, n);
        ++i;
    }
    CHECK(n == NULL);
    CHECK_EQ(i, count);
    CHECK_EQ(listCount(l), count);
}

static void testList(void) {
    PacketList l, other;
    PacketNode *a, *b, *c, *d;
    const int o1[] = { 0, 1, 2, 3 };
    const int o2[] = { 1, 0, 2, 3 };
    const int o3[] = { 1, 3, 2, 0 };
    const int o4[] = { 1, 3, 2, 0, 4, 5 };
    const int o5[] = { 6, 1, 3, 2, 0, 4, 5 };
    listInit(&l);
    listInit(&other);
    CHECK(listEmpty(&l));
    CHECK(listFirst(&l) == NULL && listLast(&l) == NULL);

    a = mk(0); b = mk(1); c = mk(2); d = mk(3);
    listPushBack(&l, a);
    listPushBack(&l, b);
    listPushBack(&l, c);
    listPushBack(&l, d);
    checkOrder(&l, o1, 4);
    CHECK(listLast(&l) == d);
    CHECK(listPrev(&l, a) == NULL);

    listSwap(&l, a, b);           // adjacent
    checkOrder(&l, o2, 4);
    listSwap(&l, a, d);           // non adjacent
    checkOrder(&l, o3, 4);

    listPushBack(&other, mk(4));
    listPushBack(&other, mk(5));
    listAppendAll(&l, &other);
    CHECK(listEmpty(&other));
    checkOrder(&l, o4, 6);

    listPushBack(&other, mk(6));
    listPrependAll(&l, &other);
    checkOrder(&l, o5, 7);

    // unlink from the middle and re-insert relative to sentinels
    listUnlink(&l, c);
    CHECK_EQ(listCount(&l), 6);
    listInsertAfter(&l, c, &l.head);
    CHECK(listFirst(&l) == c);
    listUnlink(&l, c);
    listInsertBefore(&l, c, &l.tail);
    CHECK(listLast(&l) == c);

    listFreeAll(&l);
    CHECK(listEmpty(&l));
    CHECK_EQ(listCount(&l), 0);
}

static void testPool(void) {
    PacketPoolStats s0, s1, s2;
    PacketNode *nodes[500];
    PacketNode *big, *clone;
    char payload[3000];
    int i;
    packetPoolGetStats(&s0);
    for (i = 0; i < 500; ++i) nodes[i] = mk(i & 0x7f);
    packetPoolGetStats(&s1);
    CHECK_EQ(s1.nodesInUse - s0.nodesInUse, 500);
    CHECK_EQ(s1.smallInUse - s0.smallInUse, 500);
    for (i = 0; i < 500; ++i) packetFree(nodes[i]);
    packetPoolGetStats(&s2);
    CHECK_EQ(s2.nodesInUse, s0.nodesInUse);
    CHECK_EQ(s2.smallInUse, s0.smallInUse);
    CHECK(s2.nodesAllocated >= 500);

    // large class and growth
    memset(payload, 0x5a, sizeof(payload));
    big = packetAlloc(payload, sizeof(payload), NULL);
    CHECK(big != NULL);
    CHECK(big->capacity >= sizeof(payload));
    packetPoolGetStats(&s1);
    CHECK_EQ(s1.largeInUse - s0.largeInUse, 1);

    nodes[0] = mk(9);
    CHECK(packetReserve(nodes[0], 5000));
    CHECK(nodes[0]->capacity >= 5000);
    CHECK_EQ(tagOf(nodes[0]), 9);
    CHECK_EQ((unsigned char)nodes[0]->packet[63], 9);
    nodes[0]->flags = PN_FLAG_LAGGED;
    nodes[0]->processId = 1234;
    clone = packetClone(nodes[0]);
    CHECK(clone != NULL);
    CHECK_EQ(clone->packetLen, nodes[0]->packetLen);
    CHECK_EQ(clone->processId, 1234);
    CHECK((clone->flags & PN_FLAG_DUPLICATE) != 0);
    CHECK((clone->flags & PN_FLAG_LAGGED) != 0);
    CHECK(memcmp(clone->packet, nodes[0]->packet, nodes[0]->packetLen) == 0);
    packetFree(clone);
    packetFree(nodes[0]);
    packetFree(big);
    packetPoolGetStats(&s2);
    CHECK_EQ(s2.nodesInUse, s0.nodesInUse);
    CHECK_EQ(s2.largeInUse, s0.largeInUse);
    CHECK(packetAlloc(NULL, WINDIVERT_MTU_MAX + 100, NULL) == NULL);
}

// ---- params ----
typedef struct {
    ScopeState scope;
    volatile short time[2];
    volatile short chance;
    volatile short mode;
    volatile LONG limit;
    volatile short fixed;
} FakeState;

static const ParamDesc fakeParams[] = {
    SCOPE_PARAMS(FakeState),
    { "time",   "Delay(ms)", PT_INT,    offsetof(FakeState, time),   0, 15000, 50, NULL, PF_PERDIR },
    { "chance", "Chance(%)", PT_CHANCE, offsetof(FakeState, chance), 0, 10000, 1000, NULL, 0 },
    { "mode",   "Mode",      PT_ENUM,   offsetof(FakeState, mode),   0, 2, 1, "fixed|uniform|normal", 0 },
    { "limit",  "Limit",     PT_INT32,  offsetof(FakeState, limit),  0, 99999, 10, NULL, 0 },
    { "fixed",  "Fixed",     PT_FIXED,  offsetof(FakeState, fixed),  0, 1000, 150, NULL, 0 },
};

static const ModuleDesc fakeDesc = {
    "Fake", "fake", sizeof(FakeState), fakeParams, (int)(sizeof(fakeParams) / sizeof(fakeParams[0])),
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static int refreshCalls = 0;
static void onRefresh(ModuleInst *inst, const ParamDesc *p) { (void)inst; (void)p; ++refreshCalls; }

static void testParams(void) {
    ModuleInst *inst = moduleCreate(&fakeDesc, NULL, 0);
    FakeState *st;
    char buf[32];
    int dir = 5;
    const ParamDesc *p;
    CHECK(inst != NULL);
    st = (FakeState *)inst->state;
    // defaults
    CHECK_EQ(st->scope.inbound, 1);
    CHECK_EQ(st->scope.outbound, 1);
    CHECK_EQ(st->scope.flowPercent, 10000);
    CHECK_EQ(st->time[0], 50);
    CHECK_EQ(st->time[1], 50);
    CHECK_EQ(st->chance, 1000);
    CHECK_EQ(st->mode, 1);
    CHECK_EQ(st->limit, 10);
    CHECK_EQ(st->fixed, 150);

    // lookup with direction suffixes
    p = moduleFindParam(&fakeDesc, "time.out", &dir);
    CHECK(p != NULL && dir == 1);
    p = moduleFindParam(&fakeDesc, "TIME.in", &dir);
    CHECK(p != NULL && dir == 0);
    p = moduleFindParam(&fakeDesc, "chance.in", &dir);
    CHECK(p == NULL);            // not per direction
    CHECK(moduleFindParam(&fakeDesc, "nope", &dir) == NULL);

    // set / get text
    paramUiRefreshHook = onRefresh;
    CHECK(moduleSetParamText(inst, "time", "200"));
    CHECK_EQ(st->time[0], 200);
    CHECK_EQ(st->time[1], 200);
    CHECK(moduleSetParamText(inst, "time.out", "300"));
    CHECK_EQ(st->time[0], 200);
    CHECK_EQ(st->time[1], 300);
    CHECK(moduleSetParamText(inst, "time", "99999"));   // clamped
    CHECK_EQ(st->time[1], 15000);
    CHECK(!moduleSetParamText(inst, "time", "abc"));
    CHECK(moduleSetParamText(inst, "chance", "12.5"));
    CHECK_EQ(st->chance, 1250);
    CHECK(moduleSetParamText(inst, "chance", "0.25%"));
    CHECK_EQ(st->chance, 25);
    CHECK(moduleGetParamText(inst, "chance", buf, sizeof(buf)));
    CHECK(strcmp(buf, "0.25") == 0);
    CHECK(moduleSetParamText(inst, "chance", "10"));
    CHECK(moduleGetParamText(inst, "chance", buf, sizeof(buf)));
    CHECK(strcmp(buf, "10.0") == 0);
    CHECK(moduleSetParamText(inst, "mode", "normal"));
    CHECK_EQ(st->mode, 2);
    CHECK(moduleSetParamText(inst, "mode", "0"));
    CHECK_EQ(st->mode, 0);
    CHECK(!moduleSetParamText(inst, "mode", "weird"));
    CHECK(moduleGetParamText(inst, "mode", buf, sizeof(buf)));
    CHECK(strcmp(buf, "fixed") == 0);
    CHECK(moduleSetParamText(inst, "limit", "5000"));
    CHECK_EQ(st->limit, 5000);
    CHECK(moduleSetParamText(inst, "inbound", "off"));
    CHECK_EQ(st->scope.inbound, 0);
    CHECK(moduleSetParamText(inst, "inbound", "YES"));
    CHECK_EQ(st->scope.inbound, 1);
    CHECK(!moduleSetParamText(inst, "inbound", "maybe"));
    CHECK(moduleGetParamText(inst, "inbound", buf, sizeof(buf)));
    CHECK(strcmp(buf, "on") == 0);
    CHECK(moduleSetParamText(inst, "fixed", "2.5"));
    CHECK_EQ(st->fixed, 250);
    CHECK(moduleGetParamText(inst, "time.out", buf, sizeof(buf)));
    CHECK(strcmp(buf, "15000") == 0);
    CHECK(refreshCalls > 0);
    paramUiRefreshHook = NULL;

    // scope matching
    {
        PacketNode *in = mk(2), *out = mk(3);
        st->scope.inbound = 1; st->scope.outbound = 0; st->scope.flowPercent = 10000;
        CHECK(scopeMatch(&st->scope, in));
        CHECK(!scopeMatch(&st->scope, out));
        st->scope.outbound = 1;
        st->scope.flowPercent = 0;
        CHECK(!scopeMatch(&st->scope, in));
        st->scope.flowPercent = 5000;
        {
            // deterministic: same flow hash gives same answer every time
            int first = scopeMatch(&st->scope, in), i, same = 1;
            for (i = 0; i < 100; ++i) if (scopeMatch(&st->scope, in) != first) same = 0;
            CHECK(same);
        }
        {
            // roughly half of distinct flows selected
            int hits = 0, i;
            for (i = 0; i < 2000; ++i) {
                in->flowHash = rngNext();
                hits += scopeMatch(&st->scope, in);
            }
            CHECK(hits > 800 && hits < 1200);
        }
        packetFree(in);
        packetFree(out);
    }

    moduleResetDefaults(inst);
    CHECK_EQ(st->time[1], 50);
    moduleDestroy(inst);
}

static void testRng(void) {
    uint64_t a1, a2, b1;
    int i, hits;
    double sum, sumsq;
    rngSeed(42);
    a1 = rngNext(); a2 = rngNext();
    rngSeed(42);
    b1 = rngNext();
    CHECK(a1 == b1 && a1 != a2);
    CHECK_EQ(rngSeedValue(), 42);
    rngSeed(0);
    CHECK(rngSeedValue() != 0);

    for (i = 0; i < 10000; ++i) {
        double u = rngUniform();
        if (u < 0.0 || u >= 1.0) { CHECK(0); break; }
    }
    for (i = 0; i < 10000; ++i) {
        int r = rngRange(3, 7);
        if (r < 3 || r > 7) { CHECK(0); break; }
    }
    CHECK_EQ(rngRange(5, 5), 5);
    CHECK_EQ(rngRange(9, 2), 9);
    CHECK_EQ(rngChance(0), 0);
    CHECK_EQ(rngChance(10000), 1);
    hits = 0;
    for (i = 0; i < 20000; ++i) hits += rngChance(2500);
    CHECK(hits > 4500 && hits < 5500);

    sum = 0; sumsq = 0;
    for (i = 0; i < 20000; ++i) { double n = rngNormal(); sum += n; sumsq += n * n; }
    CHECK(fabs(sum / 20000.0) < 0.05);
    CHECK(fabs(sumsq / 20000.0 - 1.0) < 0.1);
    for (i = 0; i < 1000; ++i) {
        if (rngPareto(2.0) < 1.0) { CHECK(0); break; }
    }
}

static void testClock(void) {
    int64_t a = clockNowUs(), b;
    Sleep(5);
    b = clockNowUs();
    CHECK(b - a >= 4000);
    CHECK(b - a < 1000000);
}

int main(void) {
    packetPoolInit();
    clockInit();
    testList();
    testPool();
    testParams();
    testRng();
    testClock();
    packetPoolShutdown();
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
