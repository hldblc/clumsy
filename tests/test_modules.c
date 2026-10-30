// Module level tests: synthetic IPv4/UDP packets pushed through the real
// module descriptors with a simulated clock. Uses the WinDivert user-mode
// helpers (checksums, parsing, filter compilation) but never the driver.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "rules.h"

extern int checks, failures;
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); ++checks; if (_a != _b) { ++failures; printf("FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b); } } while (0)
#define CHECK_RANGE(v, lo, hi) do { long long _v = (long long)(v); ++checks; if (_v < (lo) || _v > (hi)) { ++failures; printf("FAIL %s:%d: %s = %lld not in [%lld, %lld]\n", __FILE__, __LINE__, #v, _v, (long long)(lo), (long long)(hi)); } } while (0)

#define T0 1000000000LL   // simulated "now" in microseconds

// ---- synthetic packets ----
static PacketNode *mkUdp(uint16_t srcPort, uint16_t dstPort, int payloadLen, int outbound) {
    unsigned char buf[4096];
    UINT len = 20 + 8 + (UINT)payloadLen;
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(buf + 20);
    WINDIVERT_ADDRESS addr;
    PacketNode *n;
    int i;
    memset(buf, 0, len);
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->Length = WinDivertHelperHtons((UINT16)len);
    ip->Id = WinDivertHelperHtons(0x1234);
    ip->TTL = 64;
    ip->Protocol = 17;
    ip->SrcAddr = WinDivertHelperHtonl(0x0A000001);
    ip->DstAddr = WinDivertHelperHtonl(0x0A000002);
    udp->SrcPort = WinDivertHelperHtons(srcPort);
    udp->DstPort = WinDivertHelperHtons(dstPort);
    udp->Length = WinDivertHelperHtons((UINT16)(8 + payloadLen));
    for (i = 0; i < payloadLen; ++i) buf[28 + i] = (unsigned char)(i * 7 + 3);
    WinDivertHelperCalcChecksums(buf, len, NULL, 0);
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = outbound ? 1 : 0;
    addr.Layer = WINDIVERT_LAYER_NETWORK;
    n = packetAlloc(buf, len, &addr);
    n->captureTime = T0;
    n->flowHash = ((uint64_t)(srcPort < dstPort ? srcPort : dstPort) << 32) | (uint64_t)(srcPort < dstPort ? dstPort : srcPort);
    return n;
}

static uint16_t srcPortOf(PacketNode *n) {
    PWINDIVERT_UDPHDR udp = NULL;
    WinDivertHelperParsePacket(n->packet, n->packetLen, NULL, NULL, NULL, NULL, NULL, NULL, &udp, NULL, NULL, NULL, NULL);
    return udp ? WinDivertHelperNtohs(udp->SrcPort) : 0;
}

static int checksumsValid(PacketNode *n) {
    unsigned char copy[4096];
    memcpy(copy, n->packet, n->packetLen);
    WinDivertHelperCalcChecksums(copy, n->packetLen, NULL, 0);
    return memcmp(copy, n->packet, n->packetLen) == 0;
}

// ---- driving modules like the engine does ----
static void runStep(ModuleInst *m, PacketList *l, int64_t now) {
    if (!m->lastEnabled) {
        m->desc->startUp(m, now);
        m->lastEnabled = 1;
    }
    m->desc->process(m, l, now);
}

static void stopModule(ModuleInst *m, PacketList *l) {
    if (m->lastEnabled) {
        m->desc->closeDown(m, l);
        m->lastEnabled = 0;
    }
}

static void fill(PacketList *l, int count, int outbound) {
    int i;
    for (i = 0; i < count; ++i) {
        listPushBack(l, mkUdp((uint16_t)(1000 + i), 7000, 100, outbound));
    }
}

static int countAndFree(PacketList *l) {
    int n = listCount(l);
    listFreeAll(l);
    return n;
}

// ---- lag ----
static void testLagFixed(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *lag = ruleFindModule(r, "lag");
    PacketList l;
    PacketNode *n;
    int i;
    listInit(&l);
    CHECK(lag != NULL);
    CHECK(moduleSetParamText(lag, "time", "50"));
    fill(&l, 3, 1);
    runStep(lag, &l, T0);
    CHECK(listEmpty(&l));
    CHECK_EQ(lag->stats.queued, 3);
    CHECK_EQ(lag->desc->nextDeadline(lag, T0), T0 + 50000);
    runStep(lag, &l, T0 + 49000);
    CHECK(listEmpty(&l));
    runStep(lag, &l, T0 + 50000);
    CHECK_EQ(listCount(&l), 3);
    for (n = listFirst(&l), i = 0; n; n = listNext(&l, n), ++i) {
        CHECK_EQ(srcPortOf(n), 1000 + i);
        CHECK((n->flags & PN_FLAG_LAGGED) != 0);
    }
    CHECK_EQ(lag->desc->nextDeadline(lag, T0 + 50000), -1);
    listFreeAll(&l);

    // per direction: inbound 20 ms, outbound 80 ms
    CHECK(moduleSetParamText(lag, "time", "20/80"));
    listPushBack(&l, mkUdp(1, 2, 10, 0));
    listPushBack(&l, mkUdp(3, 4, 10, 1));
    runStep(lag, &l, T0);
    CHECK(listEmpty(&l));
    runStep(lag, &l, T0 + 20000);
    CHECK_EQ(listCount(&l), 1);
    CHECK_EQ(listFirst(&l)->addr.Outbound, 0);
    runStep(lag, &l, T0 + 80000);
    CHECK_EQ(listCount(&l), 2);
    listFreeAll(&l);

    // closeDown flushes whatever is held
    fill(&l, 5, 1);
    runStep(lag, &l, T0);
    CHECK(listEmpty(&l));
    stopModule(lag, &l);
    CHECK_EQ(listCount(&l), 5);
    listFreeAll(&l);
    ruleDestroy(r);
}

static void testLagJitter(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *lag = ruleFindModule(r, "lag");
    PacketList l;
    PacketNode *n;
    int released, i, ordered;
    uint16_t last;
    listInit(&l);
    CHECK(moduleSetParamText(lag, "time", "100"));
    CHECK(moduleSetParamText(lag, "jitter", "20"));
    CHECK(moduleSetParamText(lag, "dist", "uniform"));
    CHECK(moduleSetParamText(lag, "order", "off"));
    fill(&l, 400, 1);
    runStep(lag, &l, T0);
    CHECK(listEmpty(&l));
    runStep(lag, &l, T0 + 79000);
    CHECK(listEmpty(&l));                 // nothing before time - jitter
    runStep(lag, &l, T0 + 100000);
    released = listCount(&l);
    CHECK_RANGE(released, 120, 280);      // about half by the mean
    runStep(lag, &l, T0 + 121000);
    CHECK_EQ(listCount(&l), 400);         // everything by time + jitter
    listFreeAll(&l);

    // keep order: a burst captured at once all waits for the slowest sample,
    // and release order equals capture order
    CHECK(moduleSetParamText(lag, "order", "on"));
    fill(&l, 400, 1);
    runStep(lag, &l, T0);
    runStep(lag, &l, T0 + 121000);
    CHECK_EQ(listCount(&l), 400);
    ordered = 1;
    last = 0;
    for (n = listFirst(&l), i = 0; n; n = listNext(&l, n), ++i) {
        uint16_t p = srcPortOf(n);
        if (i > 0 && p < last) ordered = 0;
        last = p;
    }
    CHECK(ordered);
    listFreeAll(&l);

    // normal and spiky never go negative and always finish within the cap
    CHECK(moduleSetParamText(lag, "order", "off"));
    CHECK(moduleSetParamText(lag, "dist", "normal"));
    CHECK(moduleSetParamText(lag, "jitter", "100"));
    fill(&l, 200, 1);
    runStep(lag, &l, T0);
    runStep(lag, &l, T0 + 100000);
    CHECK_RANGE(listCount(&l), 60, 140);  // the mean is the base delay
    runStep(lag, &l, T0 + 15000000);
    CHECK_EQ(listCount(&l), 200);
    listFreeAll(&l);
    CHECK(moduleSetParamText(lag, "dist", "spiky"));
    fill(&l, 200, 1);
    runStep(lag, &l, T0);
    runStep(lag, &l, T0 + 99000);
    CHECK(listEmpty(&l));                 // spikes only ever add delay
    runStep(lag, &l, T0 + 300000);
    CHECK(listCount(&l) > 100);           // most spikes are small
    runStep(lag, &l, T0 + 15000000);
    CHECK_EQ(listCount(&l), 200);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- drop ----
static double meanDropRun(const unsigned char *survived, int n) {
    int i, runs = 0, dropped = 0;
    for (i = 0; i < n; ++i) {
        if (!survived[i]) {
            ++dropped;
            if (i == 0 || survived[i - 1]) ++runs;
        }
    }
    return runs ? (double)dropped / runs : 0.0;
}

static void testDrop(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *drop = ruleFindModule(r, "drop");
    PacketList l;
    PacketNode *n;
    static unsigned char survived[20000];
    int i, dropped;
    double run;
    listInit(&l);

    CHECK(moduleSetParamText(drop, "chance", "25"));
    for (i = 0; i < 20000; ++i) {
        n = mkUdp((uint16_t)(i & 0xffff), 9, 10, 1);
        n->processId = (uint32_t)i;   // identify survivors
        listPushBack(&l, n);
    }
    runStep(drop, &l, T0);
    memset(survived, 0, sizeof(survived));
    for (n = listFirst(&l); n; n = listNext(&l, n)) survived[n->processId] = 1;
    dropped = 20000 - listCount(&l);
    CHECK_RANGE(dropped, 4500, 5500);
    CHECK_EQ(drop->stats.dropped, dropped);
    run = meanDropRun(survived, 20000);
    CHECK(run < 1.6);                     // independent losses come in short runs
    listFreeAll(&l);

    // bursty: same overall loss, much longer runs
    CHECK(moduleSetParamText(drop, "chance", "10"));
    CHECK(moduleSetParamText(drop, "burst", "on"));
    CHECK(moduleSetParamText(drop, "burstlen", "10"));
    CHECK(moduleSetParamText(drop, "burstloss", "100"));
    for (i = 0; i < 20000; ++i) {
        n = mkUdp((uint16_t)(i & 0xffff), 9, 10, 1);
        n->processId = (uint32_t)i;
        listPushBack(&l, n);
    }
    runStep(drop, &l, T0);
    memset(survived, 0, sizeof(survived));
    for (n = listFirst(&l); n; n = listNext(&l, n)) survived[n->processId] = 1;
    dropped = 20000 - listCount(&l);
    CHECK_RANGE(dropped, 1400, 2600);
    run = meanDropRun(survived, 20000);
    CHECK(run > 4.0);
    listFreeAll(&l);

    // per direction: outbound 100%, inbound 0%
    CHECK(moduleSetParamText(drop, "burst", "off"));
    CHECK(moduleSetParamText(drop, "chance", "0/100"));
    fill(&l, 10, 1);
    fill(&l, 10, 0);
    runStep(drop, &l, T0);
    CHECK_EQ(listCount(&l), 10);
    for (n = listFirst(&l); n; n = listNext(&l, n)) CHECK_EQ(n->addr.Outbound, 0);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- bandwidth ----
static void testBandwidth(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *bw = ruleFindModule(r, "bandwidth");
    PacketList l;
    int i, passed;
    int64_t dl;
    listInit(&l);
    // 100 KB/s, huge queue so nothing drops, 10 ms bucket
    CHECK(moduleSetParamText(bw, "limit", "100"));
    CHECK(moduleSetParamText(bw, "queue", "5000"));
    CHECK(moduleSetParamText(bw, "mode", "shape"));
    for (i = 0; i < 100; ++i) listPushBack(&l, mkUdp((uint16_t)i, 1, 1024, 1));   // 1052 byte packets
    runStep(bw, &l, T0);
    passed = countAndFree(&l);
    CHECK_RANGE(passed, 1, 2);                 // the bucket holds one packet
    CHECK_EQ(bw->stats.queued, 100 - passed);
    dl = bw->desc->nextDeadline(bw, T0);
    CHECK(dl > T0 && dl < T0 + 20000);         // next packet due within a few ms
    runStep(bw, &l, T0 + 500000);              // half a second: ~51200 bytes of credit
    passed += countAndFree(&l);
    CHECK_RANGE(passed, 46, 52);
    runStep(bw, &l, T0 + 1200000);
    passed += countAndFree(&l);
    CHECK_EQ(passed, 100);
    CHECK_EQ(bw->stats.dropped, 0);
    CHECK_EQ(bw->desc->nextDeadline(bw, T0 + 1200000), -1);
    stopModule(bw, &l);
    listFreeAll(&l);

    // a long sleep while idle must not bank more than the burst allowance
    for (i = 0; i < 100; ++i) listPushBack(&l, mkUdp((uint16_t)i, 1, 1024, 1));
    runStep(bw, &l, T0 + 60000000);           // a minute later
    passed = countAndFree(&l);
    CHECK_RANGE(passed, 1, 2);
    stopModule(bw, &l);
    listFreeAll(&l);

    // police mode drops instead of queueing
    {
        LONG64 dropped0 = bw->stats.dropped;
        CHECK(moduleSetParamText(bw, "mode", "police"));
        for (i = 0; i < 100; ++i) listPushBack(&l, mkUdp((uint16_t)i, 1, 1024, 1));
        runStep(bw, &l, T0);
        passed = countAndFree(&l);
        CHECK_RANGE(passed, 1, 2);
        CHECK_EQ(bw->stats.dropped - dropped0, 100 - passed);
        stopModule(bw, &l);
        listFreeAll(&l);
    }

    // small queue with tail drop: excess is dropped, queue depth bounded
    {
        LONG64 dropped0 = bw->stats.dropped;
        CHECK(moduleSetParamText(bw, "mode", "shape"));
        CHECK(moduleSetParamText(bw, "queue", "100"));      // 100 ms at 100 KB/s = 10240 bytes
        for (i = 0; i < 100; ++i) listPushBack(&l, mkUdp((uint16_t)i, 1, 1024, 1));
        runStep(bw, &l, T0);
        passed = countAndFree(&l);
        CHECK(bw->stats.queued <= 10);
        CHECK(bw->stats.dropped - dropped0 >= 80);
        stopModule(bw, &l);
        listFreeAll(&l);
    }

    // asymmetric: inbound practically unlimited, outbound tiny
    CHECK(moduleSetParamText(bw, "limit", "100000/1"));
    CHECK(moduleSetParamText(bw, "queue", "5000"));
    fill(&l, 20, 0);
    fill(&l, 20, 1);
    runStep(bw, &l, T0);
    passed = listCount(&l);
    CHECK(passed >= 21 && passed < 40);
    listFreeAll(&l);
    stopModule(bw, &l);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- throttle ----
static void testThrottle(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *th = ruleFindModule(r, "throttle");
    PacketList l;
    listInit(&l);
    CHECK(moduleSetParamText(th, "chance", "100"));
    CHECK(moduleSetParamText(th, "frame", "30"));
    fill(&l, 2, 1);
    runStep(th, &l, T0);
    CHECK(listEmpty(&l));
    CHECK_EQ(th->stats.queued, 2);
    CHECK_EQ(th->desc->nextDeadline(th, T0), T0 + 30000);
    fill(&l, 1, 1);
    runStep(th, &l, T0 + 10000);
    CHECK(listEmpty(&l));
    CHECK_EQ(th->stats.queued, 3);
    runStep(th, &l, T0 + 31000);
    CHECK_EQ(listCount(&l), 3);
    CHECK_EQ(th->desc->nextDeadline(th, T0 + 31000), -1);
    listFreeAll(&l);

    CHECK(moduleSetParamText(th, "drop", "on"));
    fill(&l, 4, 1);
    runStep(th, &l, T0 + 100000);
    runStep(th, &l, T0 + 200000);
    CHECK(listEmpty(&l));
    CHECK_EQ(th->stats.dropped, 4);
    stopModule(th, &l);
    ruleDestroy(r);
}

// ---- duplicate / ood / tamper ----
static void testDuplicate(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *dup = ruleFindModule(r, "duplicate");
    PacketList l;
    PacketNode *n;
    int copies = 0;
    listInit(&l);
    CHECK(moduleSetParamText(dup, "chance", "100"));
    CHECK(moduleSetParamText(dup, "count", "3"));
    fill(&l, 2, 1);
    runStep(dup, &l, T0);
    CHECK_EQ(listCount(&l), 6);
    for (n = listFirst(&l); n; n = listNext(&l, n)) if (n->flags & PN_FLAG_DUPLICATE) ++copies;
    CHECK_EQ(copies, 4);
    // originals keep their relative order: 1000,1000,1000,1001,1001,1001
    CHECK_EQ(srcPortOf(listFirst(&l)), 1000);
    CHECK_EQ(srcPortOf(listLast(&l)), 1001);
    listFreeAll(&l);
    ruleDestroy(r);
}

static void testOod(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *ood = ruleFindModule(r, "ood");
    PacketList l;
    PacketNode *n;
    const int expect[4] = { 1001, 1000, 1003, 1002 };
    int i;
    listInit(&l);
    CHECK(moduleSetParamText(ood, "chance", "100"));
    fill(&l, 4, 1);
    runStep(ood, &l, T0);
    CHECK_EQ(listCount(&l), 4);
    for (n = listFirst(&l), i = 0; n && i < 4; n = listNext(&l, n), ++i) CHECK_EQ(srcPortOf(n), expect[i]);
    listFreeAll(&l);
    // a lone packet is held until the next one arrives
    fill(&l, 1, 1);
    runStep(ood, &l, T0);
    CHECK(listEmpty(&l));
    CHECK_EQ(ood->stats.queued, 1);
    fill(&l, 1, 1);
    runStep(ood, &l, T0 + 1000);
    CHECK_EQ(listCount(&l), 2);
    CHECK_EQ(srcPortOf(listFirst(&l)), 1000);  // the newer one first
    listFreeAll(&l);
    // or released on its own after the hold timeout
    fill(&l, 1, 1);
    runStep(ood, &l, T0);
    CHECK(listEmpty(&l));
    CHECK(ood->desc->nextDeadline(ood, T0) > T0);
    runStep(ood, &l, T0 + 1000000);
    CHECK_EQ(listCount(&l), 1);
    listFreeAll(&l);
    ruleDestroy(r);
}

static void testTamper(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *tm = ruleFindModule(r, "tamper");
    PacketList l;
    PacketNode *n, *orig;
    listInit(&l);
    CHECK(moduleSetParamText(tm, "chance", "100"));
    n = mkUdp(5, 6, 200, 1);
    orig = packetClone(n);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    CHECK_EQ(listCount(&l), 1);
    CHECK(memcmp(n->packet + 28, orig->packet + 28, 200) != 0);   // payload changed
    CHECK(memcmp(n->packet, orig->packet, 10) == 0);               // IP header up to the checksum intact
    CHECK(checksumsValid(n));                                       // and checksums were redone
    CHECK((n->flags & PN_FLAG_TAMPERED) != 0);
    listFreeAll(&l);
    packetFree(orig);
    // without redo the checksum stays stale but the flags claim validity
    CHECK(moduleSetParamText(tm, "checksum", "off"));
    n = mkUdp(5, 6, 200, 1);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    CHECK(!checksumsValid(n));
    CHECK(n->addr.UDPChecksum == 1 && n->addr.IPChecksum == 1);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- scope: flows ----
static void testFlowScope(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *drop = ruleFindModule(r, "drop");
    PacketList l;
    PacketNode *n;
    int i, dropped;
    listInit(&l);
    CHECK(moduleSetParamText(drop, "chance", "100"));
    CHECK(moduleSetParamText(drop, "flows", "50"));
    // 2000 distinct flows, one packet each
    for (i = 0; i < 2000; ++i) {
        n = mkUdp((uint16_t)(1 + i), 9, 10, 1);
        n->flowHash = rngNext();
        listPushBack(&l, n);
    }
    runStep(drop, &l, T0);
    dropped = 2000 - listCount(&l);
    CHECK_RANGE(dropped, 850, 1150);
    listFreeAll(&l);
    // the same flow is treated the same every time
    for (i = 0; i < 100; ++i) {
        n = mkUdp(7, 9, 10, 1);
        n->flowHash = 0x1234567890ULL;
        listPushBack(&l, n);
    }
    runStep(drop, &l, T0);
    CHECK(listCount(&l) == 0 || listCount(&l) == 100);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- rules ----
static void testRules(void) {
    char err[256], uni[4096];
    Rule *a = ruleCreate("A", "udp.DstPort == 5000");
    Rule *b = ruleCreate("B", "udp");
    Rule *bad = ruleCreate("bad", "udp.DstPort === 1");
    PacketNode *p5000 = mkUdp(1, 5000, 10, 1), *p6000 = mkUdp(1, 6000, 10, 1);
    ruleSetClear();
    CHECK(ruleCompile(a, err, sizeof(err)));
    CHECK(ruleCompile(b, err, sizeof(err)));
    CHECK(!ruleCompile(bad, err, sizeof(err)));
    CHECK(strstr(err, "bad") != NULL);
    CHECK_EQ(ruleSetAdd(a), 0);
    CHECK_EQ(ruleSetAdd(b), 1);
    CHECK_EQ(ruleSetBuildUnionFilter(uni, sizeof(uni)), 2);
    CHECK(strcmp(uni, "(udp.DstPort == 5000) or (udp)") == 0);
    CHECK(ruleSetMatch(p5000->packet, p5000->packetLen, &p5000->addr) == a);
    CHECK(ruleSetMatch(p6000->packet, p6000->packetLen, &p6000->addr) == b);
    b->enabled = 0;
    CHECK_EQ(ruleSetBuildUnionFilter(uni, sizeof(uni)), 1);
    CHECK(ruleSetMatch(p6000->packet, p6000->packetLen, &p6000->addr) == a); // single enabled rule: fast path
    b->enabled = 1;
    ruleSetRemove(0);
    CHECK_EQ(ruleSet.count, 1);
    CHECK_EQ(ruleSet.rules[0]->index, 0);
    CHECK(ruleSet.rules[0] == b);
    ruleSetClear();
    ruleDestroy(bad);
    packetFree(p5000);
    packetFree(p6000);
}

void testModules(void) {
    rngSeed(777);
    testLagFixed();
    testLagJitter();
    testDrop();
    testBandwidth();
    testThrottle();
    testDuplicate();
    testOod();
    testTamper();
    testFlowScope();
    testRules();
}
