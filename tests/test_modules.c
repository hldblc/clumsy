// Module level tests: synthetic IPv4/UDP packets pushed through the real
// module descriptors with a simulated clock. Uses the WinDivert user-mode
// helpers (checksums, parsing, filter compilation) but never the driver.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "rules.h"
#include "procflow.h"
#include "config.h"
#include "profiles.h"
#include "scenario.h"
#include "pcap.h"
#include "remote.h"
#include "targets.h"

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

// synthetic TCP segment; optLen pads the TCP header with that many option bytes
static PacketNode *mkTcp(uint16_t srcPort, uint16_t dstPort, uint32_t seq, int payloadLen,
                         int syn, int ack, int fin, int outbound, int optLen, uint16_t window) {
    unsigned char buf[4096];
    UINT hdr = 20 + (UINT)optLen;
    UINT len = 20 + hdr + (UINT)payloadLen;
    PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)buf;
    PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(buf + 20);
    WINDIVERT_ADDRESS addr;
    PacketNode *n;
    int i;
    memset(buf, 0, len);
    ip->Version = 4;
    ip->HdrLength = 5;
    ip->Length = WinDivertHelperHtons((UINT16)len);
    ip->TTL = 64;
    ip->Protocol = 6;
    ip->SrcAddr = WinDivertHelperHtonl(0x0A000001);
    ip->DstAddr = WinDivertHelperHtonl(0x0A000002);
    tcp->SrcPort = WinDivertHelperHtons(srcPort);
    tcp->DstPort = WinDivertHelperHtons(dstPort);
    tcp->SeqNum = WinDivertHelperHtonl(seq);
    tcp->HdrLength = (UINT16)(hdr / 4);
    tcp->Syn = syn ? 1 : 0;
    tcp->Ack = ack ? 1 : 0;
    tcp->Fin = fin ? 1 : 0;
    tcp->Window = WinDivertHelperHtons(window);
    for (i = 0; i < optLen; ++i) buf[40 + i] = (unsigned char)(0x01); // NOP options
    for (i = 0; i < payloadLen; ++i) buf[20 + hdr + i] = (unsigned char)(i + 1);
    WinDivertHelperCalcChecksums(buf, len, NULL, 0);
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = outbound ? 1 : 0;
    addr.Layer = WINDIVERT_LAYER_NETWORK;
    n = packetAlloc(buf, len, &addr);
    n->captureTime = T0;
    n->flowHash = ((uint64_t)srcPort << 16) | dstPort;
    return n;
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
    // leave: checksum stays stale but the flags claim validity
    CHECK(moduleSetParamText(tm, "checksum", "leave"));
    n = mkUdp(5, 6, 200, 1);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    CHECK(!checksumsValid(n));
    CHECK(n->addr.UDPChecksum == 1 && n->addr.IPChecksum == 1);
    listFreeAll(&l);

    // zero-fill the payload
    CHECK(moduleSetParamText(tm, "checksum", "redo"));
    CHECK(moduleSetParamText(tm, "mode", "zero"));
    n = mkUdp(5, 6, 100, 1);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    {
        int i, allZero = 1;
        for (i = 0; i < 100; ++i) if ((unsigned char)n->packet[28 + i] != 0) allZero = 0;
        CHECK(allZero);
        CHECK(checksumsValid(n));
    }
    listFreeAll(&l);

    // bitflip: exactly N bits change
    CHECK(moduleSetParamText(tm, "mode", "bitflip"));
    CHECK(moduleSetParamText(tm, "amount", "3"));
    n = mkUdp(5, 6, 100, 1);
    orig = packetClone(n);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    {
        int i, bits = 0;
        for (i = 0; i < 100; ++i) {
            unsigned char x = (unsigned char)(n->packet[28 + i] ^ orig->packet[28 + i]);
            while (x) { bits += x & 1; x >>= 1; }
        }
        CHECK(bits >= 1 && bits <= 3);   // up to 3 (a bit may be picked twice)
    }
    packetFree(orig);
    listFreeAll(&l);

    // truncate payload to 10 bytes, lengths kept consistent
    CHECK(moduleSetParamText(tm, "mode", "truncate"));
    CHECK(moduleSetParamText(tm, "amount", "10"));
    n = mkUdp(5, 6, 200, 1);
    listPushBack(&l, n);
    runStep(tm, &l, T0);
    CHECK_EQ(n->packetLen, 20 + 8 + 10);
    {
        PWINDIVERT_IPHDR ip = NULL;
        WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECK_EQ(WinDivertHelperNtohs(ip->Length), n->packetLen);
        CHECK(checksumsValid(n));
    }
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

// ---- tcp ----
static int tcpHdrLen(PacketNode *n) {
    PWINDIVERT_TCPHDR tcp = NULL;
    WinDivertHelperParsePacket(n->packet, n->packetLen, NULL, NULL, NULL, NULL, NULL, &tcp, NULL, NULL, NULL, NULL, NULL);
    return tcp ? tcp->HdrLength * 4 : -1;
}
static int tcpWindow(PacketNode *n) {
    PWINDIVERT_TCPHDR tcp = NULL;
    WinDivertHelperParsePacket(n->packet, n->packetLen, NULL, NULL, NULL, NULL, NULL, &tcp, NULL, NULL, NULL, NULL, NULL);
    return tcp ? WinDivertHelperNtohs(tcp->Window) : -1;
}

static void testTcp(void) {
    Rule *r = ruleCreate("t", "tcp");
    ModuleInst *tcp = ruleFindModule(r, "tcp");
    PacketList l;
    PacketNode *n;
    int valid;
    listInit(&l);
    CHECK(tcp != NULL);

    // drop SYN
    CHECK(moduleSetParamText(tcp, "syn", "100"));
    listPushBack(&l, mkTcp(100, 80, 0, 0, 1, 0, 0, 1, 0, 8192));   // SYN
    listPushBack(&l, mkTcp(100, 80, 1, 50, 0, 1, 0, 1, 0, 8192));  // data
    runStep(tcp, &l, T0);
    CHECK_EQ(listCount(&l), 1);                 // only the SYN is gone
    listFreeAll(&l);
    CHECK(moduleSetParamText(tcp, "syn", "0"));

    // drop pure ACK but keep ACKs that carry data
    CHECK(moduleSetParamText(tcp, "ack", "100"));
    listPushBack(&l, mkTcp(101, 80, 1, 0, 0, 1, 0, 1, 0, 8192));   // pure ACK
    listPushBack(&l, mkTcp(101, 80, 1, 50, 0, 1, 0, 1, 0, 8192));  // ACK with data
    runStep(tcp, &l, T0);
    CHECK_EQ(listCount(&l), 1);
    listFreeAll(&l);
    CHECK(moduleSetParamText(tcp, "ack", "0"));

    // clamp the advertised window
    CHECK(moduleSetParamText(tcp, "window", "500"));
    n = mkTcp(102, 80, 1, 10, 0, 1, 0, 1, 0, 60000);
    listPushBack(&l, n);
    runStep(tcp, &l, T0);
    CHECK_EQ(tcpWindow(n), 500);
    valid = WinDivertHelperCalcChecksums(n->packet, n->packetLen, NULL, 0);  // already valid -> returns nonzero but unchanged
    CHECK(valid);
    listFreeAll(&l);
    CHECK(moduleSetParamText(tcp, "window", "0"));

    // strip options from a SYN: header shrinks to 20 bytes, length stays consistent
    CHECK(moduleSetParamText(tcp, "strip", "on"));
    n = mkTcp(103, 80, 0, 0, 1, 0, 0, 1, 12, 8192);
    CHECK_EQ(tcpHdrLen(n), 32);
    listPushBack(&l, n);
    runStep(tcp, &l, T0);
    CHECK_EQ(tcpHdrLen(n), 20);
    {
        PWINDIVERT_IPHDR ip = NULL;
        WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        CHECK_EQ(WinDivertHelperNtohs(ip->Length), n->packetLen);
    }
    listFreeAll(&l);
    CHECK(moduleSetParamText(tcp, "strip", "off"));

    // delay retransmissions: the first copy passes, the re-sent one is held
    CHECK(moduleSetParamText(tcp, "retrans", "100"));
    listPushBack(&l, mkTcp(104, 80, 1000, 100, 0, 1, 0, 1, 0, 8192));
    runStep(tcp, &l, T0);
    CHECK_EQ(listCount(&l), 1);                 // new data passes
    listFreeAll(&l);
    listPushBack(&l, mkTcp(104, 80, 1000, 100, 0, 1, 0, 1, 0, 8192));  // same seq again
    runStep(tcp, &l, T0 + 1000);
    CHECK(listEmpty(&l));                        // retransmit held
    CHECK_EQ(tcp->stats.queued, 1);
    runStep(tcp, &l, T0 + 101000);
    CHECK_EQ(listCount(&l), 1);                  // released after the delay
    listFreeAll(&l);
    stopModule(tcp, &l);
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- fragment ----
static int fragInfo(PacketNode *n, UINT *offUnits, int *mf, UINT *totalLen) {
    PWINDIVERT_IPHDR ip = NULL;
    UINT16 f;
    WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (ip == NULL) return 0;
    f = WinDivertHelperNtohs(ip->FragOff0);
    *offUnits = f & 0x1FFF;
    *mf = (f >> 13) & 1;
    *totalLen = WinDivertHelperNtohs(ip->Length);
    return 1;
}

static void testFragment(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *fr = ruleFindModule(r, "fragment");
    PacketList l;
    PacketNode *n;
    int i, pieces, mf, lastMf = 1;
    UINT off, total, prevEnd, reassembled, origPayload;
    unsigned char expect[2000], got[2000];
    listInit(&l);
    CHECK(fr != NULL);
    CHECK(moduleSetParamText(fr, "mtu", "200"));
    // 1500 byte payload UDP packet -> 20 IP + 8 UDP + 1500 = 1528 total
    n = mkUdp(5000, 6000, 1500, 1);
    origPayload = n->packetLen - 20;              // everything after the IP header
    memcpy(expect, n->packet + 20, origPayload);
    listPushBack(&l, n);
    runStep(fr, &l, T0);
    pieces = listCount(&l);
    CHECK(pieces >= 8);                            // 1508 payload / (200-20=180 -> 176) ~ 9 pieces
    // fragments are in order, offsets contiguous, only the last has MF clear,
    // and reassembling their payloads reproduces the original
    prevEnd = 0;
    reassembled = 0;
    for (n = listFirst(&l), i = 0; n; n = listNext(&l, n), ++i) {
        UINT hlen;
        PWINDIVERT_IPHDR ip = NULL;
        CHECK(fragInfo(n, &off, &mf, &total));
        CHECK((n->flags & PN_FLAG_FRAGMENT) != 0);
        CHECK_EQ(off * 8, prevEnd);               // contiguous
        WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        hlen = ip->HdrLength * 4;
        CHECK_EQ(total, n->packetLen);
        CHECK(n->packetLen <= 200);
        memcpy(got + reassembled, n->packet + hlen, n->packetLen - hlen);
        reassembled += n->packetLen - hlen;
        prevEnd = off * 8 + (n->packetLen - hlen);
        lastMf = mf;
    }
    CHECK_EQ(lastMf, 0);                           // last fragment clears MF
    CHECK_EQ(reassembled, origPayload);
    CHECK(memcmp(expect, got, origPayload) == 0);  // payload preserved
    CHECK_EQ(fr->stats.packets, 1);
    listFreeAll(&l);

    // packets at or below the MTU pass untouched
    CHECK(moduleSetParamText(fr, "mtu", "1500"));
    n = mkUdp(1, 2, 100, 1);
    listPushBack(&l, n);
    runStep(fr, &l, T0);
    CHECK_EQ(listCount(&l), 1);
    CHECK(((listFirst(&l))->flags & PN_FLAG_FRAGMENT) == 0);
    listFreeAll(&l);

    // lose-a-fragment: one piece is missing, so reassembly would fail
    CHECK(moduleSetParamText(fr, "mtu", "200"));
    CHECK(moduleSetParamText(fr, "lose", "100"));
    n = mkUdp(7, 8, 1500, 1);
    listPushBack(&l, n);
    runStep(fr, &l, T0);
    CHECK(fr->stats.dropped >= 1);
    {
        // offsets are no longer fully contiguous (a hole exists)
        int hole = 0;
        prevEnd = 0;
        for (n = listFirst(&l); n; n = listNext(&l, n)) {
            PWINDIVERT_IPHDR ip = NULL;
            UINT hlen;
            fragInfo(n, &off, &mf, &total);
            if (off * 8 != prevEnd) hole = 1;
            WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            hlen = ip->HdrLength * 4;
            prevEnd = off * 8 + (n->packetLen - hlen);
        }
        CHECK(hole);
    }
    listFreeAll(&l);
    ruleDestroy(r);
}

// ---- outage ----
static void testOutage(void) {
    Rule *r = ruleCreate("t", "udp");
    ModuleInst *out = ruleFindModule(r, "outage");
    PacketList l;
    listInit(&l);
    CHECK(out != NULL);
    CHECK(moduleSetParamText(out, "mode", "periodic"));
    CHECK(moduleSetParamText(out, "up", "100"));      // 100 ms up
    CHECK(moduleSetParamText(out, "down", "50"));     // 50 ms down
    CHECK(moduleSetParamText(out, "startdown", "off"));

    // starts up: traffic passes
    fill(&l, 5, 1);
    runStep(out, &l, T0);
    CHECK_EQ(listCount(&l), 5);
    CHECK_EQ(out->desc->nextDeadline(out, T0), T0 + 100000);
    listFreeAll(&l);

    // during the down phase everything is dropped
    fill(&l, 5, 1);
    runStep(out, &l, T0 + 120000);   // 120 ms: into the first down phase (100..150)
    CHECK(listEmpty(&l));
    CHECK_EQ(out->stats.dropped, 5);
    listFreeAll(&l);

    // recovers afterwards (150..250 is up)
    fill(&l, 5, 1);
    runStep(out, &l, T0 + 200000);
    CHECK_EQ(listCount(&l), 5);
    listFreeAll(&l);
    stopModule(out, &l);

    // start-down flag
    CHECK(moduleSetParamText(out, "startdown", "on"));
    fill(&l, 3, 1);
    runStep(out, &l, T0);
    CHECK(listEmpty(&l));
    listFreeAll(&l);
    stopModule(out, &l);
    ruleDestroy(r);
}

// ---- per-process flow table (pure parts) ----
static void testProcflow(void) {
    FlowTable t;
    FlowKey ka, kb, kc;
    uint32_t la[4] = { 0x0A000001, 0, 0, 0 }, ra[4] = { 0x08080808, 0, 0, 0 };
    PacketNode *out, *in;
    flowTableInit(&t, 64);

    // the two directions of one connection map to the same key
    flowKeyFromEndpoints(&ka, 17, la, 5000, ra, 53);
    flowKeyFromEndpoints(&kb, 17, ra, 53, la, 5000);
    CHECK(flowKeyEqual(&ka, &kb));
    // a different port is a different key
    flowKeyFromEndpoints(&kc, 17, la, 5001, ra, 53);
    CHECK(!flowKeyEqual(&ka, &kc));

    flowTableSet(&t, &ka, 4321, T0);
    CHECK_EQ(flowTableGet(&t, &kb), 4321);     // looked up from the other direction
    CHECK_EQ(flowTableGet(&t, &kc), 0);
    CHECK_EQ(flowTableCount(&t), 1);
    flowTableDel(&t, &kb);
    CHECK_EQ(flowTableGet(&t, &ka), 0);
    CHECK_EQ(flowTableCount(&t), 0);

    // a packet's key matches the key built from its own endpoints, and a flow
    // learned from a FLOW event (local=src, remote=dst) is found from the packet
    out = mkUdp(5000, 53, 20, 1);
    {
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)out->packet;
        uint32_t src[4] = { 0, 0, 0, 0 }, dst[4] = { 0, 0, 0, 0 };
        FlowKey kp, ke;
        src[0] = ip->SrcAddr; dst[0] = ip->DstAddr;
        CHECK(flowKeyFromPacket(&kp, out->packet, out->packetLen));
        flowKeyFromEndpoints(&ke, 17, src, WinDivertHelperHtons(5000), dst, WinDivertHelperHtons(53));
        CHECK(flowKeyEqual(&kp, &ke));
        flowTableSet(&t, &ke, 999, T0);
        CHECK_EQ(flowTableGet(&t, &kp), 999);        // packet finds the learned flow
        CHECK_EQ(procflowLookup(out->packet, out->packetLen), 0);  // subsystem not running -> 0
    }
    packetFree(out);
    flowTableFree(&t);

    // name matching: base name, case-insensitive, optional .exe
    CHECK(processNameMatch("game.exe", "C:\\Games\\Dune\\game.exe"));
    CHECK(processNameMatch("game", "C:\\Games\\Dune\\game.exe"));
    CHECK(processNameMatch("GAME.EXE", "d:/x/game.exe"));
    CHECK(!processNameMatch("game", "C:\\game2.exe"));
    CHECK(!processNameMatch("", "C:\\game.exe"));
    CHECK(!processNameMatch("game.exe", NULL));
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

    // live filter validation helper
    {
        char e[256];
        CHECK(filterCheck("tcp and outbound", e, sizeof(e)));
        CHECK(filterCheck("udp.DstPort == 80", e, sizeof(e)));
        CHECK(!filterCheck("", e, sizeof(e)));
        CHECK(!filterCheck("   ", e, sizeof(e)));
        CHECK(!filterCheck("tcp and and", e, sizeof(e)));
        CHECK(!filterCheck("notafield == 1", e, sizeof(e)));
    }
}

// ---- config save/load + profiles ----
static void testConfig(void) {
    static char buf[CONFIG_TEXT_MAX];
    char err[256];
    Rule *a, *b, *lag;
    ModuleInst *m;
    char val[48];

    ruleSetClear();
    a = ruleCreate("Game", "udp and outbound");
    snprintf(a->process, sizeof(a->process), "game.exe");
    ruleSetAdd(a);
    b = ruleCreate("Voice", "udp.DstPort == 50000");
    ruleSetAdd(b);
    m = ruleFindModule(a, "lag");
    moduleSetEnabled(m, 1);
    CHECK(moduleSetParamText(m, "time", "20/80"));
    CHECK(moduleSetParamText(m, "dist", "normal"));
    m = ruleFindModule(b, "drop");
    moduleSetEnabled(m, 1);
    CHECK(moduleSetParamText(m, "chance", "5"));

    CHECK(configSerialize(buf, sizeof(buf)) > 0);
    CHECK(strstr(buf, "name = Game") != NULL);
    CHECK(strstr(buf, "process = game.exe") != NULL);
    CHECK(strstr(buf, "lag.time = 20/80") != NULL);

    // round trip: apply the serialized text and check the rebuilt rules
    CHECK(configApply(buf, err, sizeof(err)));
    CHECK_EQ(ruleSet.count, 2);
    CHECK(strcmp(ruleSet.rules[0]->name, "Game") == 0);
    CHECK(strcmp(ruleSet.rules[0]->filter, "udp and outbound") == 0);
    CHECK(strcmp(ruleSet.rules[0]->process, "game.exe") == 0);
    lag = ruleFindModule(ruleSet.rules[0], "lag");
    CHECK(lag->enabled);
    CHECK(moduleGetParamText(lag, "time", val, sizeof(val)));
    CHECK(strcmp(val, "20/80") == 0);
    CHECK(moduleGetParamText(lag, "dist", val, sizeof(val)));
    CHECK(strcmp(val, "normal") == 0);
    CHECK(ruleFindModule(ruleSet.rules[1], "drop")->enabled);

    // a fragment applies to one rule in place
    {
        ModuleInst *bw;
        configApplyFragment(ruleSet.rules[0], "bandwidth=on bandwidth.limit=256; drop=on drop.chance=2.5");
        bw = ruleFindModule(ruleSet.rules[0], "bandwidth");
        CHECK(bw->enabled);
        CHECK(moduleGetParamText(bw, "limit", val, sizeof(val)));
        CHECK(strcmp(val, "256") == 0);
        CHECK(ruleFindModule(ruleSet.rules[0], "drop")->enabled);
    }

    // every built-in profile applies without error
    CHECK(profileCount() > 5);
    {
        int i;
        for (i = 0; i < profileCount(); ++i) {
            CHECK(profileText(i) != NULL);
            CHECK(configApplyFragment(ruleSet.rules[0], profileText(i)) > 0);
        }
    }
    ruleSetClear();
}

// ---- scenario ----
static int scenApplyCount;
static char scenLast[256];
static void scenMockApply(const char *frag, void *user) {
    UNREFERENCED_PARAMETER(user);
    ++scenApplyCount;
    snprintf(scenLast, sizeof(scenLast), "%s", frag);
}

static void testScenario(void) {
    Scenario s;
    char err[256];
    const char *text =
        "# a short scenario\n"
        "0     lag=on lag.time=50\n"
        "5000  lag.time=300 drop=on drop.chance=5\n"
        "15000 outage=on\n";
    CHECK(scenarioParse(&s, text, err, sizeof(err)));
    CHECK_EQ(s.count, 3);
    CHECK_EQ(s.loop, 0);
    CHECK_EQ(scenarioSpanMs(&s), 15000);

    scenApplyCount = 0;
    scenarioStart(&s, T0);
    // at t=0 the first step fires
    CHECK(scenarioTick(&s, T0, scenMockApply, NULL));
    CHECK_EQ(scenApplyCount, 1);
    CHECK(strstr(scenLast, "lag.time=50") != NULL);
    // nothing new until 5s
    CHECK(scenarioTick(&s, T0 + 4999000, scenMockApply, NULL));
    CHECK_EQ(scenApplyCount, 1);
    CHECK(scenarioTick(&s, T0 + 5000000, scenMockApply, NULL));
    CHECK_EQ(scenApplyCount, 2);
    // jumping past the end fires the remaining step and finishes
    CHECK(!scenarioTick(&s, T0 + 20000000, scenMockApply, NULL));
    CHECK_EQ(scenApplyCount, 3);
    CHECK(strstr(scenLast, "outage=on") != NULL);

    // loop keeps running and restarts
    {
        Scenario l;
        const char *lt = "0 drop=on\n1000 drop=off\nloop\n";
        CHECK(scenarioParse(&l, lt, err, sizeof(err)));
        CHECK_EQ(l.loop, 1);
        scenApplyCount = 0;
        scenarioStart(&l, T0);
        CHECK(scenarioTick(&l, T0 + 2000000, scenMockApply, NULL));   // fires both, then restarts
        CHECK(scenApplyCount >= 2);
    }

    CHECK(!scenarioParse(&s, "# only comments\n", err, sizeof(err)));
    CHECK(!scenarioParse(&s, "notanumber lag=on\n", err, sizeof(err)));
}

// ---- pcapng writer ----
static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void testPcap(void) {
    unsigned char buf[2048];
    size_t hn, pn;
    PacketNode *n;
    char comment[160];

    hn = pcapBuildHeaders(buf, sizeof(buf));
    CHECK(hn == 48);
    CHECK_EQ(rd32(buf + 0), 0x0A0D0D0A);        // SHB
    CHECK_EQ(rd32(buf + 8), 0x1A2B3C4D);        // byte-order magic
    CHECK_EQ(rd32(buf + 4), 28);                // SHB length
    CHECK_EQ(rd32(buf + 24), 28);               // SHB trailer
    CHECK_EQ(rd32(buf + 28), 0x00000001);       // IDB
    CHECK_EQ(rd32(buf + 28 + 4), 20);           // IDB length
    CHECK_EQ(buf[28 + 8], 101);                 // LINKTYPE_RAW

    n = mkUdp(1, 2, 40, 1);
    pn = pcapBuildPacketBlock(buf, sizeof(buf), (const unsigned char *)n->packet, n->packetLen,
                              1700000000000000LL, "out Rule 1 lagged");
    CHECK(pn > 0);
    CHECK_EQ(rd32(buf + 0), 0x00000006);        // EPB
    CHECK_EQ(rd32(buf + 4), (uint32_t)pn);      // total length
    CHECK_EQ(rd32(buf + 4), rd32(buf + pn - 4)); // leading == trailing length
    CHECK_EQ(rd32(buf + 20), n->packetLen);     // captured length
    CHECK_EQ(rd32(buf + 24), n->packetLen);     // original length
    CHECK((pn % 4) == 0);
    packetFree(n);

    // comment reflects the flags and direction
    pcapActionComment(comment, sizeof(comment), "Game", PN_FLAG_LAGGED | PN_FLAG_TAMPERED, 1);
    CHECK(strstr(comment, "out") != NULL);
    CHECK(strstr(comment, "Game") != NULL);
    CHECK(strstr(comment, "lagged") != NULL);
    CHECK(strstr(comment, "tampered") != NULL);
    pcapActionComment(comment, sizeof(comment), "R", PN_FLAG_DUPLICATE, 0);
    CHECK(strstr(comment, "in") != NULL);
    CHECK(strstr(comment, "duplicate") != NULL);

    // a too-small buffer is refused, not overrun
    CHECK_EQ(pcapBuildHeaders(buf, 10), 0u);
    CHECK_EQ(pcapBuildPacketBlock(buf, 8, buf, 40, 0, "x"), 0u);
}

// ---- remote API (JSON + command apply, no sockets) ----
static void testRemote(void) {
    static char buf[CONFIG_TEXT_MAX];
    char val[48];
    Rule *r;
    ModuleInst *lag, *drop;
    ruleSetClear();
    r = ruleCreate("Game", "udp and outbound");
    snprintf(r->process, sizeof(r->process), "game.exe");
    ruleSetAdd(r);

    CHECK(remoteBuildStatus(buf, sizeof(buf)) > 0);
    CHECK(strstr(buf, "\"running\":false") != NULL);
    CHECK(strstr(buf, "\"ruleCount\":1") != NULL);

    CHECK(remoteBuildRules(buf, sizeof(buf)) > 0);
    CHECK(strstr(buf, "\"name\":\"Game\"") != NULL);
    CHECK(strstr(buf, "\"process\":\"game.exe\"") != NULL);
    CHECK(strstr(buf, "\"lag\"") != NULL);

    // commands apply to the rule set
    remoteApplyCommand("set 0 lag time 123");
    lag = ruleFindModule(ruleSet.rules[0], "lag");
    CHECK(moduleGetParamText(lag, "time", val, sizeof(val)));
    CHECK(strcmp(val, "123") == 0);
    remoteApplyCommand("set 0 lag time 20/80");
    CHECK(moduleGetParamText(lag, "time", val, sizeof(val)));
    CHECK(strcmp(val, "20/80") == 0);
    remoteApplyCommand("enable 0 drop 1");
    drop = ruleFindModule(ruleSet.rules[0], "drop");
    CHECK(drop->enabled);
    remoteApplyCommand("enable 0 drop 0");
    CHECK(!drop->enabled);
    remoteApplyCommand("profile 3G");
    CHECK(ruleFindModule(ruleSet.rules[0], "lag")->enabled);
    // malformed commands are ignored, not crashing
    remoteApplyCommand("set 9 lag time 1");
    remoteApplyCommand("garbage");
    remoteApplyCommand("set 0 nosuch time 1");
    ruleSetClear();
}

// ---- targets: hostname / IP / CIDR -> filter clause ----
static void testTargets(void) {
    char out[512];
    uint32_t lo, hi;
    char err[128];

    CHECK(targetParseCidr("10.0.0.0/24", &lo, &hi));
    CHECK_EQ(lo, 0x0A000000u);
    CHECK_EQ(hi, 0x0A0000FFu);
    CHECK(targetParseCidr("192.168.1.128/25", &lo, &hi));
    CHECK_EQ(lo, 0xC0A80180u);
    CHECK_EQ(hi, 0xC0A801FFu);
    CHECK(targetParseCidr("1.2.3.4/32", &lo, &hi));
    CHECK_EQ(lo, hi);
    CHECK(!targetParseCidr("1.2.3.4", &lo, &hi));       // no slash
    CHECK(!targetParseCidr("1.2.3.4/33", &lo, &hi));    // bad width

    CHECK(targetBuildClause("10.0.0.5", out, sizeof(out)));
    CHECK(strcmp(out, "(ip.DstAddr == 10.0.0.5 or ip.SrcAddr == 10.0.0.5)") == 0);

    CHECK(targetBuildClause("10.0.0.0/24", out, sizeof(out)));
    CHECK(strstr(out, "ip.DstAddr >= 10.0.0.0") != NULL);
    CHECK(strstr(out, "ip.DstAddr <= 10.0.0.255") != NULL);

    // the produced clauses must compile as real WinDivert filters
    CHECK(filterCheck(out, err, sizeof(err)));
    targetBuildClause("10.0.0.5", out, sizeof(out));
    CHECK(filterCheck(out, err, sizeof(err)));

    // localhost resolves offline to 127.0.0.1
    if (targetBuildClause("localhost", out, sizeof(out))) {
        CHECK(strstr(out, "127.0.0.1") != NULL);
        CHECK(filterCheck(out, err, sizeof(err)));
    }
    CHECK(!targetBuildClause("", out, sizeof(out)));
    CHECK(!targetBuildClause("1.2.3.4/99", out, sizeof(out)));
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
    testTcp();
    testOutage();
    testFragment();
    testFlowScope();
    testProcflow();
    testRules();
    testConfig();
    testScenario();
    testPcap();
    testRemote();
    testTargets();
}
