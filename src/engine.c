#include <stdlib.h>
#include <string.h>
#include "engine.h"
#include "procflow.h"
#include "pcap.h"

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif
#ifndef ERROR_NO_DATA
#define ERROR_NO_DATA 232L
#endif
#ifndef ERROR_INVALID_IMAGE_HASH
#define ERROR_INVALID_IMAGE_HASH 577L
#endif
#ifndef ERROR_DRIVER_FAILED_PRIOR_UNLOAD
#define ERROR_DRIVER_FAILED_PRIOR_UNLOAD 654L
#endif
#ifndef ERROR_DRIVER_BLOCKED
#define ERROR_DRIVER_BLOCKED 1275L
#endif
#ifndef EPT_S_NOT_REGISTERED
#define EPT_S_NOT_REGISTERED 1753L
#endif

#define CAPTURE_BUF_SIZE (256 * 1024)
#define RING_SIZE 16384              // power of two
#define RING_MASK (RING_SIZE - 1)
#define HEARTBEAT_MS 50              // longest the processor sleeps without a deadline
#define DIVERT_PRIORITY 0

EngineStats engineStats;

static HANDLE divertHandle = INVALID_HANDLE_VALUE;
static HANDLE captureThread = NULL, processThread = NULL;
static HANDLE ringEvent = NULL, wakeEvent = NULL, stopEvent = NULL, spaceEvent = NULL, timerHandle = NULL;
static volatile LONG engineState = 0;   // 0 stopped, 1 running, 2 stopping
static int highResTimer = 0;
static HANDLE watchdogThread = NULL;
static volatile LONG64 heartbeatUs = 0;
static int watchdogSeconds = 10;
static char filterInUse[FILTER_BUFSIZE * RULE_MAX + 64];
static PacketList passList;             // packets that matched no rule

// ---- single producer / single consumer ring ----
static PacketNode *ring[RING_SIZE];
static volatile LONG ringHead = 0;      // consumer side
static volatile LONG ringTail = 0;      // producer side

static int ringPush(PacketNode *n) {
    LONG tail = ringTail;
    LONG next = (tail + 1) & RING_MASK;
    if (next == atomicLoad32(&ringHead)) {
        return 0;
    }
    ring[tail] = n;
    atomicExch32(&ringTail, next);
    return 1;
}

static PacketNode *ringPop(void) {
    LONG head = ringHead;
    PacketNode *n;
    if (head == atomicLoad32(&ringTail)) {
        return NULL;
    }
    n = ring[head];
    ring[head] = NULL;
    atomicExch32(&ringHead, (head + 1) & RING_MASK);
    return n;
}

static LONG ringDepth(void) {
    return (atomicLoad32(&ringTail) - atomicLoad32(&ringHead)) & RING_MASK;
}

// ---- flow hashing ----
static uint64_t fnv1a(uint64_t h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    size_t i;
    for (i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int tupleCompare(const UINT32 *a, UINT16 pa, const UINT32 *b, UINT16 pb) {
    int c = memcmp(a, b, 16);
    if (c != 0) return c;
    return (int)pa - (int)pb;
}

static uint64_t flowHashOf(const void *packet, UINT len) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    UINT8 proto = 0;
    UINT32 a[4] = { 0, 0, 0, 0 }, b[4] = { 0, 0, 0, 0 };
    UINT16 pa = 0, pb = 0;
    uint64_t h = 14695981039346656037ULL;
    WinDivertHelperParsePacket(packet, len, &ip, &ip6, &proto, NULL, NULL, &tcp, &udp, NULL, NULL, NULL, NULL);
    if (ip) {
        a[0] = ip->SrcAddr;
        b[0] = ip->DstAddr;
    } else if (ip6) {
        memcpy(a, ip6->SrcAddr, 16);
        memcpy(b, ip6->DstAddr, 16);
    }
    if (tcp) {
        pa = tcp->SrcPort;
        pb = tcp->DstPort;
    } else if (udp) {
        pa = udp->SrcPort;
        pb = udp->DstPort;
    }
    if (tupleCompare(a, pa, b, pb) > 0) {
        // canonical order so both directions of a connection hash alike
        h = fnv1a(h, b, 16);
        h = fnv1a(h, &pb, 2);
        h = fnv1a(h, a, 16);
        h = fnv1a(h, &pa, 2);
    } else {
        h = fnv1a(h, a, 16);
        h = fnv1a(h, &pa, 2);
        h = fnv1a(h, b, 16);
        h = fnv1a(h, &pb, 2);
    }
    h = fnv1a(h, &proto, 1);
    return h;
}

// ---- capture thread ----
static void enqueue(PacketNode *node) {
    while (!ringPush(node)) {
        atomicAdd64(&engineStats.ringWaits, 1);
        SetEvent(ringEvent);
        if (engineState != 1) {
            // stopping and the processor is not draining: do not block forever
            if (!ringPush(node)) {
                packetFree(node);
            }
            return;
        }
        WaitForSingleObject(spaceEvent, 20);
    }
}

static DWORD WINAPI captureLoop(LPVOID arg) {
    char *buf = (char *)malloc(CAPTURE_BUF_SIZE);
    WINDIVERT_ADDRESS addrs[WINDIVERT_BATCH_MAX];
    UNREFERENCED_PARAMETER(arg);
    if (buf == NULL) {
        return 1;
    }
    for (;;) {
        UINT recvLen = 0, addrLen = sizeof(addrs), count, i, remaining;
        const char *p;
        int64_t now;
        if (!WinDivertRecvEx(divertHandle, buf, CAPTURE_BUF_SIZE, &recvLen, 0, addrs, &addrLen, NULL)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_DATA || e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED) {
                LOG("capture: handle shut down (%lu), exiting", e);
                break;
            }
            LOG("capture: WinDivertRecvEx failed (%lu)", e);
            if (engineState != 1) break;
            continue;
        }
        now = clockNowUs();
        count = addrLen / sizeof(WINDIVERT_ADDRESS);
        p = buf;
        remaining = recvLen;
        for (i = 0; i < count && remaining > 0; ++i) {
            PVOID next = NULL;
            UINT nextLen = 0, pktLen;
            PacketNode *node;
            if (WinDivertHelperParsePacket(p, remaining, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &next, &nextLen) && next != NULL) {
                pktLen = (UINT)((const char *)next - p);
            } else {
                pktLen = remaining;
                next = NULL;
                nextLen = 0;
            }
            node = packetAlloc(p, pktLen, &addrs[i]);
            if (node != NULL) {
                node->captureTime = now;
                node->flowHash = flowHashOf(p, pktLen);
                enqueue(node);
            } else {
                atomicAdd64(&engineStats.allocFailed, 1);
            }
            if (next == NULL) break;
            p = (const char *)next;
            remaining = nextLen;
        }
        SetEvent(ringEvent);
    }
    free(buf);
    return 0;
}

// ---- sending ----
static int resendInboundIcmpAsOutbound(PacketNode *n) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_ICMPHDR icmp = NULL;
    PWINDIVERT_ICMPV6HDR icmp6 = NULL;
    UINT sendLen = 0;
    // WinDivert sometimes refuses reinjecting inbound ICMP; send it back out instead.
    WinDivertHelperParsePacket(n->packet, n->packetLen, &ip, &ip6, NULL, &icmp, &icmp6, NULL, NULL, NULL, NULL, NULL, NULL);
    if ((icmp == NULL && icmp6 == NULL) || n->addr.Outbound) {
        return 0;
    }
    n->addr.Outbound = TRUE;
    if (ip) {
        UINT32 tmp = ip->SrcAddr;
        ip->SrcAddr = ip->DstAddr;
        ip->DstAddr = tmp;
    } else if (ip6) {
        UINT32 tmp[4];
        memcpy(tmp, ip6->SrcAddr, sizeof(tmp));
        memcpy(ip6->SrcAddr, ip6->DstAddr, sizeof(tmp));
        memcpy(ip6->DstAddr, tmp, sizeof(tmp));
    }
    return WinDivertSend(divertHandle, n->packet, n->packetLen, &sendLen, &n->addr) ? 1 : 0;
}

static void sendList(PacketList *list) {
    PacketNode *n;
    while ((n = listFirst(list)) != NULL) {
        UINT sendLen = 0;
        int ok;
        listUnlink(list, n);
        ok = WinDivertSend(divertHandle, n->packet, n->packetLen, &sendLen, &n->addr);
        if (!ok) {
            DWORD e = GetLastError();
            ok = resendInboundIcmpAsOutbound(n);
            if (!ok) {
                LOG("send failed (%lu), len %u, %s", e, n->packetLen, n->addr.Outbound ? "outbound" : "inbound");
            }
        }
        if (ok) {
            int64_t lat = clockNowUs() - n->captureTime;
            atomicAdd64(&engineStats.sent, 1);
            atomicAdd64(&engineStats.bytesSent, n->packetLen);
            atomicAdd64(&engineStats.latencySumUs, lat);
            atomicAdd64(&engineStats.latencySamples, 1);
        } else {
            atomicAdd64(&engineStats.sendFailed, 1);
        }
        if (pcapIsOpen()) {
            const char *rn = (n->ruleIndex < (uint16_t)ruleSet.count) ? ruleSet.rules[n->ruleIndex]->name : "passthrough";
            pcapLogNode(n, rn);
        }
        packetFree(n);
    }
}

// ---- processor thread ----
static void drain(void) {
    PacketNode *n;
    int drained = 0;
    LONG depth = ringDepth();
    if (depth > engineStats.ringDepthMax) {
        atomicExch32(&engineStats.ringDepthMax, depth);
    }
    atomicExch32(&engineStats.ringDepth, depth);
    while ((n = ringPop()) != NULL) {
        Rule *r = ruleSetMatch(n->packet, n->packetLen, &n->addr);
        atomicAdd64(&engineStats.captured, 1);
        atomicAdd64(&engineStats.bytesCaptured, n->packetLen);
        if (r != NULL && r->process[0]) {
            // scope the rule to one process via the flow-layer pid map
            char exe[64];
            uint32_t pid = procflowLookup(n->packet, n->packetLen);
            n->processId = pid;
            if (pid == 0 || !procflowName(pid, exe, sizeof(exe)) || !processNameMatch(r->process, exe)) {
                r = NULL;
            }
        }
        if (r != NULL) {
            n->ruleIndex = (uint16_t)r->index;
            listPushBack(&r->list, n);
            atomicAdd64(&r->matched, 1);
            atomicAdd64(&r->bytesMatched, n->packetLen);
        } else {
            n->ruleIndex = PACKET_RULE_NONE;
            listPushBack(&passList, n);
            atomicAdd64(&engineStats.passthrough, 1);
        }
        ++drained;
    }
    if (drained) {
        SetEvent(spaceEvent);
    }
}

static void processRule(Rule *r, int64_t now) {
    int i;
    for (i = 0; i < r->moduleCount; ++i) {
        ModuleInst *m = r->modules[i];
        if (m->enabled && r->enabled) {
            if (!m->lastEnabled) {
                m->desc->startUp(m, now);
                m->lastEnabled = 1;
            }
            if (m->desc->process(m, &r->list, now)) {
                atomicExch16(&m->triggered, 1);
            }
        } else if (m->lastEnabled) {
            m->desc->closeDown(m, &r->list);
            m->lastEnabled = 0;
        }
    }
    sendList(&r->list);
}

static void step(int64_t now) {
    int i;
    for (i = 0; i < ruleSet.count; ++i) {
        processRule(ruleSet.rules[i], now);
    }
    sendList(&passList);
    atomicAdd64(&engineStats.steps, 1);
}

static int64_t computeDeadline(int64_t now) {
    int64_t best = -1;
    int i, j;
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            int64_t d;
            if (!m->lastEnabled || m->desc->nextDeadline == NULL) continue;
            d = m->desc->nextDeadline(m, now);
            if (d >= 0 && (best < 0 || d < best)) best = d;
        }
    }
    return best;
}

static void armTimer(int64_t deltaUs) {
    LARGE_INTEGER due;
    if (deltaUs < 1) deltaUs = 1;
    due.QuadPart = -(deltaUs * 10); // relative, 100 ns units
    SetWaitableTimer(timerHandle, &due, 0, NULL, NULL, FALSE);
}

static void flushAll(void) {
    int i, j;
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            if (m->lastEnabled) {
                m->desc->closeDown(m, &r->list);
                m->lastEnabled = 0;
            }
        }
        sendList(&r->list);
    }
    sendList(&passList);
}

static DWORD WINAPI processLoop(LPVOID arg) {
    HANDLE waits[4];
    UNREFERENCED_PARAMETER(arg);
    waits[0] = stopEvent;
    waits[1] = ringEvent;
    waits[2] = wakeEvent;
    waits[3] = timerHandle;
    for (;;) {
        int64_t now = clockNowUs();
        int64_t deadline = computeDeadline(now);
        DWORD count = 3, timeoutMs = HEARTBEAT_MS, r;
        if (deadline >= 0) {
            int64_t delta = deadline - now;
            if (delta <= 0) {
                timeoutMs = 0;
            } else if (delta < MS_TO_US(HEARTBEAT_MS)) {
                armTimer(delta);
                count = 4;
                timeoutMs = (DWORD)((delta + 999) / 1000) + 1;
            }
        }
        r = WaitForMultipleObjects(count, waits, FALSE, timeoutMs);
        if (r == WAIT_OBJECT_0) {
            break;
        }
        now = clockNowUs();
        if (deadline >= 0 && now > deadline + 2000) {
            atomicAdd64(&engineStats.lateWakeups, 1);
        }
        atomicExch64(&heartbeatUs, now);
        drain();
        step(now);
    }
    // stopping: the capture thread has exited, take what is left and flush every module
    drain();
    flushAll();
    return 0;
}

// Safety watchdog: if the processor thread stops updating its heartbeat while
// the engine is running, the process is wedged with diversion active. Closing
// the handle makes the kernel stop diverting so normal traffic resumes, and
// the capture/processor loops then error out and exit.
static DWORD WINAPI watchdogLoop(LPVOID arg) {
    UNREFERENCED_PARAMETER(arg);
    while (engineState == 1) {
        Sleep(500);
        if (engineState == 1 && watchdogSeconds > 0) {
            int64_t beat = atomicLoad64(&heartbeatUs);
            if (beat != 0 && clockNowUs() - beat > (int64_t)watchdogSeconds * 1000000) {
                LOG("watchdog: processor stalled, force-closing the divert handle to restore traffic");
                if (divertHandle != INVALID_HANDLE_VALUE) {
                    WinDivertShutdown(divertHandle, WINDIVERT_SHUTDOWN_BOTH);
                    WinDivertClose(divertHandle);
                    divertHandle = INVALID_HANDLE_VALUE;
                }
                return 0;
            }
        }
    }
    return 0;
}

void engineSetWatchdog(int seconds) {
    watchdogSeconds = seconds;
}

// ---- public API ----
int engineIsRunning(void) {
    return engineState == 1;
}

int engineHighResolutionTimer(void) {
    return highResTimer;
}

const char *engineFilterInUse(void) {
    return filterInUse;
}

void engineWake(void) {
    if (wakeEvent) SetEvent(wakeEvent);
}

void engineResetStats(void) {
    memset(&engineStats, 0, sizeof(engineStats));
    engineStats.startedAtUs = clockNowUs();
}

void engineDescribeOpenError(DWORD code, char *buf, size_t size) {
    const char *hint;
    switch (code) {
    case ERROR_FILE_NOT_FOUND:        hint = "the WinDivert driver files (WinDivert.dll, WinDivert64.sys) are missing next to clumsy.exe"; break;
    case ERROR_PATH_NOT_FOUND:        hint = "the driver could not be loaded; another program may hold an incompatible WinDivert version, or the service is stuck (reboot or run 'sc stop WinDivert')"; break;
    case ERROR_ACCESS_DENIED:         hint = "clumsy must run as Administrator"; break;
    case ERROR_INVALID_PARAMETER:     hint = "invalid filter expression"; break;
    case ERROR_INVALID_IMAGE_HASH:    hint = "Windows rejected the driver signature; try the A/B/C build variants, or Secure Boot / memory integrity may be blocking it"; break;
    case ERROR_DRIVER_FAILED_PRIOR_UNLOAD: hint = "a previous WinDivert driver is still unloading; wait a few seconds or reboot"; break;
    case ERROR_SERVICE_DOES_NOT_EXIST: hint = "the WinDivert service does not exist yet; the driver install failed"; break;
    case ERROR_SERVICE_DISABLED:      hint = "the WinDivert service is disabled; enable it with 'sc config WinDivert start= demand'"; break;
    case ERROR_SERVICE_MARKED_FOR_DELETE: hint = "the WinDivert service is marked for deletion; reboot"; break;
    case ERROR_SERVICE_EXISTS:        hint = "a different WinDivert service is already registered (VPN, anti-cheat or an older clumsy); stop it or reboot"; break;
    case ERROR_DRIVER_BLOCKED:        hint = "the driver is blocked by policy (memory integrity / HVCI); check Windows Security > Core isolation"; break;
    case EPT_S_NOT_REGISTERED:        hint = "the Base Filtering Engine service is not running; start 'BFE'"; break;
    default:                          hint = "make sure you run clumsy as Administrator"; break;
    }
    snprintf(buf, size, "Failed to start filtering: failed to open device (code:%lu). %s.", code, hint);
}

int engineStart(char *err, size_t errSize) {
    int i, j, enabled = 0;
    if (engineState != 0) {
        snprintf(err, errSize, "Already running.");
        return 0;
    }
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        if (!r->enabled) continue;
        if (!ruleCompile(r, err, errSize)) return 0;
        ++enabled;
    }
    if (enabled == 0) {
        snprintf(err, errSize, "No enabled rule to capture with.");
        return 0;
    }
    if (ruleSetBuildUnionFilter(filterInUse, sizeof(filterInUse)) <= 0) {
        snprintf(err, errSize, "Combined filter is too long.");
        return 0;
    }

    divertHandle = WinDivertOpen(filterInUse, WINDIVERT_LAYER_NETWORK, DIVERT_PRIORITY, 0);
    if (divertHandle == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_INVALID_PARAMETER) {
            snprintf(err, errSize, "Failed to start filtering: filter syntax error.");
        } else {
            engineDescribeOpenError(lastError, err, errSize);
        }
        return 0;
    }
    LOG("opened WinDivert with filter: %s", filterInUse);

    if (ruleSetAnyProcess()) {
        char pferr[MSG_BUFSIZE];
        if (!procflowStart(pferr, sizeof(pferr))) {
            snprintf(err, errSize, "%s", pferr);
            WinDivertClose(divertHandle);
            divertHandle = INVALID_HANDLE_VALUE;
            return 0;
        }
        LOG("per-process flow tracking started");
    }

    // keep as much as the kernel allows so slow processing never drops packets silently
    WinDivertSetParam(divertHandle, WINDIVERT_PARAM_QUEUE_LENGTH, WINDIVERT_PARAM_QUEUE_LENGTH_MAX);
    WinDivertSetParam(divertHandle, WINDIVERT_PARAM_QUEUE_TIME, 8000);
    WinDivertSetParam(divertHandle, WINDIVERT_PARAM_QUEUE_SIZE, WINDIVERT_PARAM_QUEUE_SIZE_MAX);

    listInit(&passList);
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        listInit(&r->list);
        r->matched = 0;
        r->bytesMatched = 0;
        for (j = 0; j < r->moduleCount; ++j) {
            r->modules[j]->lastEnabled = 0;
            r->modules[j]->triggered = 0;
        }
    }
    engineResetStats();
    ringHead = ringTail = 0;

    ringEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    wakeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    spaceEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    timerHandle = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    highResTimer = timerHandle != NULL;
    if (timerHandle == NULL) {
        timerHandle = CreateWaitableTimerExW(NULL, NULL, 0, TIMER_ALL_ACCESS);
    }
    if (!ringEvent || !wakeEvent || !stopEvent || !spaceEvent || !timerHandle) {
        snprintf(err, errSize, "Failed to create engine events (%lu)", GetLastError());
        engineStop();
        return 0;
    }
    startTimePeriod(); // 1 ms scheduler granularity as a fallback for the waits

    engineState = 1;
    processThread = CreateThread(NULL, 0, processLoop, NULL, 0, NULL);
    if (processThread == NULL) {
        snprintf(err, errSize, "Failed to create processor thread (%lu)", GetLastError());
        engineStop();
        return 0;
    }
    SetThreadPriority(processThread, THREAD_PRIORITY_HIGHEST);
    captureThread = CreateThread(NULL, 0, captureLoop, NULL, 0, NULL);
    if (captureThread == NULL) {
        snprintf(err, errSize, "Failed to create capture thread (%lu)", GetLastError());
        engineStop();
        return 0;
    }
    SetThreadPriority(captureThread, THREAD_PRIORITY_ABOVE_NORMAL);
    heartbeatUs = clockNowUs();
    watchdogThread = CreateThread(NULL, 0, watchdogLoop, NULL, 0, NULL);
    LOG("engine started, high resolution timer: %d", highResTimer);
    return 1;
}

void engineStop(void) {
    if (engineState == 0 && divertHandle == INVALID_HANDLE_VALUE) {
        return;
    }
    engineState = 2;
    if (procflowRunning()) {
        procflowStop();
    }
    // stop receiving; the kernel queue drains into the capture thread, which then exits
    if (divertHandle != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(divertHandle, WINDIVERT_SHUTDOWN_RECV);
    }
    if (captureThread) {
        if (spaceEvent) SetEvent(spaceEvent);
        if (WaitForSingleObject(captureThread, 5000) != WAIT_OBJECT_0) {
            LOG("capture thread did not exit in time");
        }
        CloseHandle(captureThread);
        captureThread = NULL;
    }
    if (processThread) {
        SetEvent(stopEvent);
        WaitForSingleObject(processThread, INFINITE);
        CloseHandle(processThread);
        processThread = NULL;
    } else {
        // threads never started: free anything already queued
        PacketNode *n;
        while ((n = ringPop()) != NULL) packetFree(n);
        listFreeAll(&passList);
    }
    if (divertHandle != INVALID_HANDLE_VALUE) {
        WinDivertClose(divertHandle);
        divertHandle = INVALID_HANDLE_VALUE;
    }
    if (watchdogThread) {
        WaitForSingleObject(watchdogThread, 2000);
        CloseHandle(watchdogThread);
        watchdogThread = NULL;
    }
    if (ringEvent) { CloseHandle(ringEvent); ringEvent = NULL; }
    if (wakeEvent) { CloseHandle(wakeEvent); wakeEvent = NULL; }
    if (stopEvent) { CloseHandle(stopEvent); stopEvent = NULL; }
    if (spaceEvent) { CloseHandle(spaceEvent); spaceEvent = NULL; }
    if (timerHandle) { CloseHandle(timerHandle); timerHandle = NULL; }
    endTimePeriod();
    engineState = 0;
    LOG("engine stopped");
}
