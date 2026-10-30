#include "procflow.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ---- 5-tuple key ----
static int endpointLess(const uint32_t a[4], uint16_t pa, const uint32_t b[4], uint16_t pb) {
    int c = memcmp(a, b, 16);
    if (c != 0) return c < 0;
    return pa < pb;
}

void flowKeyFromEndpoints(FlowKey *k, uint8_t proto,
                          const uint32_t localAddr[4], uint16_t localPort,
                          const uint32_t remoteAddr[4], uint16_t remotePort) {
    memset(k, 0, sizeof(*k));
    k->proto = proto;
    if (endpointLess(localAddr, localPort, remoteAddr, remotePort)) {
        memcpy(k->addrA, localAddr, 16);  k->portA = localPort;
        memcpy(k->addrB, remoteAddr, 16); k->portB = remotePort;
    } else {
        memcpy(k->addrA, remoteAddr, 16); k->portA = remotePort;
        memcpy(k->addrB, localAddr, 16);  k->portB = localPort;
    }
}

int flowKeyFromPacket(FlowKey *k, const void *packet, UINT len) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_IPV6HDR ip6 = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    UINT8 proto = 0;
    uint32_t src[4] = { 0, 0, 0, 0 }, dst[4] = { 0, 0, 0, 0 };
    uint16_t sp = 0, dp = 0;
    WinDivertHelperParsePacket(packet, len, &ip, &ip6, &proto, NULL, NULL, &tcp, &udp, NULL, NULL, NULL, NULL);
    if (ip) {
        src[0] = ip->SrcAddr; dst[0] = ip->DstAddr;
    } else if (ip6) {
        memcpy(src, ip6->SrcAddr, 16); memcpy(dst, ip6->DstAddr, 16);
    } else {
        return 0;
    }
    if (tcp) { sp = tcp->SrcPort; dp = tcp->DstPort; proto = 6; }
    else if (udp) { sp = udp->SrcPort; dp = udp->DstPort; proto = 17; }
    flowKeyFromEndpoints(k, proto, src, sp, dst, dp);
    return 1;
}

int flowKeyEqual(const FlowKey *a, const FlowKey *b) {
    return a->proto == b->proto && a->portA == b->portA && a->portB == b->portB
        && memcmp(a->addrA, b->addrA, 16) == 0 && memcmp(a->addrB, b->addrB, 16) == 0;
}

uint64_t flowKeyHash(const FlowKey *k) {
    uint64_t h = 14695981039346656037ULL;
    const unsigned char *p = (const unsigned char *)k;
    size_t i;
    for (i = 0; i < sizeof(FlowKey); ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// ---- open addressed table ----
void flowTableInit(FlowTable *t, int capacity) {
    int cap = 16;
    while (cap < capacity) cap <<= 1;
    t->capacity = cap;
    t->slots = (FlowEntry *)calloc((size_t)cap, sizeof(FlowEntry));
}

void flowTableFree(FlowTable *t) {
    free(t->slots);
    t->slots = NULL;
    t->capacity = 0;
}

static int findSlot(FlowTable *t, const FlowKey *k, int forInsert, int64_t now) {
    uint64_t h = flowKeyHash(k);
    int mask = t->capacity - 1;
    int start = (int)(h & mask);
    int i, firstFree = -1;
    for (i = 0; i < t->capacity; ++i) {
        int s = (start + i) & mask;
        FlowEntry *e = &t->slots[s];
        if (e->used && flowKeyEqual(&e->key, k)) return s;
        if (!e->used) {
            if (firstFree < 0) firstFree = s;
            if (!forInsert) return -1;      // not present
            break;                          // insert: first free in the probe run
        }
    }
    if (forInsert && firstFree < 0) {
        // table full: evict the oldest entry we can find
        int oldest = start;
        int64_t oldestTs = t->slots[start].lastSeen;
        for (i = 1; i < t->capacity; ++i) {
            int s = (start + i) & mask;
            if (t->slots[s].lastSeen < oldestTs) { oldestTs = t->slots[s].lastSeen; oldest = s; }
        }
        firstFree = oldest;
        UNREFERENCED_PARAMETER(now);
    }
    return firstFree;
}

void flowTableSet(FlowTable *t, const FlowKey *k, uint32_t pid, int64_t now) {
    int s;
    if (t->slots == NULL) return;
    s = findSlot(t, k, 1, now);
    if (s < 0) return;
    t->slots[s].key = *k;
    t->slots[s].pid = pid;
    t->slots[s].used = 1;
    t->slots[s].lastSeen = now;
}

uint32_t flowTableGet(FlowTable *t, const FlowKey *k) {
    int s;
    if (t->slots == NULL) return 0;
    s = findSlot(t, k, 0, 0);
    return s >= 0 ? t->slots[s].pid : 0;
}

void flowTableDel(FlowTable *t, const FlowKey *k) {
    int s;
    if (t->slots == NULL) return;
    s = findSlot(t, k, 0, 0);
    if (s >= 0) t->slots[s].used = 0;
}

int flowTableCount(const FlowTable *t) {
    int i, n = 0;
    for (i = 0; i < t->capacity; ++i) if (t->slots[i].used) ++n;
    return n;
}

// ---- name matching ----
static const char *baseName(const char *path) {
    const char *b = path, *p;
    for (p = path; *p; ++p) if (*p == '\\' || *p == '/') b = p + 1;
    return b;
}

int processNameMatch(const char *filter, const char *exePath) {
    const char *base;
    size_t fl, bl;
    if (filter == NULL || *filter == 0 || exePath == NULL) return 0;
    base = baseName(exePath);
    fl = strlen(filter);
    bl = strlen(base);
    if (bl == fl && strieq(base, filter)) return 1;
    // allow the filter to omit a trailing .exe
    if (bl == fl + 4) {
        char withExe[128];
        if (fl + 5 <= sizeof(withExe)) {
            snprintf(withExe, sizeof(withExe), "%s.exe", filter);
            if (strieq(base, withExe)) return 1;
        }
    }
    return 0;
}

// ---- live subsystem ----
#define PROCFLOW_FLOWS 8192
#define NAME_CACHE 256
#define NAME_TTL_US 5000000LL

typedef struct {
    uint32_t pid;
    char name[64];
    int64_t at;
    uint8_t used;
} NameEntry;

static HANDLE flowHandle = INVALID_HANDLE_VALUE;
static HANDLE flowThread = NULL;
static volatile LONG flowState = 0;   // 0 stopped, 1 running
static FlowTable table;
static CRITICAL_SECTION lock;
static int lockReady = 0;
static NameEntry nameCache[NAME_CACHE];

int procflowRunning(void) {
    return flowState == 1;
}

static DWORD WINAPI flowLoop(LPVOID arg) {
    WINDIVERT_ADDRESS addr;
    UINT addrLen;
    UNREFERENCED_PARAMETER(arg);
    for (;;) {
        addrLen = sizeof(addr);
        if (!WinDivertRecvEx(flowHandle, NULL, 0, NULL, 0, &addr, &addrLen, NULL)) {
            DWORD e = GetLastError();
            if (e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED || e == 232L) break;
            if (flowState != 1) break;
            continue;
        }
        if (addr.Layer == WINDIVERT_LAYER_FLOW) {
            FlowKey k;
            flowKeyFromEndpoints(&k, addr.Flow.Protocol,
                                 addr.Flow.LocalAddr, WinDivertHelperHtons(addr.Flow.LocalPort),
                                 addr.Flow.RemoteAddr, WinDivertHelperHtons(addr.Flow.RemotePort));
            EnterCriticalSection(&lock);
            if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
                flowTableSet(&table, &k, addr.Flow.ProcessId, clockNowUs());
            } else if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED) {
                flowTableDel(&table, &k);
            }
            LeaveCriticalSection(&lock);
        }
    }
    return 0;
}

int procflowStart(char *err, size_t errSize) {
    if (flowState == 1) return 1;
    if (!lockReady) { InitializeCriticalSection(&lock); lockReady = 1; }
    flowTableInit(&table, PROCFLOW_FLOWS);
    memset(nameCache, 0, sizeof(nameCache));
    // sniff only: we never block or reinject flow events
    flowHandle = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0,
                               WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (flowHandle == INVALID_HANDLE_VALUE) {
        snprintf(err, errSize, "Per-process filtering needs the flow layer; WinDivertOpen failed (%lu).", GetLastError());
        flowTableFree(&table);
        return 0;
    }
    flowState = 1;
    flowThread = CreateThread(NULL, 0, flowLoop, NULL, 0, NULL);
    if (flowThread == NULL) {
        snprintf(err, errSize, "Failed to start the flow thread (%lu).", GetLastError());
        procflowStop();
        return 0;
    }
    return 1;
}

void procflowStop(void) {
    if (flowHandle != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(flowHandle, WINDIVERT_SHUTDOWN_RECV);
    }
    flowState = 0;
    if (flowThread) {
        WaitForSingleObject(flowThread, 3000);
        CloseHandle(flowThread);
        flowThread = NULL;
    }
    if (flowHandle != INVALID_HANDLE_VALUE) {
        WinDivertClose(flowHandle);
        flowHandle = INVALID_HANDLE_VALUE;
    }
    if (lockReady) {
        EnterCriticalSection(&lock);
        flowTableFree(&table);
        LeaveCriticalSection(&lock);
    }
}

uint32_t procflowLookup(const void *packet, UINT len) {
    FlowKey k;
    uint32_t pid;
    if (flowState != 1 || !flowKeyFromPacket(&k, packet, len)) return 0;
    EnterCriticalSection(&lock);
    pid = flowTableGet(&table, &k);
    LeaveCriticalSection(&lock);
    return pid;
}

int procflowName(uint32_t pid, char *buf, size_t size) {
    int slot = (int)(pid % NAME_CACHE);
    int64_t now = clockNowUs();
    NameEntry *e = &nameCache[slot];
    HANDLE h;
    if (pid == 0) return 0;
    if (e->used && e->pid == pid && now - e->at < NAME_TTL_US) {
        snprintf(buf, size, "%s", e->name);
        return 1;
    }
    e->used = 0;
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h != NULL) {
        char path[MAX_PATH];
        DWORD n = sizeof(path);
        if (QueryFullProcessImageNameA(h, 0, path, &n)) {
            const char *b = path, *p;
            for (p = path; *p; ++p) if (*p == '\\' || *p == '/') b = p + 1;
            snprintf(e->name, sizeof(e->name), "%s", b);
            e->pid = pid;
            e->at = now;
            e->used = 1;
        }
        CloseHandle(h);
    }
    if (!e->used) return 0;
    snprintf(buf, size, "%s", e->name);
    return 1;
}
