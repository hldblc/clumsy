#include "procflow.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

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

static void sockRefresh(int64_t now);   // defined with the socket-table fallback below

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
    sockRefresh(clockNowUs());    // prime with the sockets that already exist
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

// ---- fallback: sockets that already existed when we started ----
// The FLOW layer only reports connections created after its handle opened, so
// a game that was already connected would never be found there. The IP helper
// tables list every UDP/TCP socket with its owning pid, keyed by local address
// and port. Refreshed lazily on a miss, at most once a second, on the
// processor thread only (so no lock is needed for this table).
typedef struct {
    uint32_t addr;     // network order, 0 = bound to any address
    uint16_t port;     // network order
    uint8_t proto;
    uint8_t used;
    uint32_t pid;
} SockEntry;

#define SOCK_TABLE 4096
static SockEntry sockTable[SOCK_TABLE];
static int64_t sockRefreshedUs = 0;
#define SOCK_REFRESH_US 1000000LL

static uint32_t sockHash(uint8_t proto, uint32_t addr, uint16_t port) {
    uint32_t h = addr * 2654435761u;
    h ^= (uint32_t)port * 40503u;
    h ^= (uint32_t)proto * 97u;
    return h;
}

static void sockPut(uint8_t proto, uint32_t addr, uint16_t port, uint32_t pid) {
    uint32_t h = sockHash(proto, addr, port);
    int i;
    for (i = 0; i < 32; ++i) {
        SockEntry *e = &sockTable[(h + i) & (SOCK_TABLE - 1)];
        if (!e->used || (e->proto == proto && e->addr == addr && e->port == port)) {
            e->proto = proto; e->addr = addr; e->port = port; e->pid = pid; e->used = 1;
            return;
        }
    }
}

static uint32_t sockGet(uint8_t proto, uint32_t addr, uint16_t port) {
    uint32_t h = sockHash(proto, addr, port);
    int i;
    for (i = 0; i < 32; ++i) {
        SockEntry *e = &sockTable[(h + i) & (SOCK_TABLE - 1)];
        if (!e->used) return 0;
        if (e->proto == proto && e->addr == addr && e->port == port) return e->pid;
    }
    return 0;
}

static void sockRefresh(int64_t now) {
    DWORD size = 0;
    void *buf;
    memset(sockTable, 0, sizeof(sockTable));
    // UDP sockets
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER && size > 0) {
        buf = malloc(size);
        if (buf && GetExtendedUdpTable(buf, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            MIB_UDPTABLE_OWNER_PID *t = (MIB_UDPTABLE_OWNER_PID *)buf;
            DWORD i;
            for (i = 0; i < t->dwNumEntries; ++i) {
                sockPut(17, t->table[i].dwLocalAddr, (uint16_t)t->table[i].dwLocalPort, t->table[i].dwOwningPid);
            }
        }
        free(buf);
    }
    // TCP connections and listeners
    size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER && size > 0) {
        buf = malloc(size);
        if (buf && GetExtendedTcpTable(buf, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)buf;
            DWORD i;
            for (i = 0; i < t->dwNumEntries; ++i) {
                sockPut(6, t->table[i].dwLocalAddr, (uint16_t)t->table[i].dwLocalPort, t->table[i].dwOwningPid);
            }
        }
        free(buf);
    }
    sockRefreshedUs = now;
}

// raw (non-canonical) endpoints of an IPv4 packet, read alignment-safely
static int parseV4Endpoints(const void *packet, UINT len, uint8_t *proto,
                            uint32_t *src, uint16_t *sp, uint32_t *dst, uint16_t *dp) {
    PWINDIVERT_IPHDR ip = NULL;
    PWINDIVERT_TCPHDR tcp = NULL;
    PWINDIVERT_UDPHDR udp = NULL;
    const unsigned char *h;
    WinDivertHelperParsePacket(packet, len, &ip, NULL, proto, NULL, NULL, &tcp, &udp, NULL, NULL, NULL, NULL);
    if (ip == NULL) return 0;
    h = (const unsigned char *)ip;
    memcpy(src, h + offsetof(WINDIVERT_IPHDR, SrcAddr), 4);
    memcpy(dst, h + offsetof(WINDIVERT_IPHDR, DstAddr), 4);
    *sp = *dp = 0;
    if (tcp) {
        h = (const unsigned char *)tcp;
        memcpy(sp, h + offsetof(WINDIVERT_TCPHDR, SrcPort), 2);
        memcpy(dp, h + offsetof(WINDIVERT_TCPHDR, DstPort), 2);
        *proto = 6;
    } else if (udp) {
        h = (const unsigned char *)udp;
        memcpy(sp, h + offsetof(WINDIVERT_UDPHDR, SrcPort), 2);
        memcpy(dp, h + offsetof(WINDIVERT_UDPHDR, DstPort), 2);
        *proto = 17;
    } else {
        return 0;
    }
    return 1;
}

uint32_t procflowLookup(const void *packet, UINT len, int outbound) {
    FlowKey k;
    uint32_t pid;
    uint8_t proto;
    uint32_t src, dst, local;
    uint16_t sp, dp, lport;
    int64_t now;
    if (flowState != 1 || !flowKeyFromPacket(&k, packet, len)) return 0;
    EnterCriticalSection(&lock);
    pid = flowTableGet(&table, &k);
    LeaveCriticalSection(&lock);
    if (pid) return pid;

    // not learned from the flow layer: look the local endpoint up in the OS tables
    if (!parseV4Endpoints(packet, len, &proto, &src, &sp, &dst, &dp)) return 0;
    local = outbound ? src : dst;
    lport = outbound ? sp : dp;
    now = clockNowUs();
    if (now - sockRefreshedUs > SOCK_REFRESH_US) {
        sockRefresh(now);
    }
    pid = sockGet(proto, local, lport);
    if (pid == 0) pid = sockGet(proto, 0, lport);          // socket bound to any address
    if (pid) {
        // remember it so later packets of this connection are a fast hit
        EnterCriticalSection(&lock);
        flowTableSet(&table, &k, pid, now);
        LeaveCriticalSection(&lock);
    }
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
