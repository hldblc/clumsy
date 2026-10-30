#include "pcap.h"
#include <stdlib.h>
#include <string.h>

#define LINKTYPE_RAW 101
#define SNAPLEN 262144

static void put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v); p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}
static void put16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v); p[1] = (unsigned char)(v >> 8);
}
static size_t pad4(size_t n) { return (n + 3u) & ~(size_t)3u; }

// Section Header Block + Interface Description Block
size_t pcapBuildHeaders(unsigned char *out, size_t cap) {
    size_t need = 28 + 20;
    unsigned char *p;
    if (cap < need) return 0;
    p = out;
    // SHB
    put32(p + 0, 0x0A0D0D0A);     // block type
    put32(p + 4, 28);             // total length
    put32(p + 8, 0x1A2B3C4D);     // byte-order magic
    put16(p + 12, 1);             // major
    put16(p + 14, 0);             // minor
    put32(p + 16, 0xFFFFFFFF);    // section length (unknown), low
    put32(p + 20, 0xFFFFFFFF);    // section length, high
    put32(p + 24, 28);            // total length (trailer)
    p += 28;
    // IDB
    put32(p + 0, 0x00000001);     // block type
    put32(p + 4, 20);             // total length
    put16(p + 8, LINKTYPE_RAW);   // link type
    put16(p + 10, 0);             // reserved
    put32(p + 12, SNAPLEN);       // snap length
    put32(p + 16, 20);            // total length (trailer)
    return need;
}

// Enhanced Packet Block with an opt_comment option
size_t pcapBuildPacketBlock(unsigned char *out, size_t cap, const unsigned char *pkt,
                            UINT len, int64_t tsUs, const char *comment) {
    size_t capLen = len;
    size_t dataPad = pad4(capLen);
    size_t commentLen = comment ? strlen(comment) : 0;
    size_t optLen = 0;
    size_t total;
    unsigned char *p;
    uint64_t ts = (uint64_t)tsUs;
    if (commentLen > 0) {
        optLen = 4 + pad4(commentLen) + 4; // opt_comment header+value + opt_endofopt
    }
    total = 32 + dataPad + optLen;
    if (cap < total) return 0;
    p = out;
    put32(p + 0, 0x00000006);               // EPB block type
    put32(p + 4, (uint32_t)total);          // total length
    put32(p + 8, 0);                         // interface id
    put32(p + 12, (uint32_t)(ts >> 32));     // timestamp high
    put32(p + 16, (uint32_t)(ts & 0xFFFFFFFF)); // timestamp low
    put32(p + 20, (uint32_t)capLen);         // captured length
    put32(p + 24, len);                      // original length
    memcpy(p + 28, pkt, capLen);
    memset(p + 28 + capLen, 0, dataPad - capLen);
    p += 28 + dataPad;
    if (commentLen > 0) {
        put16(p + 0, 1);                     // opt_comment
        put16(p + 2, (uint16_t)commentLen);
        memcpy(p + 4, comment, commentLen);
        memset(p + 4 + commentLen, 0, pad4(commentLen) - commentLen);
        p += 4 + pad4(commentLen);
        put16(p + 0, 0);                     // opt_endofopt
        put16(p + 2, 0);
        p += 4;
    }
    put32(p, (uint32_t)total);               // block total length (trailer)
    return total;
}

void pcapActionComment(char *buf, size_t size, const char *ruleName, uint16_t flags, int outbound) {
    int n = snprintf(buf, size, "%s %s", outbound ? "out" : "in", ruleName ? ruleName : "-");
#define ADD(bit, label) do { if ((flags & (bit)) && n < (int)size) n += snprintf(buf + n, size - n, " %s", label); } while (0)
    ADD(PN_FLAG_LAGGED, "lagged");
    ADD(PN_FLAG_THROTTLED, "throttled");
    ADD(PN_FLAG_REORDERED, "reordered");
    ADD(PN_FLAG_DUPLICATE, "duplicate");
    ADD(PN_FLAG_TAMPERED, "tampered");
    ADD(PN_FLAG_RST, "rst");
    ADD(PN_FLAG_TCPMOD, "tcp-mod");
    ADD(PN_FLAG_SHAPED, "shaped");
    ADD(PN_FLAG_FRAGMENT, "fragment");
    ADD(PN_FLAG_INJECTED, "injected");
#undef ADD
}

// ---- live writer ----
static FILE *pcapFile = NULL;
static CRITICAL_SECTION pcapLock;
static int pcapLockReady = 0;
static unsigned char pcapScratch[SNAPLEN + 512];

int pcapOpen(const char *path) {
    unsigned char hdr[64];
    size_t n;
    if (!pcapLockReady) { InitializeCriticalSection(&pcapLock); pcapLockReady = 1; }
    EnterCriticalSection(&pcapLock);
    if (pcapFile) { fclose(pcapFile); pcapFile = NULL; }
    pcapFile = fopen(path, "wb");
    if (pcapFile) {
        n = pcapBuildHeaders(hdr, sizeof(hdr));
        fwrite(hdr, 1, n, pcapFile);
        fflush(pcapFile);
    }
    LeaveCriticalSection(&pcapLock);
    return pcapFile != NULL;
}

void pcapClose(void) {
    if (!pcapLockReady) return;
    EnterCriticalSection(&pcapLock);
    if (pcapFile) { fclose(pcapFile); pcapFile = NULL; }
    LeaveCriticalSection(&pcapLock);
}

int pcapIsOpen(void) {
    return pcapFile != NULL;
}

static int64_t nowUnixUs(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // FILETIME is 100 ns ticks since 1601; convert to us since 1970
    return (int64_t)(u.QuadPart / 10ULL) - 11644473600000000LL;
}

void pcapLogNode(const PacketNode *n, const char *ruleName) {
    char comment[160];
    size_t sz;
    if (pcapFile == NULL || n->packetLen > SNAPLEN) return;
    pcapActionComment(comment, sizeof(comment), ruleName, n->flags, n->addr.Outbound);
    EnterCriticalSection(&pcapLock);
    if (pcapFile) {
        sz = pcapBuildPacketBlock(pcapScratch, sizeof(pcapScratch),
                                  (const unsigned char *)n->packet, n->packetLen, nowUnixUs(), comment);
        if (sz) fwrite(pcapScratch, 1, sz, pcapFile);
    }
    LeaveCriticalSection(&pcapLock);
}
