#include "targets.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define TARGET_MAX_ADDRS 16

static int parseDottedQuad(const char *s, const char *end, uint32_t *out) {
    uint32_t v = 0;
    int parts = 0;
    const char *p = s;
    while (p < end && parts < 4) {
        int n = 0, digits = 0;
        while (p < end && isdigit((unsigned char)*p)) { n = n * 10 + (*p - '0'); ++p; ++digits; }
        if (digits == 0 || n > 255) return 0;
        v = (v << 8) | (uint32_t)n;
        ++parts;
        if (p < end && *p == '.') { ++p; } else break;
    }
    if (parts != 4 || p != end) return 0;
    *out = v;
    return 1;
}

int targetParseCidr(const char *input, uint32_t *lo, uint32_t *hi) {
    const char *slash = strchr(input, '/');
    uint32_t base;
    int bits;
    char *endp;
    if (slash == NULL) return 0;
    if (!parseDottedQuad(input, slash, &base)) return 0;
    bits = (int)strtol(slash + 1, &endp, 10);
    if (*endp != 0 || bits < 0 || bits > 32) return 0;
    if (bits == 0) { *lo = 0; *hi = 0xFFFFFFFFu; return 1; }
    {
        uint32_t mask = (bits == 32) ? 0xFFFFFFFFu : ~((1u << (32 - bits)) - 1u);
        *lo = base & mask;
        *hi = base | ~mask;
    }
    return 1;
}

static void fmtIp(uint32_t a, char *buf, size_t size) {
    snprintf(buf, size, "%u.%u.%u.%u", (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
}

static int looksNumeric(const char *s) {
    for (; *s; ++s) if (!isdigit((unsigned char)*s) && *s != '.' && *s != '/') return 0;
    return 1;
}

int targetBuildClause(const char *input, char *out, size_t outSize) {
    char trimmed[256];
    size_t n = 0;
    const char *p = input;
    uint32_t lo, hi, one;
    while (*p && isspace((unsigned char)*p)) ++p;
    while (*p && n + 1 < sizeof(trimmed)) trimmed[n++] = *p++;
    while (n > 0 && isspace((unsigned char)trimmed[n - 1])) --n;
    trimmed[n] = 0;
    if (n == 0) { snprintf(out, outSize, "empty target"); return 0; }

    // CIDR
    if (strchr(trimmed, '/') != NULL) {
        char a[16], b[16];
        if (!targetParseCidr(trimmed, &lo, &hi)) { snprintf(out, outSize, "bad CIDR: %s", trimmed); return 0; }
        fmtIp(lo, a, sizeof(a));
        fmtIp(hi, b, sizeof(b));
        if ((size_t)snprintf(out, outSize,
                "((ip.DstAddr >= %s and ip.DstAddr <= %s) or (ip.SrcAddr >= %s and ip.SrcAddr <= %s))",
                a, b, a, b) >= outSize) return 0;
        return 1;
    }

    // plain dotted quad
    if (looksNumeric(trimmed) && parseDottedQuad(trimmed, trimmed + strlen(trimmed), &one)) {
        if ((size_t)snprintf(out, outSize, "(ip.DstAddr == %s or ip.SrcAddr == %s)", trimmed, trimmed) >= outSize)
            return 0;
        return 1;
    }

    // hostname: resolve A records
    {
        struct addrinfo hints, *res = NULL, *ai;
        WSADATA wsa;
        int started = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        size_t used = 0;
        int count = 0;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        if (getaddrinfo(trimmed, NULL, &hints, &res) != 0 || res == NULL) {
            if (started) WSACleanup();
            snprintf(out, outSize, "cannot resolve host: %s", trimmed);
            return 0;
        }
        used += (size_t)snprintf(out + used, outSize - used, "(");
        for (ai = res; ai != NULL && count < TARGET_MAX_ADDRS; ai = ai->ai_next) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            uint32_t a = ntohl(sin->sin_addr.s_addr);
            char ip[16];
            int w;
            fmtIp(a, ip, sizeof(ip));
            w = snprintf(out + used, outSize - used, "%sip.DstAddr == %s or ip.SrcAddr == %s",
                         count ? " or " : "", ip, ip);
            if (w < 0 || (size_t)w >= outSize - used) break;
            used += (size_t)w;
            ++count;
        }
        snprintf(out + used, outSize - used, ")");
        freeaddrinfo(res);
        if (started) WSACleanup();
        if (count == 0) { snprintf(out, outSize, "no IPv4 address for: %s", trimmed); return 0; }
        return 1;
    }
}
