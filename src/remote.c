#include "remote.h"
#include "rules.h"
#include "engine.h"
#include "profiles.h"
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

static SOCKET listenSock = INVALID_SOCKET;
static HANDLE serverThread = NULL;
static volatile LONG running = 0;
static int boundPort = 0;
static char tokenBuf[128];
static void (*enqueueCmd)(const char *cmd) = NULL;

int remoteRunning(void) { return running == 1; }
int remotePort(void) { return boundPort; }
const char *remoteToken(void) { return tokenBuf; }

// ---- JSON builders (safe reads of shared state) ----
static int jsonEscape(char *out, size_t size, const char *in) {
    size_t n = 0;
    for (; *in && n + 2 < size; ++in) {
        if (*in == '"' || *in == '\\') { out[n++] = '\\'; out[n++] = *in; }
        else if (*in == '\n') { out[n++] = '\\'; out[n++] = 'n'; }
        else out[n++] = *in;
    }
    out[n] = 0;
    return (int)n;
}

int remoteBuildStatus(char *buf, size_t size) {
    LONG64 cap = atomicLoad64(&engineStats.captured);
    LONG64 sent = atomicLoad64(&engineStats.sent);
    LONG64 pass = atomicLoad64(&engineStats.passthrough);
    LONG64 sfail = atomicLoad64(&engineStats.sendFailed);
    LONG64 lsum = atomicLoad64(&engineStats.latencySumUs);
    LONG64 lcnt = atomicLoad64(&engineStats.latencySamples);
    LONG64 dropped = 0;
    double avg = lcnt ? (double)lsum / (double)lcnt / 1000.0 : 0.0;
    int i, j;
    for (i = 0; i < ruleSet.count; ++i)
        for (j = 0; j < ruleSet.rules[i]->moduleCount; ++j)
            dropped += atomicLoad64(&ruleSet.rules[i]->modules[j]->stats.dropped);
    return snprintf(buf, size,
        "{\"running\":%s,\"highResTimer\":%s,\"captured\":%lld,\"sent\":%lld,"
        "\"dropped\":%lld,\"passthrough\":%lld,\"sendFailed\":%lld,"
        "\"avgLatencyMs\":%.2f,\"ruleCount\":%d}",
        engineIsRunning() ? "true" : "false",
        engineHighResolutionTimer() ? "true" : "false",
        cap, sent, dropped, pass, sfail, avg, ruleSet.count);
}

int remoteBuildRules(char *buf, size_t size) {
    size_t used = 0;
    int i, j, k;
    char esc[FILTER_BUFSIZE + 16];
#define EMIT(...) do { int w = snprintf(buf + used, size - used, __VA_ARGS__); if (w < 0 || (size_t)w >= size - used) return -1; used += (size_t)w; } while (0)
    EMIT("[");
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        EMIT("%s{\"index\":%d,\"name\":\"", i ? "," : "", r->index);
        jsonEscape(esc, sizeof(esc), r->name); EMIT("%s", esc);
        EMIT("\",\"filter\":\""); jsonEscape(esc, sizeof(esc), r->filter); EMIT("%s", esc);
        EMIT("\",\"process\":\""); jsonEscape(esc, sizeof(esc), r->process); EMIT("%s", esc);
        EMIT("\",\"enabled\":%s,\"matched\":%lld,\"modules\":[", r->enabled ? "true" : "false",
             (long long)atomicLoad64(&r->matched));
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            EMIT("%s{\"name\":\"%s\",\"enabled\":%s,\"stats\":{\"packets\":%lld,\"dropped\":%lld,\"queued\":%ld},\"params\":{",
                 j ? "," : "", m->desc->shortName, m->enabled ? "true" : "false",
                 (long long)atomicLoad64(&m->stats.packets), (long long)atomicLoad64(&m->stats.dropped),
                 (long)atomicLoad32(&m->stats.queued));
            for (k = 0; k < m->desc->paramCount; ++k) {
                char val[48];
                if (m->desc->params[k].flags & PF_HIDDEN) continue;
                moduleGetParamText(m, m->desc->params[k].name, val, sizeof(val));
                EMIT("%s\"%s\":\"%s\"", k ? "," : "", m->desc->params[k].name, val);
            }
            EMIT("}}");
        }
        EMIT("]}");
    }
    EMIT("]");
#undef OUT
    return (int)used;
}

// ---- apply a command (UI thread) ----
// grammar: "set <rule> <module> <param> <value>" | "enable <rule> <module> <0|1>"
//          | "profile <name...>"
void remoteApplyCommand(const char *cmd) {
    char line[256];
    char *verb, *save = NULL;
    snprintf(line, sizeof(line), "%s", cmd);
    verb = strtok_s(line, " \t", &save);
    if (verb == NULL) return;
    if (strieq(verb, "set") || strieq(verb, "enable")) {
        char *sr = strtok_s(NULL, " \t", &save);
        char *sm = strtok_s(NULL, " \t", &save);
        char *rest = strtok_s(NULL, "", &save);
        int ri;
        Rule *r;
        ModuleInst *m;
        if (!sr || !sm || !rest) return;
        ri = atoi(sr);
        if (ri < 0 || ri >= ruleSet.count) return;
        r = ruleSet.rules[ri];
        m = ruleFindModule(r, sm);
        if (m == NULL) return;
        if (strieq(verb, "enable")) {
            moduleSetEnabled(m, atoi(rest) != 0);
        } else {
            char *param = rest;
            char *value = strchr(rest, ' ');
            if (value == NULL) return;
            *value++ = 0;
            while (*value == ' ') ++value;
            moduleSetParamText(m, param, value);
        }
        engineWake();
    } else if (strieq(verb, "profile")) {
        char *name = strtok_s(NULL, "", &save);
        int p;
        if (name == NULL || ruleSet.count == 0) return;
        for (p = 0; p < profileCount(); ++p) {
            if (strieq(profileName(p), name)) {
                configApplyFragment(ruleSet.rules[0], profileText(p));
                engineWake();
                break;
            }
        }
    }
}

// ---- tiny HTTP server ----
static void sendResponse(SOCKET c, const char *status, const char *ctype, const char *body) {
    char head[256];
    int n = snprintf(head, sizeof(head),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        status, ctype, (int)strlen(body));
    send(c, head, n, 0);
    if (*body) send(c, body, (int)strlen(body), 0);
}

// find value of query/header key; returns 1 and fills out
static int getQueryParam(const char *query, const char *key, char *out, size_t size) {
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            size_t n = 0;
            while (*v && *v != '&' && n + 1 < size) {
                if (*v == '%' && v[1] && v[2]) {
                    char hex[3] = { v[1], v[2], 0 };
                    out[n++] = (char)strtol(hex, NULL, 16);
                    v += 3;
                } else if (*v == '+') { out[n++] = ' '; ++v; }
                else out[n++] = *v++;
            }
            out[n] = 0;
            return 1;
        }
        p = strchr(p, '&');
        if (p) ++p;
    }
    return 0;
}

static int authOk(const char *query, const char *headers) {
    char got[128];
    const char *h;
    if (tokenBuf[0] == 0) return 1;   // no token set: allow (loopback only)
    if (getQueryParam(query, "token", got, sizeof(got)) && strcmp(got, tokenBuf) == 0) return 1;
    h = strstr(headers, "Authorization: Bearer ");
    if (h && strncmp(h + 22, tokenBuf, strlen(tokenBuf)) == 0) return 1;
    h = strstr(headers, "X-Clumsy-Token: ");
    if (h && strncmp(h + 16, tokenBuf, strlen(tokenBuf)) == 0) return 1;
    return 0;
}

static void handleConn(SOCKET c) {
    char req[4096];
    int total = 0, n;
    char method[8], path[256], *query, *sp, *q;
    static char body[CONFIG_TEXT_MAX];
    while (total < (int)sizeof(req) - 1) {
        n = recv(c, req + total, (int)sizeof(req) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        req[total] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    if (total <= 0) return;
    req[total] = 0;

    // parse request line
    sp = strchr(req, ' ');
    if (!sp) { sendResponse(c, "400 Bad Request", "text/plain", "bad request"); return; }
    *sp = 0;
    snprintf(method, sizeof(method), "%s", req);
    q = sp + 1;
    sp = strchr(q, ' ');
    if (sp) *sp = 0;
    snprintf(path, sizeof(path), "%s", q);
    query = strchr(path, '?');
    if (query) *query++ = 0; else query = "";

    if (!authOk(query, sp ? sp + 1 : "")) {
        sendResponse(c, "401 Unauthorized", "application/json", "{\"error\":\"bad or missing token\"}");
        return;
    }

    if (strieq(method, "GET") && strcmp(path, "/status") == 0) {
        remoteBuildStatus(body, sizeof(body));
        sendResponse(c, "200 OK", "application/json", body);
    } else if (strieq(method, "GET") && strcmp(path, "/rules") == 0) {
        if (remoteBuildRules(body, sizeof(body)) < 0) snprintf(body, sizeof(body), "[]");
        sendResponse(c, "200 OK", "application/json", body);
    } else if (strcmp(path, "/start") == 0) {
        if (enqueueCmd) enqueueCmd("start");
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/stop") == 0) {
        if (enqueueCmd) enqueueCmd("stop");
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/profile") == 0) {
        char name[64], cmd[128];
        if (getQueryParam(query, "name", name, sizeof(name)) && enqueueCmd) {
            snprintf(cmd, sizeof(cmd), "profile %s", name);
            enqueueCmd(cmd);
        }
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/set") == 0) {
        char r[8], m[32], p[32], v[48], cmd[160];
        if (getQueryParam(query, "rule", r, sizeof(r)) && getQueryParam(query, "module", m, sizeof(m))
            && getQueryParam(query, "param", p, sizeof(p)) && getQueryParam(query, "value", v, sizeof(v))
            && enqueueCmd) {
            snprintf(cmd, sizeof(cmd), "set %s %s %s %s", r, m, p, v);
            enqueueCmd(cmd);
        }
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/filter") == 0) {
        char r[8] = "0", v[FILTER_BUFSIZE], cmd[FILTER_BUFSIZE + 32];
        getQueryParam(query, "rule", r, sizeof(r));
        if (getQueryParam(query, "value", v, sizeof(v)) && enqueueCmd) {
            snprintf(cmd, sizeof(cmd), "filter %s %s", r, v);
            enqueueCmd(cmd);
        }
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/process") == 0) {
        char r[8] = "0", v[128], cmd[160];
        getQueryParam(query, "rule", r, sizeof(r));
        getQueryParam(query, "value", v, sizeof(v));   // empty clears the scope
        if (enqueueCmd) {
            snprintf(cmd, sizeof(cmd), "process %s %s", r, v);
            enqueueCmd(cmd);
        }
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/enable") == 0) {
        char r[8], m[32], on[8], cmd[96];
        if (getQueryParam(query, "rule", r, sizeof(r)) && getQueryParam(query, "module", m, sizeof(m))
            && getQueryParam(query, "on", on, sizeof(on)) && enqueueCmd) {
            snprintf(cmd, sizeof(cmd), "enable %s %s %s", r, m, on);
            enqueueCmd(cmd);
        }
        sendResponse(c, "202 Accepted", "application/json", "{\"ok\":true}");
    } else {
        sendResponse(c, "404 Not Found", "application/json", "{\"error\":\"unknown endpoint\"}");
    }
}

static DWORD WINAPI serverLoop(LPVOID arg) {
    UNREFERENCED_PARAMETER(arg);
    while (running == 1) {
        SOCKET c = accept(listenSock, NULL, NULL);
        if (c == INVALID_SOCKET) {
            if (running != 1) break;
            continue;
        }
        handleConn(c);
        closesocket(c);
    }
    return 0;
}

int remoteStart(int port, const char *token, void (*enqueue)(const char *cmd), char *err, size_t errSize) {
    WSADATA wsa;
    struct sockaddr_in addr;
    if (running == 1) return 1;
    enqueueCmd = enqueue;
    snprintf(tokenBuf, sizeof(tokenBuf), "%s", token ? token : "");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        snprintf(err, errSize, "WSAStartup failed");
        return 0;
    }
    listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        snprintf(err, errSize, "socket failed (%d)", WSAGetLastError());
        WSACleanup();
        return 0;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1 only
    if (bind(listenSock, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listenSock, 4) != 0) {
        snprintf(err, errSize, "cannot bind 127.0.0.1:%d (%d)", port, WSAGetLastError());
        closesocket(listenSock);
        listenSock = INVALID_SOCKET;
        WSACleanup();
        return 0;
    }
    boundPort = port;
    running = 1;
    serverThread = CreateThread(NULL, 0, serverLoop, NULL, 0, NULL);
    if (serverThread == NULL) {
        snprintf(err, errSize, "cannot start the API thread");
        remoteStop();
        return 0;
    }
    return 1;
}

void remoteStop(void) {
    running = 0;
    if (listenSock != INVALID_SOCKET) {
        closesocket(listenSock);   // unblocks accept()
        listenSock = INVALID_SOCKET;
    }
    if (serverThread) {
        WaitForSingleObject(serverThread, 2000);
        CloseHandle(serverThread);
        serverThread = NULL;
    }
    WSACleanup();
    boundPort = 0;
}
