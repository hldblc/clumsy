#include <stdlib.h>
#include <ctype.h>
#include <Windows.h>
#include "common.h"

// ---- logging ----
#ifdef _DEBUG
int logEnabled = 1;
#else
int logEnabled = 0;
#endif
static FILE *logFile = NULL;
static CRITICAL_SECTION logLock;
static volatile LONG logLockReady = 0;

static void logEnsureLock(void) {
    if (InterlockedCompareExchange(&logLockReady, 1, 0) == 0) {
        InitializeCriticalSection(&logLock);
        InterlockedExchange(&logLockReady, 2);
    }
    while (logLockReady != 2) {
        SwitchToThread();
    }
}

void logInit(const char *path) {
    logEnsureLock();
    EnterCriticalSection(&logLock);
    if (logFile) {
        fclose(logFile);
        logFile = NULL;
    }
    if (path && *path) {
        logFile = fopen(path, "a");
    }
    LeaveCriticalSection(&logLock);
    logEnabled = 1;
}

void logShutdown(void) {
    if (logLockReady != 2) return;
    EnterCriticalSection(&logLock);
    if (logFile) {
        fclose(logFile);
        logFile = NULL;
    }
    LeaveCriticalSection(&logLock);
}

void clumsyLog(const char *func, const char *fmt, ...) {
    char buf[1024];
    int n;
    va_list args;
    SYSTEMTIME st;
    GetLocalTime(&st);
    n = snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d %s: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, func);
    if (n < 0 || n >= (int)sizeof(buf)) n = (int)sizeof(buf) - 1;
    va_start(args, fmt);
    vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, args);
    va_end(args);
    logEnsureLock();
    EnterCriticalSection(&logLock);
    if (logFile) {
        fputs(buf, logFile);
        fputc('\n', logFile);
        fflush(logFile);
    }
#ifdef _DEBUG
    printf("%s\n", buf);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
#endif
    LeaveCriticalSection(&logLock);
}

// ---- timer resolution ----
static short resolutionSet = 0;

void startTimePeriod(void) {
    if (!resolutionSet) {
        timeBeginPeriod(TIMER_RESOLUTION);
        resolutionSet = 1;
    }
}

void endTimePeriod(void) {
    if (resolutionSet) {
        timeEndPeriod(TIMER_RESOLUTION);
        resolutionSet = 0;
    }
}

int strieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

// indicator icon, generated from scripts/im2carr.py
const unsigned char icon8x8[8 * 8] = {
    0, 0, 1, 1, 1, 1, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    0, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0,
};
