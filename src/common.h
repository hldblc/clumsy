// Shared declarations for the whole program.
#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include "windivert.h"
#include "atomics.h"
#include "clock.h"
#include "packet.h"
#include "module.h"
#include "rng.h"

#define CLUMSY_VERSION "0.4-dev"
#define MSG_BUFSIZE 512
#define FILTER_BUFSIZE 1024
#define NAME_SIZE 16

// stringize an integer macro
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// ---- logging (utils.c) ----
extern int logEnabled;
void logInit(const char *path);     // append to a file; enables logging
void logShutdown(void);
void clumsyLog(const char *func, const char *fmt, ...);
#define LOG(fmt, ...) do { if (logEnabled) clumsyLog(__FUNCTION__, fmt, ##__VA_ARGS__); } while (0)

#ifdef _DEBUG
#define ABORT() assert(0)
#else
#define ABORT() ((void)0)
#endif

// ---- timer resolution (utils.c) ----
#define TIMER_RESOLUTION 1
void startTimePeriod(void);
void endTimePeriod(void);

// ---- misc ----
extern const unsigned char icon8x8[8 * 8];
int strieq(const char *a, const char *b);

// elevate.c
BOOL IsElevated(void);
BOOL IsRunAsAdmin(void);
BOOL tryElevate(HWND hWnd, BOOL silent);

// legacy "--key value" arguments stored as IUP globals (main.c)
extern BOOL parameterized;
BOOL parseArgs(int argc, char *argv[]);
