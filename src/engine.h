// The packet engine: a capture thread reads batches from WinDivert into a
// lock-free ring, and a processor thread owns every packet list, runs the
// module chains and reinjects. The processor sleeps on a high resolution
// waitable timer armed for the earliest module deadline.
#pragma once
#include "common.h"
#include "rules.h"

typedef struct {
    volatile LONG64 captured, bytesCaptured;
    volatile LONG64 sent, bytesSent, sendFailed;
    volatile LONG64 passthrough;          // captured but matched no rule
    volatile LONG64 ringWaits;            // capture thread had to wait for ring space
    volatile LONG64 allocFailed;          // packets lost because the pool was exhausted
    volatile LONG64 latencySumUs;         // capture to reinjection, summed
    volatile LONG64 latencySamples;
    volatile LONG64 steps;                // processor iterations
    volatile LONG64 lateWakeups;          // woke more than 2 ms after a deadline
    volatile LONG ringDepth, ringDepthMax;
    volatile LONG64 startedAtUs;
} EngineStats;

extern EngineStats engineStats;

int  engineStart(char *err, size_t errSize);   // compiles rules, opens WinDivert, starts threads
void engineStop(void);                          // blocks until everything is flushed and closed
int  engineIsRunning(void);
void engineWake(void);                          // make the processor re-evaluate deadlines now
const char *engineFilterInUse(void);
void engineResetStats(void);
int  engineHighResolutionTimer(void);           // 1 if the OS gave us a high resolution timer
void engineDescribeOpenError(DWORD code, char *buf, size_t size);
// safety watchdog: if the processor stalls this long while running, the divert
// handle is force-closed so the OS restores normal traffic. 0 disables it.
void engineSetWatchdog(int seconds);

// canonical 5-tuple hash of a raw IP packet; safe on unaligned buffers
uint64_t engineFlowHash(const void *packet, UINT len);
