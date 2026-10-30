// Monotonic high-resolution clock shared by the engine and the time-based modules.
// All engine timestamps are int64 microseconds from QueryPerformanceCounter.
#pragma once
#include <stdint.h>

// Call once at startup (safe to call again).
void clockInit(void);

// Current monotonic time in microseconds.
int64_t clockNowUs(void);

#define US_PER_MS 1000LL
#define MS_TO_US(ms) ((int64_t)(ms) * US_PER_MS)
#define US_TO_MS(us) ((int64_t)(us) / US_PER_MS)
