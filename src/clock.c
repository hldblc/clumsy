#include <Windows.h>
#include "clock.h"

static LARGE_INTEGER clockFreq;
static volatile LONG clockReady = 0;

void clockInit(void) {
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    clockFreq = f;
    InterlockedExchange(&clockReady, 1);
}

int64_t clockNowUs(void) {
    LARGE_INTEGER c;
    LONGLONG freq;
    if (!clockReady) {
        clockInit();
    }
    freq = clockFreq.QuadPart;
    QueryPerformanceCounter(&c);
    // Split the division so the multiplication cannot overflow on long uptimes.
    return (int64_t)((c.QuadPart / freq) * 1000000LL + ((c.QuadPart % freq) * 1000000LL) / freq);
}
