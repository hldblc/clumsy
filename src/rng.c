#include <math.h>
#include <time.h>
#include <windows.h>
#include "rng.h"

static uint64_t rngState = 0x9E3779B97F4A7C15ULL;
static uint64_t rngSeedUsed = 0;
static int rngHasSpare = 0;
static double rngSpare = 0.0;

static uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void rngSeed(uint64_t seed) {
    uint64_t s = seed;
    if (s == 0) {
        LARGE_INTEGER c;
        QueryPerformanceCounter(&c);
        s = (uint64_t)c.QuadPart ^ ((uint64_t)time(NULL) << 32) ^ (uint64_t)GetCurrentProcessId();
        if (s == 0) s = 1;
    }
    rngSeedUsed = s;
    rngState = splitmix64(&s);
    if (rngState == 0) rngState = 0x9E3779B97F4A7C15ULL;
    rngHasSpare = 0;
}

uint64_t rngSeedValue(void) {
    return rngSeedUsed;
}

// xorshift64*
uint64_t rngNext(void) {
    uint64_t x = rngState;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rngState = x;
    return x * 0x2545F4914F6CDD1DULL;
}

double rngUniform(void) {
    return (double)(rngNext() >> 11) * (1.0 / 9007199254740992.0);
}

int rngRange(int lo, int hi) {
    if (hi <= lo) return lo;
    return lo + (int)(rngUniform() * (double)((int64_t)hi - lo + 1));
}

double rngNormal(void) {
    double u, v, s;
    if (rngHasSpare) {
        rngHasSpare = 0;
        return rngSpare;
    }
    do {
        u = rngUniform() * 2.0 - 1.0;
        v = rngUniform() * 2.0 - 1.0;
        s = u * u + v * v;
    } while (s >= 1.0 || s == 0.0);
    s = sqrt(-2.0 * log(s) / s);
    rngSpare = v * s;
    rngHasSpare = 1;
    return u * s;
}

double rngPareto(double shape) {
    double u = 1.0 - rngUniform(); // (0, 1]
    if (shape <= 0.0) shape = 1.0;
    return pow(u, -1.0 / shape);
}

short rngChance(short chance) {
    if (chance >= 10000) return 1;
    if (chance <= 0) return 0;
    return (short)((rngNext() % 10000) < (uint64_t)chance);
}
