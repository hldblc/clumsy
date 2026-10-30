// Seedable random source used by every module, so a run can be reproduced
// with --seed. Only the processor thread draws from it.
#pragma once
#include <stdint.h>

void rngSeed(uint64_t seed);          // 0 picks a time based seed
uint64_t rngSeedValue(void);          // the seed in effect
uint64_t rngNext(void);
double rngUniform(void);              // [0, 1)
int rngRange(int lo, int hi);         // inclusive bounds
double rngNormal(void);               // standard normal
double rngPareto(double shape);       // Pareto with scale 1, result >= 1
short rngChance(short chance);        // chance in [0, 10000]: 0 never, 10000 always
