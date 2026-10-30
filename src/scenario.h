// Scenario timelines: a list of timed steps that change impairment settings
// over time, so handoffs, tunnels and recovery can be reproduced on demand.
// Roadmap item 7. The parser and the tick logic are pure and unit tested; the
// UI drives a tick on an IUP timer.
//
// Format (one step per line): <time_ms> <key=value> [<key=value> ...]
//   0     lag=on lag.time=50
//   5000  lag.time=300 drop=on drop.chance=5
//   15000 outage=on
//   18000 outage=off lag.time=50
// Lines starting with # are comments. "loop" on its own line repeats.
#pragma once
#include "common.h"

#define SCENARIO_STEPS_MAX 256
#define SCENARIO_FRAG_MAX 240

typedef struct {
    int64_t atUs;
    char frag[SCENARIO_FRAG_MAX];
} ScenarioStep;

typedef struct {
    ScenarioStep steps[SCENARIO_STEPS_MAX];
    int count;
    int next;          // index of the next step to fire
    int loop;
    int64_t startUs;   // when playback started
    int64_t spanUs;    // time of the last step
} Scenario;

int  scenarioParse(Scenario *s, const char *text, char *err, size_t errSize);
void scenarioStart(Scenario *s, int64_t now);
// fire any steps now due, calling apply(frag, user) for each; returns 1 while
// playing, 0 once finished (a looping scenario never returns 0).
int  scenarioTick(Scenario *s, int64_t now, void (*apply)(const char *frag, void *user), void *user);
int  scenarioElapsedMs(const Scenario *s, int64_t now);
int  scenarioSpanMs(const Scenario *s);
