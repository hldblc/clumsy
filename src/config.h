// Save / load / share the whole rule set as a small INI-like text.
//
//   [clumsy]
//   version = 0.4
//   [rule]
//   name = Rule 1
//   filter = udp and outbound
//   process = game.exe
//   enabled = 1
//   lag = on
//   lag.time = 20/80
//   lag.dist = normal
//   drop = off
//
// A [rule] line starts a new rule. "module = on/off" toggles a module; a
// "module.param = value" line sets one parameter (value may be "in/out").
// The same format backs saved sessions (item 19), built-in profiles (item 6)
// and scenario steps (item 7).
#pragma once
#include "common.h"

#define CONFIG_TEXT_MAX 16384

// whole rule set -> text; returns bytes written, or -1 if it did not fit
int configSerialize(char *buf, size_t size);

// rebuild the rule set from text; 1 ok, 0 with message in err
int configApply(const char *text, char *err, size_t errSize);

// apply only parameter/toggle changes to the existing rules, without
// recreating them (used by scenarios so the engine keeps running)
int configApplyLive(const char *text, char *err, size_t errSize);

int configSave(const char *path, char *err, size_t errSize);
int configLoad(const char *path, char *err, size_t errSize);

// apply a fragment of "key = value" lines (no [rule] header) to one rule,
// in place. Used by profiles and scenario steps. Lines may be newline or
// semicolon separated; returns the number of lines applied.
int configApplyFragment(Rule *r, const char *text);

// main.c sets this so configApply can rebuild the tabs after the rule set changes
extern void (*configRebuildUiHook)(void);
