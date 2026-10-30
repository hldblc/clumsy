// Module descriptors, instances and their declarative parameter tables.
//
// A ModuleDesc describes one impairment (lag, drop, ...). A ModuleInst is one
// live copy of it inside a Rule, with its own state block. Parameters are
// declared once in a table and drive the UI, the command line, profiles,
// scenarios and the remote API.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include "packet.h"

#ifndef __IUP_H
typedef struct Ihandle_ Ihandle;
#endif

#define MODULE_MAX 16

typedef enum {
    PT_BOOL,    // short 0/1
    PT_INT,     // short, min..max
    PT_INT32,   // LONG, min..max
    PT_CHANCE,  // short, percent * 100 in [0, 10000]
    PT_FIXED,   // short, value * 100
    PT_ENUM     // short index into enumNames
} ParamType;

#define PF_PERDIR   0x1   // storage is short[2] indexed by addr.Outbound (0 inbound, 1 outbound)
#define PF_HIDDEN   0x2   // never shown by the generic UI
#define PF_ADVANCED 0x4   // shown on the second (advanced) row

typedef struct {
    const char *name;       // key used by CLI, profiles, remote API
    const char *label;      // UI label
    ParamType type;
    size_t offset;          // offsetof(State, field)
    int min, max, def;      // in storage units
    const char *enumNames;  // "a|b|c" for PT_ENUM
    unsigned flags;         // PF_*
} ParamDesc;

// Shared by every module: which directions and which share of flows it applies to.
typedef struct {
    volatile short inbound;
    volatile short outbound;
    volatile short flowPercent; // CHANCE units, 10000 = every flow
} ScopeState;

#define SCOPE_PARAMS(T) \
    { "inbound",  "Inbound",  PT_BOOL,   offsetof(T, scope.inbound),     0, 1, 1, NULL, 0 }, \
    { "outbound", "Outbound", PT_BOOL,   offsetof(T, scope.outbound),    0, 1, 1, NULL, 0 }, \
    { "flows",    "Flows(%)", PT_CHANCE, offsetof(T, scope.flowPercent), 0, 10000, 10000, NULL, PF_ADVANCED }

typedef struct ModuleInst ModuleInst;
typedef struct Rule Rule;

typedef struct {
    volatile LONG64 packets;  // packets the module acted on
    volatile LONG64 bytes;
    volatile LONG64 dropped;  // packets it destroyed
    volatile LONG queued;     // currently held back
} ModuleStats;

typedef struct {
    const char *displayName;
    const char *shortName;
    size_t stateSize;
    const ParamDesc *params;
    int paramCount;
    Ihandle *(*setupUI)(ModuleInst *inst);                     // NULL: generic controls from the param table
    void (*init)(ModuleInst *inst);                            // after defaults are applied; may be NULL
    void (*destroy)(ModuleInst *inst);                         // may be NULL
    void (*startUp)(ModuleInst *inst, int64_t now);            // enabled while the engine runs
    void (*closeDown)(ModuleInst *inst, PacketList *list);     // return held packets to list
    short (*process)(ModuleInst *inst, PacketList *list, int64_t now); // nonzero if it acted
    int64_t (*nextDeadline)(ModuleInst *inst, int64_t now);    // next time process() needs to run, -1 none; may be NULL
    const char *actionLabel;                                   // optional push button shown with the controls
    void (*action)(ModuleInst *inst);                          // its handler, runs on the UI thread
} ModuleDesc;

struct ModuleInst {
    const ModuleDesc *desc;
    void *state;
    Rule *rule;
    int index;
    volatile short enabled;
    short lastEnabled;
    volatile short triggered;
    ModuleStats stats;
    // UI (owned by the UI layer)
    Ihandle *icon, *toggle, *controls, *advanced;
    Ihandle **widgets;        // one per param, NULL when not shown
    Ihandle **widgetsDir;     // two per param (inbound, outbound) for per-direction fields
};

// All known module descriptors in processing order.
extern const ModuleDesc *const moduleDescs[];
extern const int moduleDescCount;

// Instance lifecycle (params.c)
ModuleInst *moduleCreate(const ModuleDesc *desc, Rule *rule, int index);
void moduleDestroy(ModuleInst *inst);
void moduleResetDefaults(ModuleInst *inst);
const ModuleDesc *moduleFindDesc(const char *shortName);

// Parameter access. Direction: 0 inbound, 1 outbound, -1 both (set) or first (get).
const ParamDesc *moduleFindParam(const ModuleDesc *desc, const char *name, int *dirOut);
int  paramGetInt(const ModuleInst *inst, const ParamDesc *p, int dir);
void paramSetInt(ModuleInst *inst, const ParamDesc *p, int dir, int value);
int  paramParse(const ParamDesc *p, const char *text, int *out);        // 1 ok, 0 error
void paramFormat(const ParamDesc *p, int value, char *buf, size_t bufSize);
int  paramEnumCount(const ParamDesc *p);
int  paramEnumName(const ParamDesc *p, int index, char *buf, size_t bufSize);
int  paramApplyText(ModuleInst *inst, const ParamDesc *p, int dir, const char *text); // "in/out" allowed when dir < 0
void paramFormatBoth(const ModuleInst *inst, const ParamDesc *p, char *buf, size_t bufSize); // "v" or "in/out"
int  moduleSetParamText(ModuleInst *inst, const char *name, const char *text); // 1 ok, 0 error
int  moduleGetParamText(const ModuleInst *inst, const char *name, char *buf, size_t bufSize);
void moduleSetEnabled(ModuleInst *inst, int on);

// Hooks the UI layer installs so programmatic changes refresh widgets. Called on the UI thread only.
extern void (*paramUiRefreshHook)(ModuleInst *inst, const ParamDesc *p);
extern void (*moduleEnabledUiHook)(ModuleInst *inst);

// Scope helpers for modules
int scopeMatch(const ScopeState *s, const PacketNode *pac);

// Per-direction value lookup inside process()
#define PERDIR(field, pac) ((field)[(pac)->addr.Outbound ? 1 : 0])
