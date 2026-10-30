// Rule sets: each rule is a WinDivert filter with its own chain of module instances.
// The engine captures the union of all enabled rule filters and hands each packet
// to the first rule whose filter matches it.
#pragma once
#include "common.h"

#define RULE_MAX 8
#define RULE_NAME_MAX 32
#define FILTER_OBJ_SIZE 8192

struct Rule {
    char name[RULE_NAME_MAX];
    char filter[FILTER_BUFSIZE];     // filter text as typed
    char object[FILTER_OBJ_SIZE];    // compiled filter object for WinDivertHelperEvalFilter
    volatile short enabled;
    int index;
    PacketList list;                 // working list, processor thread only
    ModuleInst *modules[MODULE_MAX];
    int moduleCount;
    volatile LONG64 matched, bytesMatched;
    // UI handles owned by main.c
    Ihandle *tab, *filterText, *enabledToggle;
};

typedef struct {
    Rule *rules[RULE_MAX];
    int count;
} RuleSet;

extern RuleSet ruleSet;

Rule *ruleCreate(const char *name, const char *filter);
void ruleDestroy(Rule *r);
int  ruleSetAdd(Rule *r);                 // index or -1 when full
void ruleSetRemove(int index);            // destroys the rule
void ruleSetClear(void);
int  ruleSetEnabledCount(void);
int  ruleCompile(Rule *r, char *err, size_t errSize);
int  ruleSetBuildUnionFilter(char *buf, size_t size);   // number of enabled rules
Rule *ruleSetMatch(const void *packet, UINT len, const WINDIVERT_ADDRESS *addr);
ModuleInst *ruleFindModule(Rule *r, const char *shortName);
