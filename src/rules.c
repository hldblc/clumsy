#include <stdlib.h>
#include "rules.h"

extern const ModuleDesc lagModuleDesc, dropModuleDesc, throttleModuleDesc, dupModuleDesc,
    oodModuleDesc, tamperModuleDesc, resetModuleDesc, bandwidthModuleDesc,
    tcpModuleDesc, outageModuleDesc, fragmentModuleDesc;

// Processing order: a packet walks this chain from first to last.
// Fragment runs last so earlier modules act on whole packets.
const ModuleDesc *const moduleDescs[] = {
    &outageModuleDesc,
    &lagModuleDesc,
    &dropModuleDesc,
    &throttleModuleDesc,
    &dupModuleDesc,
    &oodModuleDesc,
    &tcpModuleDesc,
    &tamperModuleDesc,
    &resetModuleDesc,
    &bandwidthModuleDesc,
    &fragmentModuleDesc,
};
const int moduleDescCount = (int)(sizeof(moduleDescs) / sizeof(moduleDescs[0]));

RuleSet ruleSet;

Rule *ruleCreate(const char *name, const char *filter) {
    Rule *r = (Rule *)calloc(1, sizeof(Rule));
    int i;
    if (r == NULL) return NULL;
    snprintf(r->name, sizeof(r->name), "%s", name ? name : "Rule");
    snprintf(r->filter, sizeof(r->filter), "%s", filter ? filter : "");
    r->enabled = 1;
    r->index = -1;
    listInit(&r->list);
    for (i = 0; i < moduleDescCount && i < MODULE_MAX; ++i) {
        r->modules[i] = moduleCreate(moduleDescs[i], r, i);
        if (r->modules[i] == NULL) {
            ruleDestroy(r);
            return NULL;
        }
        r->moduleCount = i + 1;
    }
    return r;
}

void ruleDestroy(Rule *r) {
    int i;
    if (r == NULL) return;
    for (i = 0; i < r->moduleCount; ++i) {
        moduleDestroy(r->modules[i]);
    }
    listFreeAll(&r->list);
    free(r);
}

int ruleSetAdd(Rule *r) {
    if (ruleSet.count >= RULE_MAX) return -1;
    r->index = ruleSet.count;
    ruleSet.rules[ruleSet.count++] = r;
    return r->index;
}

void ruleSetRemove(int index) {
    int i;
    if (index < 0 || index >= ruleSet.count) return;
    ruleDestroy(ruleSet.rules[index]);
    for (i = index; i < ruleSet.count - 1; ++i) {
        ruleSet.rules[i] = ruleSet.rules[i + 1];
        ruleSet.rules[i]->index = i;
    }
    ruleSet.rules[--ruleSet.count] = NULL;
}

void ruleSetClear(void) {
    while (ruleSet.count > 0) {
        ruleSetRemove(ruleSet.count - 1);
    }
}

int ruleSetEnabledCount(void) {
    int i, n = 0;
    for (i = 0; i < ruleSet.count; ++i) {
        if (ruleSet.rules[i]->enabled) ++n;
    }
    return n;
}

int ruleSetAnyProcess(void) {
    int i;
    for (i = 0; i < ruleSet.count; ++i) {
        if (ruleSet.rules[i]->enabled && ruleSet.rules[i]->process[0]) return 1;
    }
    return 0;
}

int filterCheck(const char *filter, char *err, size_t errSize) {
    const char *errStr = NULL;
    UINT errPos = 0;
    const char *f = filter;
    char object[FILTER_OBJ_SIZE];
    while (*f == ' ' || *f == '\t') ++f;
    if (*f == 0) {
        snprintf(err, errSize, "filter is empty");
        return 0;
    }
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK, object, sizeof(object), &errStr, &errPos)) {
        snprintf(err, errSize, "error at position %u: %s", errPos, errStr ? errStr : "invalid filter");
        return 0;
    }
    return 1;
}

int ruleCompile(Rule *r, char *err, size_t errSize) {
    const char *errStr = NULL;
    UINT errPos = 0;
    const char *f = r->filter;
    while (*f == ' ' || *f == '\t') ++f;
    if (*f == 0) {
        snprintf(err, errSize, "%s: filter is empty", r->name);
        return 0;
    }
    if (!WinDivertHelperCompileFilter(r->filter, WINDIVERT_LAYER_NETWORK, r->object, sizeof(r->object), &errStr, &errPos)) {
        snprintf(err, errSize, "%s: filter error at position %u: %s", r->name, errPos, errStr ? errStr : "invalid filter");
        return 0;
    }
    return 1;
}

int ruleSetBuildUnionFilter(char *buf, size_t size) {
    int i, n = 0;
    size_t used = 0;
    buf[0] = 0;
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        int w;
        if (!r->enabled) continue;
        w = snprintf(buf + used, size - used, n == 0 ? "(%s)" : " or (%s)", r->filter);
        if (w < 0 || (size_t)w >= size - used) {
            buf[used] = 0;
            return -1;
        }
        used += (size_t)w;
        ++n;
    }
    return n;
}

Rule *ruleSetMatch(const void *packet, UINT len, const WINDIVERT_ADDRESS *addr) {
    Rule *only = NULL;
    int i, enabled = 0;
    for (i = 0; i < ruleSet.count; ++i) {
        if (ruleSet.rules[i]->enabled) {
            ++enabled;
            only = ruleSet.rules[i];
        }
    }
    if (enabled == 1) {
        // the kernel filter is exactly this rule's filter
        return only;
    }
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        if (!r->enabled) continue;
        if (WinDivertHelperEvalFilter(r->object, packet, len, addr)) {
            return r;
        }
    }
    return NULL;
}

ModuleInst *ruleFindModule(Rule *r, const char *shortName) {
    int i;
    for (i = 0; i < r->moduleCount; ++i) {
        if (strieq(r->modules[i]->desc->shortName, shortName)) return r->modules[i];
    }
    return NULL;
}
