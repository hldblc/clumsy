#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "module.h"
#include "atomics.h"
#include "rng.h"

void (*paramUiRefreshHook)(ModuleInst *inst, const ParamDesc *p) = NULL;
void (*moduleEnabledUiHook)(ModuleInst *inst) = NULL;

static int strieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

const ModuleDesc *moduleFindDesc(const char *shortName) {
    int i;
    for (i = 0; i < moduleDescCount; ++i) {
        if (strieq(moduleDescs[i]->shortName, shortName)) return moduleDescs[i];
    }
    return NULL;
}

ModuleInst *moduleCreate(const ModuleDesc *desc, Rule *rule, int index) {
    ModuleInst *inst = (ModuleInst *)calloc(1, sizeof(ModuleInst));
    if (inst == NULL) return NULL;
    inst->desc = desc;
    inst->rule = rule;
    inst->index = index;
    inst->state = calloc(1, desc->stateSize > 0 ? desc->stateSize : 1);
    inst->widgets = (Ihandle **)calloc(desc->paramCount > 0 ? (size_t)desc->paramCount : 1, sizeof(Ihandle *));
    if (inst->state == NULL || inst->widgets == NULL) {
        moduleDestroy(inst);
        return NULL;
    }
    moduleResetDefaults(inst);
    if (desc->init) desc->init(inst);
    return inst;
}

void moduleDestroy(ModuleInst *inst) {
    if (inst == NULL) return;
    if (inst->desc->destroy && inst->state) inst->desc->destroy(inst);
    free(inst->state);
    free(inst->widgets);
    free(inst);
}

void moduleResetDefaults(ModuleInst *inst) {
    int i;
    for (i = 0; i < inst->desc->paramCount; ++i) {
        const ParamDesc *p = &inst->desc->params[i];
        paramSetInt(inst, p, -1, p->def);
    }
}

// "name", "name.in", "name.out"
const ParamDesc *moduleFindParam(const ModuleDesc *desc, const char *name, int *dirOut) {
    char base[64];
    const char *dot = strrchr(name, '.');
    int dir = -1;
    int i;
    size_t len;
    if (dot && (strieq(dot + 1, "in") || strieq(dot + 1, "out"))) {
        dir = strieq(dot + 1, "out") ? 1 : 0;
        len = (size_t)(dot - name);
    } else {
        len = strlen(name);
    }
    if (len >= sizeof(base)) return NULL;
    memcpy(base, name, len);
    base[len] = 0;
    for (i = 0; i < desc->paramCount; ++i) {
        const ParamDesc *p = &desc->params[i];
        if (strieq(p->name, base)) {
            if (dir >= 0 && !(p->flags & PF_PERDIR)) return NULL;
            if (dirOut) *dirOut = dir;
            return p;
        }
    }
    return NULL;
}

static void *paramAddr(const ModuleInst *inst, const ParamDesc *p, int dir) {
    char *base = (char *)inst->state + p->offset;
    if ((p->flags & PF_PERDIR) && dir == 1) {
        base += (p->type == PT_INT32) ? sizeof(LONG) : sizeof(short);
    }
    return base;
}

static int clampInt(const ParamDesc *p, int value) {
    if (p->type == PT_BOOL) return value ? 1 : 0;
    if (value < p->min) return p->min;
    if (value > p->max) return p->max;
    return value;
}

int paramGetInt(const ModuleInst *inst, const ParamDesc *p, int dir) {
    void *addr = paramAddr(inst, p, dir < 0 ? 0 : dir);
    if (p->type == PT_INT32) return (int)*(volatile LONG *)addr;
    return (int)*(volatile short *)addr;
}

static void paramStore(const ModuleInst *inst, const ParamDesc *p, int dir, int value) {
    void *addr = paramAddr(inst, p, dir);
    if (p->type == PT_INT32) {
        atomicExch32((volatile LONG *)addr, value);
    } else {
        atomicExch16((volatile short *)addr, value);
    }
}

void paramSetInt(ModuleInst *inst, const ParamDesc *p, int dir, int value) {
    value = clampInt(p, value);
    if (p->flags & PF_PERDIR) {
        if (dir < 0) {
            paramStore(inst, p, 0, value);
            paramStore(inst, p, 1, value);
        } else {
            paramStore(inst, p, dir, value);
        }
    } else {
        paramStore(inst, p, 0, value);
    }
}

int paramEnumCount(const ParamDesc *p) {
    int n = 1;
    const char *s = p->enumNames;
    if (s == NULL || *s == 0) return 0;
    for (; *s; ++s) if (*s == '|') ++n;
    return n;
}

int paramEnumName(const ParamDesc *p, int index, char *buf, size_t bufSize) {
    const char *s = p->enumNames;
    const char *end;
    size_t len;
    if (s == NULL || index < 0) return 0;
    while (index > 0) {
        s = strchr(s, '|');
        if (s == NULL) return 0;
        ++s;
        --index;
    }
    end = strchr(s, '|');
    len = end ? (size_t)(end - s) : strlen(s);
    if (len + 1 > bufSize) len = bufSize - 1;
    memcpy(buf, s, len);
    buf[len] = 0;
    return 1;
}

static int parseBool(const char *t, int *out) {
    if (strieq(t, "1") || strieq(t, "on") || strieq(t, "yes") || strieq(t, "true")) { *out = 1; return 1; }
    if (strieq(t, "0") || strieq(t, "off") || strieq(t, "no") || strieq(t, "false")) { *out = 0; return 1; }
    return 0;
}

int paramParse(const ParamDesc *p, const char *text, int *out) {
    char *end;
    double d;
    long l;
    int i, n;
    char name[32];
    while (isspace((unsigned char)*text)) ++text;
    if (*text == 0) return 0;
    switch (p->type) {
    case PT_BOOL:
        return parseBool(text, out);
    case PT_INT:
    case PT_INT32:
        l = strtol(text, &end, 10);
        while (isspace((unsigned char)*end)) ++end;
        if (*end != 0) return 0;
        *out = (int)l;
        return 1;
    case PT_CHANCE:
    case PT_FIXED:
        d = strtod(text, &end);
        while (isspace((unsigned char)*end)) ++end;
        if (*end == '%') ++end;
        while (isspace((unsigned char)*end)) ++end;
        if (*end != 0) return 0;
        *out = (int)floor(d * 100.0 + 0.5);
        return 1;
    case PT_ENUM:
        n = paramEnumCount(p);
        for (i = 0; i < n; ++i) {
            if (paramEnumName(p, i, name, sizeof(name)) && strieq(name, text)) { *out = i; return 1; }
        }
        l = strtol(text, &end, 10);
        if (*end == 0 && l >= 0 && l < n) { *out = (int)l; return 1; }
        return 0;
    }
    return 0;
}

static void trimFixed(char *buf) {
    // "10.00" -> "10.0", "0.25" stays, "12.50" -> "12.5"
    char *dot = strchr(buf, '.');
    char *e;
    if (dot == NULL) return;
    e = buf + strlen(buf) - 1;
    while (e > dot + 1 && *e == '0') { *e = 0; --e; }
}

void paramFormat(const ParamDesc *p, int value, char *buf, size_t bufSize) {
    switch (p->type) {
    case PT_BOOL:
        snprintf(buf, bufSize, "%s", value ? "on" : "off");
        break;
    case PT_INT:
    case PT_INT32:
        snprintf(buf, bufSize, "%d", value);
        break;
    case PT_CHANCE:
    case PT_FIXED:
        snprintf(buf, bufSize, "%.2f", value / 100.0);
        trimFixed(buf);
        break;
    case PT_ENUM:
        if (!paramEnumName(p, value, buf, bufSize)) snprintf(buf, bufSize, "%d", value);
        break;
    }
}

int moduleSetParamText(ModuleInst *inst, const char *name, const char *text) {
    int dir = -1, value;
    const ParamDesc *p = moduleFindParam(inst->desc, name, &dir);
    if (p == NULL) return 0;
    if (!paramParse(p, text, &value)) return 0;
    paramSetInt(inst, p, dir, value);
    if (paramUiRefreshHook) paramUiRefreshHook(inst, p);
    return 1;
}

int moduleGetParamText(const ModuleInst *inst, const char *name, char *buf, size_t bufSize) {
    int dir = -1;
    const ParamDesc *p = moduleFindParam(inst->desc, name, &dir);
    if (p == NULL) return 0;
    paramFormat(p, paramGetInt(inst, p, dir), buf, bufSize);
    return 1;
}

void moduleSetEnabled(ModuleInst *inst, int on) {
    atomicExch16(&inst->enabled, on ? 1 : 0);
    if (moduleEnabledUiHook) moduleEnabledUiHook(inst);
}

int scopeMatch(const ScopeState *s, const PacketNode *pac) {
    short pct;
    if (pac->addr.Outbound ? !s->outbound : !s->inbound) return 0;
    pct = s->flowPercent;
    if (pct >= 10000) return 1;
    if (pct <= 0) return 0;
    // Deterministic per flow: the same connection is always in or always out.
    return (int)((pac->flowHash >> 20) % 10000) < pct;
}
