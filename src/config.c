#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"
#include "rules.h"

void (*configRebuildUiHook)(void) = NULL;

// ---- serialize ----
int configSerialize(char *buf, size_t size) {
    size_t used = 0;
    int i, j, k;
#define EMIT(...) do { \
        int w = snprintf(buf + used, size - used, __VA_ARGS__); \
        if (w < 0 || (size_t)w >= size - used) return -1; \
        used += (size_t)w; \
    } while (0)
    EMIT("[clumsy]\nversion = %s\n", CLUMSY_VERSION);
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        EMIT("\n[rule]\nname = %s\nfilter = %s\n", r->name, r->filter);
        if (r->process[0]) EMIT("process = %s\n", r->process);
        EMIT("enabled = %s\n", r->enabled ? "on" : "off");
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            EMIT("%s = %s\n", m->desc->shortName, m->enabled ? "on" : "off");
            for (k = 0; k < m->desc->paramCount; ++k) {
                const ParamDesc *p = &m->desc->params[k];
                char val[48], key[80];
                if (p->flags & PF_HIDDEN) continue;
                paramFormatBoth(m, p, val, sizeof(val));
                snprintf(key, sizeof(key), "%s.%s", m->desc->shortName, p->name);
                EMIT("%s = %s\n", key, val);
            }
        }
    }
#undef EMIT
    return (int)used;
}

// ---- parse ----
static char *trim(char *s) {
    char *e;
    while (isspace((unsigned char)*s)) ++s;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

// apply one "key = value" line to rule r. 1 ok, 0 unknown/bad.
static int applyLine(Rule *r, const char *key, const char *val) {
    const char *dot;
    if (strieq(key, "name")) { snprintf(r->name, sizeof(r->name), "%s", val); return 1; }
    if (strieq(key, "filter")) { snprintf(r->filter, sizeof(r->filter), "%s", val); return 1; }
    if (strieq(key, "process")) { snprintf(r->process, sizeof(r->process), "%s", val); return 1; }
    if (strieq(key, "enabled")) { r->enabled = (short)(strieq(val, "on") || strieq(val, "1")); return 1; }
    dot = strchr(key, '.');
    if (dot == NULL) {
        // a bare module name toggles it
        ModuleInst *m = ruleFindModule(r, key);
        if (m == NULL) return 0;
        moduleSetEnabled(m, strieq(val, "on") || strieq(val, "1"));
        return 1;
    } else {
        char mod[32];
        size_t n = (size_t)(dot - key);
        ModuleInst *m;
        if (n >= sizeof(mod)) return 0;
        memcpy(mod, key, n);
        mod[n] = 0;
        m = ruleFindModule(r, mod);
        if (m == NULL) return 0;
        return moduleSetParamText(m, dot + 1, val);
    }
}

int configApplyFragment(Rule *r, const char *text) {
    // fragment values never contain spaces, so each whitespace/';' delimited
    // token is one "key=value" pair
    char *copy, *tok, *save = NULL;
    int applied = 0;
    if (r == NULL) return 0;
    copy = _strdup(text);
    if (copy == NULL) return 0;
    for (tok = strtok_s(copy, " \t\r\n;", &save); tok != NULL; tok = strtok_s(NULL, " \t\r\n;", &save)) {
        char *eq;
        if (*tok == '#') break;         // rest of this run is a comment
        eq = strchr(tok, '=');
        if (eq == NULL) continue;
        *eq = 0;
        if (applyLine(r, tok, eq + 1)) ++applied;
    }
    free(copy);
    return applied;
}

// shared parser. If live, only toggles/params of existing rules are applied,
// matched by position; rules are neither created nor destroyed.
static int parse(const char *text, int live, char *err, size_t errSize) {
    char *copy = _strdup(text);
    char *line, *nl;
    Rule *cur = NULL;
    int ruleIx = -1;
    int created = 0;
    if (copy == NULL) { snprintf(err, errSize, "out of memory"); return 0; }

    if (!live) {
        ruleSetClear();
    }

    line = copy;
    while (line && *line) {
        char *key, *eq;
        nl = strchr(line, '\n');
        if (nl) *nl = 0;
        {
            char *t = trim(line);
            if (*t == 0 || *t == '#' || *t == ';') goto NEXT;
            if (t[0] == '[') {
                if (strnicmp(t, "[rule]", 6) == 0) {
                    ++ruleIx;
                    if (live) {
                        cur = (ruleIx < ruleSet.count) ? ruleSet.rules[ruleIx] : NULL;
                    } else {
                        cur = ruleCreate("Rule", "");
                        if (cur == NULL || ruleSetAdd(cur) < 0) {
                            ruleDestroy(cur);
                            snprintf(err, errSize, "too many rules");
                            free(copy);
                            return 0;
                        }
                        ++created;
                    }
                } else {
                    cur = NULL;   // [clumsy] or unknown section
                }
                goto NEXT;
            }
            eq = strchr(t, '=');
            if (eq == NULL) goto NEXT;
            *eq = 0;
            key = trim(t);
            if (cur != NULL) {
                applyLine(cur, key, trim(eq + 1));
            }
        }
NEXT:
        if (!nl) break;
        line = nl + 1;
    }
    free(copy);
    if (!live && created == 0) {
        // keep at least one rule so the UI always has a tab
        Rule *r = ruleCreate("Rule 1", "outbound");
        if (r) ruleSetAdd(r);
    }
    return 1;
}

int configApply(const char *text, char *err, size_t errSize) {
    int ok = parse(text, 0, err, errSize);
    if (ok && configRebuildUiHook) configRebuildUiHook();
    return ok;
}

int configApplyLive(const char *text, char *err, size_t errSize) {
    return parse(text, 1, err, errSize);
}

// ---- files ----
int configSave(const char *path, char *err, size_t errSize) {
    static char buf[CONFIG_TEXT_MAX];
    FILE *f;
    int n = configSerialize(buf, sizeof(buf));
    if (n < 0) { snprintf(err, errSize, "configuration too large to save"); return 0; }
    f = fopen(path, "wb");
    if (f == NULL) { snprintf(err, errSize, "cannot open %s for writing", path); return 0; }
    fwrite(buf, 1, (size_t)n, f);
    fclose(f);
    return 1;
}

int configLoad(const char *path, char *err, size_t errSize) {
    static char buf[CONFIG_TEXT_MAX];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) { snprintf(err, errSize, "cannot open %s", path); return 0; }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    return configApply(buf, err, errSize);
}
