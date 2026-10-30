#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "scenario.h"

int scenarioParse(Scenario *s, const char *text, char *err, size_t errSize) {
    char *copy = _strdup(text);
    char *line, *nl;
    int lineNo = 0;
    if (copy == NULL) { snprintf(err, errSize, "out of memory"); return 0; }
    memset(s, 0, sizeof(*s));
    line = copy;
    while (line && *line) {
        char *p = line;
        ++lineNo;
        nl = strchr(line, '\n');
        if (nl) *nl = 0;
        while (isspace((unsigned char)*p)) ++p;
        if (*p == 0 || *p == '#') goto NEXT;
        if (strnicmp(p, "loop", 4) == 0 && (p[4] == 0 || isspace((unsigned char)p[4]))) {
            s->loop = 1;
            goto NEXT;
        }
        {
            char *end;
            long ms = strtol(p, &end, 10);
            if (end == p || ms < 0) {
                snprintf(err, errSize, "line %d: expected a time in milliseconds", lineNo);
                free(copy);
                return 0;
            }
            while (isspace((unsigned char)*end)) ++end;
            if (s->count >= SCENARIO_STEPS_MAX) {
                snprintf(err, errSize, "too many steps (max %d)", SCENARIO_STEPS_MAX);
                free(copy);
                return 0;
            }
            s->steps[s->count].atUs = MS_TO_US(ms);
            snprintf(s->steps[s->count].frag, SCENARIO_FRAG_MAX, "%s", end);
            if (s->steps[s->count].atUs > s->spanUs) s->spanUs = s->steps[s->count].atUs;
            ++s->count;
        }
NEXT:
        if (!nl) break;
        line = nl + 1;
    }
    free(copy);
    if (s->count == 0) {
        snprintf(err, errSize, "scenario has no steps");
        return 0;
    }
    return 1;
}

void scenarioStart(Scenario *s, int64_t now) {
    s->next = 0;
    s->startUs = now;
}

int scenarioTick(Scenario *s, int64_t now, void (*apply)(const char *frag, void *user), void *user) {
    int64_t elapsed = now - s->startUs;
    while (s->next < s->count && s->steps[s->next].atUs <= elapsed) {
        if (s->steps[s->next].frag[0] && apply) {
            apply(s->steps[s->next].frag, user);
        }
        ++s->next;
    }
    if (s->next >= s->count) {
        if (s->loop) {
            // restart one span after the final step so the loop has a beat
            s->startUs = now;
            s->next = 0;
            return 1;
        }
        return 0;
    }
    return 1;
}

int scenarioElapsedMs(const Scenario *s, int64_t now) {
    return (int)US_TO_MS(now - s->startUs);
}

int scenarioSpanMs(const Scenario *s) {
    return (int)US_TO_MS(s->spanUs);
}
