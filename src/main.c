#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <Windows.h>
#include "iup.h"
#include "common.h"
#include "engine.h"
#include "rules.h"
#include "uibind.h"
#include "config.h"
#include "profiles.h"
#include "cli.h"
#include "scenario.h"
#include "pcap.h"
#include "winui.h"
#include "safety.h"
#include "remote.h"
#include "targets.h"

#define CONFIG_FILE "config.txt"
#define CONFIG_MAX_RECORDS 64
#define CONFIG_BUF_SIZE 4096
#define ICON_UPDATE_MS 200

// filter presets from config.txt
typedef struct {
    char *filterName;
    char *filterValue;
} filterRecord;
static UINT filtersSize;
static filterRecord filters[CONFIG_MAX_RECORDS];
static char configBuf[CONFIG_BUF_SIZE + 2];
BOOL parameterized = 0;

static Ihandle *dialog, *startButton, *stateIcon, *statusLabel, *tabs, *presetList;
static Ihandle *addRuleButton, *removeRuleButton, *advancedToggle, *timer, *timeoutTimer;
static Ihandle *profileList, *saveButton, *loadButton, *statsButton, *logButton;
static Ihandle *scenarioButton, *scenarioLoadButton, *scenarioLabel, *scenarioTimer;
static Scenario scenario;
static int scenarioLoaded = 0, scenarioPlaying = 0;
static void uiAddRuleTab(Rule *r);

// ---- live statistics ----
#define STATS_SAMPLES 180
static Ihandle *statsDialog = NULL, *statsCanvas, *statsText, *statsTimer;
static int statsOpen = 0;
static float sampleSent[STATS_SAMPLES], sampleDrop[STATS_SAMPLES];
static int sampleHead = 0, sampleCount = 0;
static LONG64 statsPrevSent, statsPrevDrop, statsPrevCap;
static int64_t statsPrevUs;
static int dialogMapped = 0;
static int ruleSerial = 1;
static LONG64 lastSent = 0, lastFailed = 0;
static int startOnShow = 0;     // auto-start filtering when the window shows
static int headlessMode = 0;    // run without a visible window
static int headlessStop = 0;

static int uiStartCb(Ihandle *ih);
static int uiStopCb(Ihandle *ih);

void showStatus(const char *line) {
    IupStoreAttribute(statusLabel, "TITLE", line);
}

// ---- config presets ----
static void loadConfig(void) {
    char path[MSG_BUFSIZE];
    char *p;
    FILE *f;
    GetModuleFileName(NULL, path, MSG_BUFSIZE);
    p = strrchr(path, '\\');
    if (p == NULL) p = strrchr(path, '/');
    if (p == NULL) p = path - 1;
    strcpy(p + 1, CONFIG_FILE);
    LOG("config path: %s", path);
    f = fopen(path, "r");
    if (f) {
        size_t len;
        char *current, *last;
        len = fread(configBuf, sizeof(char), CONFIG_BUF_SIZE, f);
        fclose(f);
        if (len == CONFIG_BUF_SIZE) {
            LOG("config file is larger than %d bytes, truncated", CONFIG_BUF_SIZE);
        }
        configBuf[len] = '\n';
        configBuf[len + 1] = '\0';
        filtersSize = 0;
        last = current = configBuf;
        do {
EAT_SPACE:  while (isspace((unsigned char)*current)) { ++current; }
            if (*current == '#') {
                current = strchr(current, '\n');
                if (!current) break;
                current = current + 1;
                goto EAT_SPACE;
            }
            last = current;
            current = strchr(last, ':');
            if (!current) break;
            *current = '\0';
            filters[filtersSize].filterName = last;
            current += 1;
            while (isspace((unsigned char)*current)) { ++current; }
            last = current;
            current = strchr(last, '\n');
            if (!current) break;
            filters[filtersSize].filterValue = last;
            *current = '\0';
            if (current > last && *(current - 1) == '\r') *(current - 1) = 0;
            last = current = current + 1;
            ++filtersSize;
        } while (last && last - configBuf < CONFIG_BUF_SIZE && filtersSize < CONFIG_MAX_RECORDS);
        LOG("loaded %u presets", filtersSize);
    }
    if (!f || filtersSize == 0) {
        LOG("no presets loaded, using a built-in one");
        filters[0].filterName = "loopback packets";
        filters[0].filterValue = "outbound and ip.DstAddr >= 127.0.0.1 and ip.DstAddr <= 127.255.255.255";
        filtersSize = 1;
    }
}

// ---- rule tabs ----
static Rule *currentRule(void) {
    int pos = IupGetInt(tabs, "VALUEPOS");
    if (ruleSet.count == 0) return NULL;
    if (pos < 0 || pos >= ruleSet.count) return ruleSet.rules[0];
    return ruleSet.rules[pos];
}

static void updateFilterStatus(Rule *r) {
    char err[MSG_BUFSIZE], msg[MSG_BUFSIZE];
    const char *f;
    if (r == NULL || r->filterStatus == NULL) return;
    f = IupGetAttribute(r->filterText, "VALUE");
    if (filterCheck(f ? f : "", err, sizeof(err))) {
        IupSetAttribute(r->filterStatus, "FGCOLOR", "0 128 0");
        IupSetStrAttribute(r->filterStatus, "TITLE", "\xE2\x9C\x93 valid");
    } else {
        snprintf(msg, sizeof(msg), "\xE2\x9C\x97 %s", err);
        IupSetAttribute(r->filterStatus, "FGCOLOR", "208 70 72");
        IupSetStrAttribute(r->filterStatus, "TITLE", msg);
    }
    IupRefresh(r->filterStatus);
}

static int uiFilterTextCb(Ihandle *ih) {
    Rule *r = (Rule *)IupGetAttribute(ih, "_CLUMSY_RULE");
    IupSetAttribute(presetList, "VALUE", "0");
    updateFilterStatus(r);
    return IUP_DEFAULT;
}

// visual filter builder: a small dialog that assembles a WinDivert filter
static int uiBuildFilterCb(Ihandle *ih) {
    Rule *r = (Rule *)IupGetAttribute(ih, "_CLUMSY_RULE");
    int proto = 0, dir = 0, port = 0;
    char ip[256] = "";
    char filter[FILTER_BUFSIZE] = "";
    const char *protoName[] = { NULL, "tcp", "udp", "icmp" };
    size_t used = 0;
    int clauses = 0;
    if (r == NULL) return IUP_DEFAULT;
    if (!IupGetParam("Filter builder", NULL, NULL,
            "Protocol: %l|any|tcp|udp|icmp|\n"
            "Direction: %l|any|outbound|inbound|\n"
            "Host/IP/CIDR (optional): %s\n"
            "Port (0 = any): %i\n",
            &proto, &dir, ip, &port, NULL)) {
        return IUP_DEFAULT;
    }
#define ADD(...) do { \
        int w = snprintf(filter + used, sizeof(filter) - used, clauses ? " and %s" : "%s", __VA_ARGS__); \
        if (w > 0 && (size_t)w < sizeof(filter) - used) { used += (size_t)w; ++clauses; } \
    } while (0)
    if (proto >= 1 && proto <= 3) ADD(protoName[proto]);
    if (dir == 1) ADD("outbound");
    else if (dir == 2) ADD("inbound");
    if (ip[0]) {
        char clause[512];
        if (targetBuildClause(ip, clause, sizeof(clause))) {
            ADD(clause);
        } else {
            showStatus(clause);   // clause holds the error message
        }
    }
    if (port > 0 && port <= 65535) {
        char clause[160];
        const char *pp = (proto == 1) ? "tcp" : (proto == 2) ? "udp" : "tcp or udp, use";
        UNREFERENCED_PARAMETER(pp);
        if (proto == 1 || proto == 2) {
            snprintf(clause, sizeof(clause), "(%s.DstPort == %d or %s.SrcPort == %d)", protoName[proto], port, protoName[proto], port);
        } else {
            snprintf(clause, sizeof(clause), "(tcp.DstPort == %d or tcp.SrcPort == %d or udp.DstPort == %d or udp.SrcPort == %d)", port, port, port, port);
        }
        ADD(clause);
    }
#undef ADD
    if (clauses == 0) snprintf(filter, sizeof(filter), "outbound");
    IupStoreAttribute(r->filterText, "VALUE", filter);
    IupSetAttribute(presetList, "VALUE", "0");
    updateFilterStatus(r);
    return IUP_DEFAULT;
}

static int uiRuleEnabledCb(Ihandle *ih, int state) {
    Rule *r = (Rule *)IupGetAttribute(ih, "_CLUMSY_RULE");
    atomicExch16(&r->enabled, state ? 1 : 0);
    engineWake();
    return IUP_DEFAULT;
}

static void uiAddRuleTab(Rule *r) {
    Ihandle *filterText, *enabledToggle, *filterRow, *procRow, *procText, *procLabel;
    Ihandle *modulesVbox, *functionsFrame, *tab, *label, *tabBox, *buildButton, *filterStatus;
    int i;

    label = IupLabel("Filter:");
    filterText = IupText(NULL);
    IupSetAttribute(filterText, "EXPAND", "HORIZONTAL");
    IupStoreAttribute(filterText, "VALUE", r->filter);
    IupSetAttribute(filterText, "_CLUMSY_RULE", (char *)r);
    IupSetCallback(filterText, "VALUECHANGED_CB", uiFilterTextCb);
    buildButton = IupButton("Build...", NULL);
    IupSetAttribute(buildButton, "PADDING", "4x");
    IupSetAttribute(buildButton, "_CLUMSY_RULE", (char *)r);
    IupSetCallback(buildButton, "ACTION", uiBuildFilterCb);
    enabledToggle = IupToggle("Enabled", NULL);
    IupSetAttribute(enabledToggle, "VALUE", r->enabled ? "ON" : "OFF");
    IupSetAttribute(enabledToggle, "_CLUMSY_RULE", (char *)r);
    IupSetCallback(enabledToggle, "ACTION", (Icallback)uiRuleEnabledCb);
    filterRow = IupHbox(label, filterText, buildButton, enabledToggle, NULL);
    IupSetAttribute(filterRow, "ALIGNMENT", "ACENTER");
    IupSetAttribute(filterRow, "GAP", "4");
    filterStatus = IupLabel("");
    r->filterStatus = filterStatus;

    procLabel = IupLabel("Process (optional, e.g. game.exe):");
    procText = IupText(NULL);
    IupSetAttribute(procText, "VISIBLECOLUMNS", "24");
    IupStoreAttribute(procText, "VALUE", r->process);
    procRow = IupHbox(procLabel, procText, IupFill(), NULL);
    IupSetAttribute(procRow, "ALIGNMENT", "ACENTER");
    IupSetAttribute(procRow, "GAP", "4");
    r->processText = procText;

    modulesVbox = IupVbox(NULL);
    IupSetAttribute(modulesVbox, "NCMARGIN", "4x4");
    IupSetAttribute(modulesVbox, "NCGAP", "4x2");
    for (i = 0; i < r->moduleCount; ++i) {
        uiBuildModuleRow(r->modules[i], modulesVbox);
    }
    functionsFrame = IupFrame(modulesVbox);
    IupSetAttribute(functionsFrame, "TITLE", "Functions");
    IupSetAttribute(functionsFrame, "EXPAND", "HORIZONTAL");

    tabBox = IupVbox(filterRow, filterStatus, procRow, functionsFrame, NULL);
    tab = tabBox;
    IupSetAttribute(tab, "NCMARGIN", "4x4");
    IupSetAttribute(tab, "NCGAP", "4x4");
    IupSetStrAttribute(tab, "TABTITLE", r->name);
    r->tab = tab;
    r->filterText = filterText;
    r->enabledToggle = enabledToggle;
    IupAppend(tabs, tab);
    if (dialogMapped) {
        IupMap(tab);
        IupRefresh(tabs);
    }
    updateFilterStatus(r);
}

static int uiAddRuleCb(Ihandle *ih) {
    char name[RULE_NAME_MAX];
    Rule *cur = currentRule(), *r;
    const char *f;
    UNREFERENCED_PARAMETER(ih);
    if (engineIsRunning()) return IUP_DEFAULT;
    if (ruleSet.count >= RULE_MAX) {
        showStatus("At most " STR(RULE_MAX) " rules are supported.");
        return IUP_DEFAULT;
    }
    snprintf(name, sizeof(name), "Rule %d", ++ruleSerial);
    f = cur ? IupGetAttribute(cur->filterText, "VALUE") : filters[0].filterValue;
    r = ruleCreate(name, f);
    if (r == NULL || ruleSetAdd(r) < 0) {
        ruleDestroy(r);
        showStatus("Could not add a rule.");
        return IUP_DEFAULT;
    }
    uiAddRuleTab(r);
    IupSetInt(tabs, "VALUEPOS", r->index);
    IupRefresh(dialog);
    return IUP_DEFAULT;
}

static int uiRemoveRuleCb(Ihandle *ih) {
    int pos;
    Rule *r;
    UNREFERENCED_PARAMETER(ih);
    if (engineIsRunning()) return IUP_DEFAULT;
    if (ruleSet.count <= 1) {
        showStatus("Keep at least one rule.");
        return IUP_DEFAULT;
    }
    pos = IupGetInt(tabs, "VALUEPOS");
    if (pos < 0 || pos >= ruleSet.count) return IUP_DEFAULT;
    r = ruleSet.rules[pos];
    IupDestroy(r->tab);     // detaches the page and all module widgets
    ruleSetRemove(pos);     // then the instances behind them
    IupRefresh(dialog);
    return IUP_DEFAULT;
}

static int uiListSelectCb(Ihandle *ih, char *text, int item, int state) {
    UNREFERENCED_PARAMETER(ih);
    UNREFERENCED_PARAMETER(text);
    if (state == 1) {
        Rule *r = currentRule();
        if (r && item >= 1 && (UINT)item <= filtersSize) {
            IupStoreAttribute(r->filterText, "VALUE", filters[item - 1].filterValue);
        }
    }
    return IUP_DEFAULT;
}

static int uiAdvancedCb(Ihandle *ih, int state) {
    UNREFERENCED_PARAMETER(ih);
    uiSetAdvancedVisible(state);
    IupRefresh(dialog);
    return IUP_DEFAULT;
}

// ---- profiles / sessions ----
static int uiProfileCb(Ihandle *ih, char *text, int item, int state) {
    UNREFERENCED_PARAMETER(ih);
    UNREFERENCED_PARAMETER(text);
    if (state == 1) {
        Rule *r = currentRule();
        const char *frag = profileText(item - 1);
        if (r && frag) {
            configApplyFragment(r, frag);
            engineWake();
            showStatus("Applied profile to the current rule.");
        }
    }
    return IUP_DEFAULT;
}

static int uiSaveCb(Ihandle *ih) {
    Ihandle *dlg = IupFileDlg();
    char err[MSG_BUFSIZE];
    int i;
    UNREFERENCED_PARAMETER(ih);
    // pull the latest filter/process text from the widgets into the rules
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        const char *f = IupGetAttribute(r->filterText, "VALUE");
        const char *p = r->processText ? IupGetAttribute(r->processText, "VALUE") : NULL;
        snprintf(r->filter, sizeof(r->filter), "%s", f ? f : "");
        snprintf(r->process, sizeof(r->process), "%s", p ? p : "");
    }
    IupSetAttribute(dlg, "DIALOGTYPE", "SAVE");
    IupSetAttribute(dlg, "TITLE", "Save clumsy configuration");
    IupSetAttribute(dlg, "EXTFILTER", "clumsy config (*.clumsy)|*.clumsy|All files|*.*|");
    IupSetAttribute(dlg, "FILE", "clumsy.clumsy");
    IupPopup(dlg, IUP_CURRENT, IUP_CURRENT);
    if (IupGetInt(dlg, "STATUS") != -1) {
        const char *path = IupGetAttribute(dlg, "VALUE");
        if (configSave(path, err, sizeof(err))) showStatus("Saved configuration.");
        else showStatus(err);
    }
    IupDestroy(dlg);
    return IUP_DEFAULT;
}

static int uiLoadCb(Ihandle *ih) {
    Ihandle *dlg;
    char err[MSG_BUFSIZE];
    UNREFERENCED_PARAMETER(ih);
    if (engineIsRunning()) {
        showStatus("Stop filtering before loading a configuration.");
        return IUP_DEFAULT;
    }
    dlg = IupFileDlg();
    IupSetAttribute(dlg, "DIALOGTYPE", "OPEN");
    IupSetAttribute(dlg, "TITLE", "Load clumsy configuration");
    IupSetAttribute(dlg, "EXTFILTER", "clumsy config (*.clumsy)|*.clumsy|All files|*.*|");
    IupPopup(dlg, IUP_CURRENT, IUP_CURRENT);
    if (IupGetInt(dlg, "STATUS") == 0) {
        const char *path = IupGetAttribute(dlg, "VALUE");
        if (configLoad(path, err, sizeof(err))) showStatus("Loaded configuration.");
        else showStatus(err);
    }
    IupDestroy(dlg);
    return IUP_DEFAULT;
}

// ---- scenario playback ----
static void scenarioApply(const char *frag, void *user) {
    int i;
    UNREFERENCED_PARAMETER(user);
    for (i = 0; i < ruleSet.count; ++i) {
        configApplyFragment(ruleSet.rules[i], frag);
    }
    engineWake();
}

static void scenarioSetPlaying(int playing) {
    scenarioPlaying = playing;
    IupSetAttribute(scenarioTimer, "RUN", playing ? "YES" : "NO");
    IupSetStrAttribute(scenarioButton, "TITLE", playing ? "Stop scenario" : "Play scenario");
}

static int uiScenarioTickCb(Ihandle *ih) {
    char buf[64];
    int64_t now = clockNowUs();
    UNREFERENCED_PARAMETER(ih);
    if (!scenarioPlaying) return IUP_DEFAULT;
    if (!scenarioTick(&scenario, now, scenarioApply, NULL)) {
        scenarioSetPlaying(0);
        IupSetStrAttribute(scenarioLabel, "TITLE", "scenario: done");
        return IUP_DEFAULT;
    }
    snprintf(buf, sizeof(buf), "scenario: %d.%01ds / %d.%01ds",
             scenarioElapsedMs(&scenario, now) / 1000, (scenarioElapsedMs(&scenario, now) / 100) % 10,
             scenarioSpanMs(&scenario) / 1000, (scenarioSpanMs(&scenario) / 100) % 10);
    IupSetStrAttribute(scenarioLabel, "TITLE", buf);
    return IUP_DEFAULT;
}

static int uiScenarioLoadCb(Ihandle *ih) {
    Ihandle *dlg = IupFileDlg();
    UNREFERENCED_PARAMETER(ih);
    IupSetAttribute(dlg, "DIALOGTYPE", "OPEN");
    IupSetAttribute(dlg, "TITLE", "Load scenario");
    IupSetAttribute(dlg, "EXTFILTER", "scenario (*.txt;*.scenario)|*.txt;*.scenario|All files|*.*|");
    IupPopup(dlg, IUP_CURRENT, IUP_CURRENT);
    if (IupGetInt(dlg, "STATUS") == 0) {
        const char *path = IupGetAttribute(dlg, "VALUE");
        static char buf[CONFIG_TEXT_MAX];
        char err[MSG_BUFSIZE];
        FILE *f = fopen(path, "rb");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[n] = 0;
            if (scenarioParse(&scenario, buf, err, sizeof(err))) {
                char msg[96];
                scenarioLoaded = 1;
                snprintf(msg, sizeof(msg), "scenario: %d steps loaded", scenario.count);
                IupSetStrAttribute(scenarioLabel, "TITLE", msg);
            } else {
                scenarioLoaded = 0;
                IupSetStrAttribute(scenarioLabel, "TITLE", err);
            }
        } else {
            IupSetStrAttribute(scenarioLabel, "TITLE", "scenario: cannot open file");
        }
    }
    IupDestroy(dlg);
    return IUP_DEFAULT;
}

static int uiScenarioPlayCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    if (scenarioPlaying) {
        scenarioSetPlaying(0);
        IupSetStrAttribute(scenarioLabel, "TITLE", "scenario: stopped");
        return IUP_DEFAULT;
    }
    if (!scenarioLoaded) {
        IupSetStrAttribute(scenarioLabel, "TITLE", "scenario: load a file first");
        return IUP_DEFAULT;
    }
    scenarioStart(&scenario, clockNowUs());
    scenarioSetPlaying(1);
    return IUP_DEFAULT;
}

static int statsCanvasCb(Ihandle *canvas) {
    int w = 0, h = 0, i;
    float maxv = 1.0f;
    IupDrawBegin(canvas);
    IupDrawGetSize(canvas, &w, &h);
    IupSetAttribute(canvas, "DRAWCOLOR", "32 32 32");
    IupDrawRectangle(canvas, 0, 0, w, h);
    // grid baseline
    IupSetAttribute(canvas, "DRAWCOLOR", "64 64 64");
    IupDrawLine(canvas, 0, h - 1, w, h - 1);
    for (i = 0; i < sampleCount; ++i) {
        int idx = (sampleHead - sampleCount + i + 2 * STATS_SAMPLES) % STATS_SAMPLES;
        if (sampleSent[idx] > maxv) maxv = sampleSent[idx];
        if (sampleDrop[idx] > maxv) maxv = sampleDrop[idx];
    }
    // draw sent (green) and dropped (red) as rolling lines
    for (i = 1; i < sampleCount; ++i) {
        int a = (sampleHead - sampleCount + i - 1 + 2 * STATS_SAMPLES) % STATS_SAMPLES;
        int b = (sampleHead - sampleCount + i + 2 * STATS_SAMPLES) % STATS_SAMPLES;
        int x0 = (i - 1) * w / STATS_SAMPLES, x1 = i * w / STATS_SAMPLES;
        int ys0 = h - 1 - (int)(sampleSent[a] / maxv * (h - 4));
        int ys1 = h - 1 - (int)(sampleSent[b] / maxv * (h - 4));
        int yd0 = h - 1 - (int)(sampleDrop[a] / maxv * (h - 4));
        int yd1 = h - 1 - (int)(sampleDrop[b] / maxv * (h - 4));
        IupSetAttribute(canvas, "DRAWCOLOR", "109 170 44");
        IupDrawLine(canvas, x0, ys0, x1, ys1);
        IupSetAttribute(canvas, "DRAWCOLOR", "208 70 72");
        IupDrawLine(canvas, x0, yd0, x1, yd1);
    }
    IupDrawEnd(canvas);
    return IUP_DEFAULT;
}

static void statsSample(void) {
    int64_t now = clockNowUs();
    double dt = statsPrevUs ? (double)(now - statsPrevUs) / 1000000.0 : 0.0;
    LONG64 sent = atomicLoad64(&engineStats.sent);
    LONG64 cap = atomicLoad64(&engineStats.captured);
    LONG64 drop = 0;
    int i;
    for (i = 0; i < ruleSet.count; ++i) {
        int j;
        for (j = 0; j < ruleSet.rules[i]->moduleCount; ++j)
            drop += atomicLoad64(&ruleSet.rules[i]->modules[j]->stats.dropped);
    }
    if (dt > 0.01) {
        float sRate = (float)((double)(sent - statsPrevSent) / dt);
        float dRate = (float)((double)(drop - statsPrevDrop) / dt);
        if (sRate < 0) sRate = 0;
        if (dRate < 0) dRate = 0;
        sampleSent[sampleHead] = sRate;
        sampleDrop[sampleHead] = dRate;
        sampleHead = (sampleHead + 1) % STATS_SAMPLES;
        if (sampleCount < STATS_SAMPLES) ++sampleCount;
    }
    statsPrevSent = sent;
    statsPrevDrop = drop;
    statsPrevCap = cap;
    statsPrevUs = now;
}

static void statsRefreshText(void) {
    char buf[1024];
    LONG64 cap = atomicLoad64(&engineStats.captured);
    LONG64 sent = atomicLoad64(&engineStats.sent);
    LONG64 pass = atomicLoad64(&engineStats.passthrough);
    LONG64 sfail = atomicLoad64(&engineStats.sendFailed);
    LONG64 allocf = atomicLoad64(&engineStats.allocFailed);
    LONG64 lsum = atomicLoad64(&engineStats.latencySumUs);
    LONG64 lcnt = atomicLoad64(&engineStats.latencySamples);
    LONG ringNow = atomicLoad32(&engineStats.ringDepth);
    LONG ringMax = atomicLoad32(&engineStats.ringDepthMax);
    LONG64 lateWk = atomicLoad64(&engineStats.lateWakeups);
    double avgMs = lcnt ? (double)lsum / (double)lcnt / 1000.0 : 0.0;
    int n = snprintf(buf, sizeof(buf),
        "engine %s   high-res timer: %s\n"
        "captured: %lld   sent: %lld   passed through: %lld\n"
        "send failures: %lld   alloc failures: %lld   late wakeups: %lld\n"
        "added latency avg: %.2f ms (%lld samples)\n"
        "ring depth now/max: %ld / %ld\n\n"
        "per module (rule: module  packets/dropped/queued):\n",
        engineIsRunning() ? "running" : "stopped",
        engineHighResolutionTimer() ? "yes" : "no",
        cap, sent, pass, sfail, allocf, lateWk, avgMs, lcnt, ringNow, ringMax);
    {
        int i, j;
        for (i = 0; i < ruleSet.count && n < (int)sizeof(buf) - 1; ++i) {
            Rule *r = ruleSet.rules[i];
            for (j = 0; j < r->moduleCount && n < (int)sizeof(buf) - 1; ++j) {
                ModuleInst *m = r->modules[j];
                LONG64 pk = atomicLoad64(&m->stats.packets);
                if (!pk && !m->enabled) continue;
                n += snprintf(buf + n, sizeof(buf) - n, "  %s: %-10s %lld / %lld / %ld\n",
                              r->name, m->desc->shortName, pk,
                              atomicLoad64(&m->stats.dropped), atomicLoad32(&m->stats.queued));
            }
        }
    }
    IupSetStrAttribute(statsText, "VALUE", buf);
}

static int statsTimerCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    if (!statsOpen) return IUP_DEFAULT;
    statsSample();
    statsRefreshText();
    IupRedraw(statsCanvas, 0);
    return IUP_DEFAULT;
}

static int statsCloseCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    statsOpen = 0;
    IupSetAttribute(statsTimer, "RUN", "NO");
    return IUP_DEFAULT;
}

static int uiStatsCsvCb(Ihandle *ih) {
    Ihandle *dlg = IupFileDlg();
    UNREFERENCED_PARAMETER(ih);
    IupSetAttribute(dlg, "DIALOGTYPE", "SAVE");
    IupSetAttribute(dlg, "TITLE", "Export statistics (CSV)");
    IupSetAttribute(dlg, "EXTFILTER", "CSV|*.csv|All files|*.*|");
    IupSetAttribute(dlg, "FILE", "clumsy-stats.csv");
    IupPopup(dlg, IUP_CURRENT, IUP_CURRENT);
    if (IupGetInt(dlg, "STATUS") != -1) {
        const char *path = IupGetAttribute(dlg, "VALUE");
        FILE *f = fopen(path, "wb");
        if (f) {
            int i;
            fputs("sample,sent_per_s,dropped_per_s\n", f);
            for (i = 0; i < sampleCount; ++i) {
                int idx = (sampleHead - sampleCount + i + 2 * STATS_SAMPLES) % STATS_SAMPLES;
                fprintf(f, "%d,%.1f,%.1f\n", i, sampleSent[idx], sampleDrop[idx]);
            }
            fclose(f);
            showStatus("Exported statistics CSV.");
        } else {
            showStatus("Could not write CSV.");
        }
    }
    IupDestroy(dlg);
    return IUP_DEFAULT;
}

static int uiLogCb(Ihandle *ih) {
    if (pcapIsOpen()) {
        pcapClose();
        IupSetStrAttribute(ih, "TITLE", "Log...");
        showStatus("Stopped pcapng logging.");
        return IUP_DEFAULT;
    } else {
        Ihandle *dlg = IupFileDlg();
        IupSetAttribute(dlg, "DIALOGTYPE", "SAVE");
        IupSetAttribute(dlg, "TITLE", "Log packets to pcapng");
        IupSetAttribute(dlg, "EXTFILTER", "pcapng|*.pcapng|All files|*.*|");
        IupSetAttribute(dlg, "FILE", "clumsy.pcapng");
        IupPopup(dlg, IUP_CURRENT, IUP_CURRENT);
        if (IupGetInt(dlg, "STATUS") != -1) {
            const char *path = IupGetAttribute(dlg, "VALUE");
            if (pcapOpen(path)) {
                IupSetStrAttribute(ih, "TITLE", "Stop log");
                showStatus("Logging sent packets to pcapng. Open it in Wireshark; comments show the actions.");
            } else {
                showStatus("Could not open the pcapng file for writing.");
            }
        }
        IupDestroy(dlg);
    }
    return IUP_DEFAULT;
}

static int uiStatsCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    if (statsDialog == NULL) {
        Ihandle *csvButton, *vbox;
        statsCanvas = IupCanvas(NULL);
        IupSetAttribute(statsCanvas, "RASTERSIZE", "520x140");
        IupSetAttribute(statsCanvas, "EXPAND", "HORIZONTAL");
        IupSetCallback(statsCanvas, "ACTION", (Icallback)statsCanvasCb);
        statsText = IupText(NULL);
        IupSetAttribute(statsText, "MULTILINE", "YES");
        IupSetAttribute(statsText, "READONLY", "YES");
        IupSetAttribute(statsText, "EXPAND", "YES");
        IupSetAttribute(statsText, "VISIBLELINES", "14");
        IupSetAttribute(statsText, "VISIBLECOLUMNS", "52");
        IupSetAttribute(statsText, "FONT", "Courier, 9");
        csvButton = IupButton("Export CSV", NULL);
        IupSetCallback(csvButton, "ACTION", uiStatsCsvCb);
        vbox = IupVbox(
            IupLabel("Throughput: sent (green) and dropped (red) per second"),
            statsCanvas, statsText, csvButton, NULL);
        IupSetAttribute(vbox, "NCMARGIN", "6x6");
        IupSetAttribute(vbox, "NCGAP", "4x4");
        statsDialog = IupDialog(vbox);
        IupSetAttribute(statsDialog, "TITLE", "clumsy statistics");
        IupSetAttribute(statsDialog, "SIZE", "QUARTER");
        IupSetCallback(statsDialog, "CLOSE_CB", statsCloseCb);
    }
    statsOpen = 1;
    statsPrevUs = 0;
    statsPrevSent = statsPrevDrop = statsPrevCap = 0;
    sampleHead = sampleCount = 0;
    IupSetAttribute(statsTimer, "RUN", "YES");
    IupShow(statsDialog);
    return IUP_DEFAULT;
}

// rebuild every rule tab from the current rule set (after a config load)
static void rebuildTabs(void) {
    Ihandle *child;
    int i;
    while ((child = IupGetChild(tabs, 0)) != NULL) {
        IupDestroy(child);
    }
    for (i = 0; i < ruleSet.count; ++i) {
        ruleSet.rules[i]->tab = NULL;
        uiAddRuleTab(ruleSet.rules[i]);
    }
    IupRefresh(dialog);
}

// ---- start / stop ----
static void setRunningUi(int running) {
    int i;
    const char *active = running ? "NO" : "YES";
    for (i = 0; i < ruleSet.count; ++i) {
        IupSetAttribute(ruleSet.rules[i]->filterText, "ACTIVE", active);
    }
    IupSetAttribute(addRuleButton, "ACTIVE", active);
    IupSetAttribute(removeRuleButton, "ACTIVE", active);
    IupSetAttribute(presetList, "ACTIVE", active);
}

static int uiStartCb(Ihandle *ih) {
    char err[MSG_BUFSIZE];
    int i;
    UNREFERENCED_PARAMETER(ih);
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        const char *txt = IupGetAttribute(r->filterText, "VALUE");
        const char *proc = r->processText ? IupGetAttribute(r->processText, "VALUE") : NULL;
        snprintf(r->filter, sizeof(r->filter), "%s", txt ? txt : "");
        snprintf(r->process, sizeof(r->process), "%s", proc ? proc : "");
    }
    if (!engineStart(err, sizeof(err))) {
        showStatus(err);
        return IUP_DEFAULT;
    }
    lastSent = lastFailed = 0;
    showStatus("Started filtering. Enable functionalities to take effect.");
    setRunningUi(1);
    IupSetAttribute(startButton, "TITLE", "Stop");
    IupSetCallback(startButton, "ACTION", uiStopCb);
    IupSetAttribute(timer, "RUN", "YES");
    return IUP_DEFAULT;
}

static int uiStopCb(Ihandle *ih) {
    int i, j;
    UNREFERENCED_PARAMETER(ih);
    IupSetAttribute(startButton, "ACTIVE", "NO");
    IupFlush();
    engineStop();
    setRunningUi(0);
    IupSetAttribute(startButton, "TITLE", "Start");
    IupSetAttribute(startButton, "ACTIVE", "YES");
    IupSetCallback(startButton, "ACTION", uiStartCb);
    IupSetAttribute(timer, "RUN", "NO");
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        for (j = 0; j < r->moduleCount; ++j) {
            r->modules[j]->triggered = 0;
            IupSetAttribute(r->modules[j]->icon, "IMAGE", "none_icon");
        }
    }
    IupSetAttribute(stateIcon, "IMAGE", "none_icon");
    showStatus("Stopped. To begin again, edit criteria and click Start.");
    return IUP_DEFAULT;
}

static int uiTimerCb(Ihandle *ih) {
    int i, j;
    LONG64 sent, failed;
    UNREFERENCED_PARAMETER(ih);
    for (i = 0; i < ruleSet.count; ++i) {
        Rule *r = ruleSet.rules[i];
        for (j = 0; j < r->moduleCount; ++j) {
            ModuleInst *m = r->modules[j];
            if (atomicLoad16(&m->triggered)) {
                IupSetAttribute(m->icon, "IMAGE", "doing_icon");
                atomicAnd16(&m->triggered, 0);
            } else {
                IupSetAttribute(m->icon, "IMAGE", "none_icon");
            }
        }
    }
    sent = atomicLoad64(&engineStats.sent);
    failed = atomicLoad64(&engineStats.sendFailed);
    if (failed != lastFailed) {
        IupSetAttribute(stateIcon, "IMAGE", "error_icon");
    } else if (sent != lastSent) {
        IupSetAttribute(stateIcon, "IMAGE", "doing_icon");
    } else {
        IupSetAttribute(stateIcon, "IMAGE", "none_icon");
    }
    lastSent = sent;
    lastFailed = failed;
    return IUP_DEFAULT;
}

static int uiTimeoutCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    return IUP_CLOSE;
}

// ---- legacy command line: --filter "..." --lag on --lag-time 100 ... ----
// parse "--key value" pairs into IUP globals. Only checks the argument shape.
BOOL parseArgs(int argc, char *argv[]) {
    int ix = 0;
    char *key, *value;
    if (argc == 1) return 0;
    for (;;) {
        if (++ix >= argc) break;
        key = argv[ix];
        if (key[0] != '-' || key[1] != '-' || key[2] == '\0') {
            return 0;
        }
        key = &(key[2]);
        if (++ix >= argc) {
            return 0;
        }
        value = argv[ix];
        IupStoreGlobal(key, value);
        LOG("option: %s : %s", key, value);
    }
    return 1;
}

static int parseOnOff(const char *v, int *out) {
    if (strieq(v, "on") || strieq(v, "1") || strieq(v, "yes") || strieq(v, "true")) { *out = 1; return 1; }
    if (strieq(v, "off") || strieq(v, "0") || strieq(v, "no") || strieq(v, "false")) { *out = 0; return 1; }
    return 0;
}

static void applyLegacyArgs(void) {
    Rule *r = ruleSet.rules[0];
    char *v;
    char key[96];
    int i, j, on;
    v = IupGetGlobal("filter");
    if (v) IupStoreAttribute(r->filterText, "VALUE", v);
    for (i = 0; i < r->moduleCount; ++i) {
        ModuleInst *m = r->modules[i];
        const ModuleDesc *d = m->desc;
        v = IupGetGlobal(d->shortName);
        if (v && parseOnOff(v, &on)) moduleSetEnabled(m, on);
        for (j = 0; j < d->paramCount; ++j) {
            snprintf(key, sizeof(key), "%s-%s", d->shortName, d->params[j].name);
            v = IupGetGlobal(key);
            if (v && !moduleSetParamText(m, d->params[j].name, v)) {
                LOG("ignored invalid value for --%s: %s", key, v);
            }
        }
    }
    // the 0.3 name of the bandwidth limit
    v = IupGetGlobal("bandwidth-bandwidth");
    if (v) {
        ModuleInst *m = ruleFindModule(r, "bandwidth");
        if (m) moduleSetParamText(m, "limit", v);
    }
}

// ---- dialog ----
static BOOL check32RunningOn64(HWND hWnd) {
    BOOL is64ret;
    if (IsWow64Process(GetCurrentProcess(), &is64ret) && is64ret) {
        MessageBox(hWnd, (LPCSTR)"You're running 32bit clumsy on 64bit Windows, which wouldn't work. Please use the 64bit clumsy version.",
            (LPCSTR)"Aborting", MB_OK);
        return TRUE;
    }
    return FALSE;
}

static BOOL checkIsRunning(void) {
    HANDLE hStartEvent = CreateEventW(NULL, FALSE, FALSE, L"Global\\CLUMSY_IS_RUNNING_EVENT_NAME");
    if (hStartEvent == NULL) return TRUE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hStartEvent);
        return TRUE;
    }
    return FALSE;
}

// ---- hotkey / tray / menu callbacks (UI thread) ----
static void cbStart(void) { if (!engineIsRunning()) uiStartCb(startButton); }
static void cbStop(void) { if (engineIsRunning()) uiStopCb(startButton); }
static void cbPanic(void) {
    if (engineIsRunning()) {
        uiStopCb(startButton);
        showStatus("PANIC: filtering stopped, network restored.");
    }
}
static void cbShow(void) {
    HWND h = (HWND)IupGetAttribute(dialog, "HWND");
    if (h) { ShowWindow(h, SW_SHOW); ShowWindow(h, SW_RESTORE); SetForegroundWindow(h); }
}
static void cbQuit(void) {
    if (engineIsRunning()) engineStop();
    IupExitLoop();
}

// remote API commands arrive here on the UI thread via IupPostMessage
static int remotePostCb(Ihandle *ih, char *s, int i, double d, void *p) {
    UNREFERENCED_PARAMETER(ih);
    UNREFERENCED_PARAMETER(i);
    UNREFERENCED_PARAMETER(d);
    UNREFERENCED_PARAMETER(p);
    if (s == NULL) return IUP_DEFAULT;
    if (strieq(s, "start")) {
        cbStart();
    } else if (strieq(s, "stop")) {
        cbStop();
    } else if (strncmp(s, "filter ", 7) == 0 || strncmp(s, "process ", 8) == 0) {
        // these touch the rule's widgets, so they are handled here on the UI thread
        char buf[FILTER_BUFSIZE + 32];
        char *save = NULL, *verb, *sr, *rest;
        int ri;
        snprintf(buf, sizeof(buf), "%s", s);
        verb = strtok_s(buf, " ", &save);
        sr = strtok_s(NULL, " ", &save);
        rest = strtok_s(NULL, "", &save);   // remainder, may be NULL (clear)
        ri = sr ? atoi(sr) : -1;
        if (ri >= 0 && ri < ruleSet.count) {
            Rule *r = ruleSet.rules[ri];
            if (strieq(verb, "filter")) {
                snprintf(r->filter, sizeof(r->filter), "%s", rest ? rest : "");
                if (r->filterText) IupStoreAttribute(r->filterText, "VALUE", r->filter);
                updateFilterStatus(r);
            } else {
                snprintf(r->process, sizeof(r->process), "%s", rest ? rest : "");
                if (r->processText) IupStoreAttribute(r->processText, "VALUE", r->process);
            }
            engineWake();
        }
    } else {
        remoteApplyCommand(s);
    }
    return IUP_DEFAULT;
}

static void remoteEnqueueToUi(const char *cmd) {
    if (dialog) IupPostMessage(dialog, cmd, 0, 0.0, NULL);
}

static int uiDiagnoseCb(Ihandle *ih) {
    char msg[MSG_BUFSIZE];
    UNREFERENCED_PARAMETER(ih);
    safetyDriverStatus(msg, sizeof(msg));
    IupMessage("Driver diagnosis", msg);
    return IUP_DEFAULT;
}

static int uiRemoveSvcCb(Ihandle *ih) {
    char msg[MSG_BUFSIZE];
    UNREFERENCED_PARAMETER(ih);
    if (engineIsRunning()) {
        IupMessage("WinDivert service", "Stop filtering first.");
        return IUP_DEFAULT;
    }
    if (IupAlarm("Remove WinDivert service",
                 "Stop and remove the WinDivert driver service?\n"
                 "A clean copy installs automatically the next time you Start.\n"
                 "Use this if Start fails with a driver error.",
                 "Remove", "Cancel", NULL) != 1) {
        return IUP_DEFAULT;
    }
    safetyRemoveDriverService(msg, sizeof(msg));
    IupMessage("WinDivert service", msg);
    return IUP_DEFAULT;
}

static int uiCliHelpCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    IupMessage("Command line",
        "clumsy accepts command-line options, for example:\n\n"
        "  clumsy --filter \"udp and outbound\" --lag on --lag-time 100 --start on\n"
        "  clumsy --profile 3G --start on --timeout 30\n"
        "  clumsy --load myconfig.clumsy --headless on\n\n"
        "Run  clumsy --help  or  --list  in a terminal for the full reference.");
    return IUP_DEFAULT;
}

static int uiAboutCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    IupMessage("About clumsy",
        "clumsy " CLUMSY_VERSION "\n"
        "Interactive network condition simulator built on WinDivert.\n\n"
        "Hotkeys: F5 start, F6 stop, Ctrl+Alt+F12 panic restore.");
    return IUP_DEFAULT;
}

static Ihandle *buildMenu(void) {
    Ihandle *tools, *help, *bar;
    Ihandle *mDiagnose, *mRemove, *mCliHelp, *mAbout;
    mDiagnose = IupItem("Diagnose driver", NULL);
    IupSetCallback(mDiagnose, "ACTION", uiDiagnoseCb);
    mRemove = IupItem("Remove WinDivert service", NULL);
    IupSetCallback(mRemove, "ACTION", uiRemoveSvcCb);
    tools = IupSubmenu("Tools", IupMenu(mDiagnose, mRemove, NULL));
    mCliHelp = IupItem("Command-line help", NULL);
    IupSetCallback(mCliHelp, "ACTION", uiCliHelpCb);
    mAbout = IupItem("About", NULL);
    IupSetCallback(mAbout, "ACTION", uiAboutCb);
    help = IupSubmenu("Help", IupMenu(mCliHelp, mAbout, NULL));
    bar = IupMenu(tools, help, NULL);
    return bar;
}

static int uiOnDialogShow(Ihandle *ih, int state) {
    HWND hWnd;
    BOOL exit;
    HICON icon;
    HINSTANCE hInstance;
    if (state != IUP_SHOW) return IUP_DEFAULT;
    dialogMapped = 1;
    hWnd = (HWND)IupGetAttribute(ih, "HWND");
    hInstance = GetModuleHandle(NULL);

    icon = LoadIcon(hInstance, "CLUMSY_ICON");
    SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)icon);
    SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)icon);

    if (checkIsRunning()) {
        MessageBox(hWnd, (LPCSTR)"There's already an instance of clumsy running.", (LPCSTR)"Aborting", MB_OK);
        return IUP_CLOSE;
    }
    if (check32RunningOn64(hWnd)) {
        return IUP_CLOSE;
    }

    exit = tryElevate(hWnd, parameterized);
    if (!exit) {
        WinUiCallbacks cb;
        cb.start = cbStart;
        cb.stop = cbStop;
        cb.panic = cbPanic;
        cb.showWindow = cbShow;
        cb.quit = cbQuit;
        winuiInstall(hWnd, hInstance, &cb);
    }
    if (!exit && startOnShow) {
        LOG("auto-start requested, begin filtering");
        uiStartCb(startButton);
    }
    return exit ? IUP_CLOSE : IUP_DEFAULT;
}

static void init(int argc, char *argv[]) {
    Ihandle *topFrame, *controlHbox, *dialogVBox, *noneIcon, *doingIcon, *errorIcon, *presetLabel;
    UINT ix;
    char *argValue;

    CliOptions opt;

    loadConfig();
    IupOpen(&argc, &argv);
    uiInstallHooks();

    LOG("argc: %d", argc);
    if (argc > 1) {
        if (!parseArgs(argc, argv)) {
            fprintf(stderr, "invalid argument count. ensure you're using options as \"--drop on\"\n");
            exit(-1);
        }
        parameterized = 1;
    }

    cliReadOptions(&opt);
    if (opt.haveSeed) rngSeed(opt.seed);
    headlessMode = opt.headless;
    startOnShow = parameterized || opt.autostart;
    if (opt.loadPath) {
        char err[MSG_BUFSIZE];
        if (!configLoad(opt.loadPath, err, sizeof(err))) {   // hook not set yet: no UI rebuild
            LOG("--load failed: %s", err);
        }
    }
    if (ruleSet.count == 0) {
        ruleSetAdd(ruleCreate("Rule 1", filters[0].filterValue));
    }
    if (opt.profile) {
        int pi, found = -1;
        for (pi = 0; pi < profileCount(); ++pi) {
            if (strieq(profileName(pi), opt.profile)) { found = pi; break; }
        }
        if (found >= 0) configApplyFragment(ruleSet.rules[0], profileText(found));
        else LOG("unknown profile: %s", opt.profile);
    }

    statusLabel = IupLabel("NOTICE: When capturing localhost (loopback) packets, you CAN'T include inbound criteria.\n"
        "Filters like 'udp' need to be 'udp and outbound' to work. See readme for more info.");
    IupSetAttribute(statusLabel, "EXPAND", "HORIZONTAL");
    IupSetAttribute(statusLabel, "PADDING", "8x8");

    noneIcon = IupImage(8, 8, icon8x8);
    doingIcon = IupImage(8, 8, icon8x8);
    errorIcon = IupImage(8, 8, icon8x8);
    IupSetAttribute(noneIcon, "0", "BGCOLOR");
    IupSetAttribute(noneIcon, "1", "224 224 224");
    IupSetAttribute(doingIcon, "0", "BGCOLOR");
    IupSetAttribute(doingIcon, "1", "109 170 44");
    IupSetAttribute(errorIcon, "0", "BGCOLOR");
    IupSetAttribute(errorIcon, "1", "208 70 72");
    IupSetHandle("none_icon", noneIcon);
    IupSetHandle("doing_icon", doingIcon);
    IupSetHandle("error_icon", errorIcon);

    stateIcon = IupLabel(NULL);
    IupSetAttribute(stateIcon, "IMAGE", "none_icon");
    IupSetAttribute(stateIcon, "PADDING", "4x");
    startButton = IupButton("Start", NULL);
    IupSetAttribute(startButton, "PADDING", "8x");
    IupSetCallback(startButton, "ACTION", uiStartCb);

    presetLabel = IupLabel("Presets:");
    presetList = IupList(NULL);
    IupSetAttribute(presetList, "VISIBLECOLUMNS", "20");
    IupSetAttribute(presetList, "DROPDOWN", "YES");
    for (ix = 0; ix < filtersSize; ++ix) {
        char ixBuf[8];
        snprintf(ixBuf, sizeof(ixBuf), "%u", ix + 1);
        IupStoreAttribute(presetList, ixBuf, filters[ix].filterName);
    }
    IupSetAttribute(presetList, "VALUE", "1");
    IupSetCallback(presetList, "ACTION", (Icallback)uiListSelectCb);

    addRuleButton = IupButton("Add rule", NULL);
    IupSetAttribute(addRuleButton, "PADDING", "4x");
    IupSetCallback(addRuleButton, "ACTION", uiAddRuleCb);
    removeRuleButton = IupButton("Remove rule", NULL);
    IupSetAttribute(removeRuleButton, "PADDING", "4x");
    IupSetCallback(removeRuleButton, "ACTION", uiRemoveRuleCb);
    advancedToggle = IupToggle("Advanced", NULL);
    IupSetCallback(advancedToggle, "ACTION", (Icallback)uiAdvancedCb);

    profileList = IupList(NULL);
    IupSetAttribute(profileList, "DROPDOWN", "YES");
    IupSetAttribute(profileList, "VISIBLECOLUMNS", "16");
    for (ix = 0; ix < (UINT)profileCount(); ++ix) {
        char key[8];
        snprintf(key, sizeof(key), "%u", ix + 1);
        IupStoreAttribute(profileList, key, profileName((int)ix));
    }
    IupSetAttribute(profileList, "TIP", "Apply a link profile to the current rule");
    IupSetCallback(profileList, "ACTION", (Icallback)uiProfileCb);

    saveButton = IupButton("Save", NULL);
    IupSetAttribute(saveButton, "PADDING", "4x");
    IupSetCallback(saveButton, "ACTION", uiSaveCb);
    loadButton = IupButton("Load", NULL);
    IupSetAttribute(loadButton, "PADDING", "4x");
    IupSetCallback(loadButton, "ACTION", uiLoadCb);
    statsButton = IupButton("Stats", NULL);
    IupSetAttribute(statsButton, "PADDING", "4x");
    IupSetCallback(statsButton, "ACTION", uiStatsCb);
    logButton = IupButton("Log...", NULL);
    IupSetAttribute(logButton, "PADDING", "4x");
    IupSetCallback(logButton, "ACTION", uiLogCb);

    controlHbox = IupHbox(stateIcon, startButton, IupFill(),
                          IupLabel("Profile:"), profileList,
                          saveButton, loadButton, statsButton, logButton, addRuleButton, removeRuleButton, advancedToggle, NULL);
    IupSetAttribute(controlHbox, "ALIGNMENT", "ACENTER");
    IupSetAttribute(controlHbox, "GAP", "4");
    IupSetAttribute(controlHbox, "NCMARGIN", "4x4");
    topFrame = IupFrame(controlHbox);
    IupSetAttribute(topFrame, "TITLE", "Control");
    IupSetAttribute(topFrame, "EXPAND", "HORIZONTAL");

    tabs = IupTabs(NULL);
    IupSetAttribute(tabs, "EXPAND", "YES");

    for (ix = 0; ix < (UINT)ruleSet.count; ++ix) {
        uiAddRuleTab(ruleSet.rules[ix]);
    }

    scenarioLoadButton = IupButton("Load scenario", NULL);
    IupSetAttribute(scenarioLoadButton, "PADDING", "4x");
    IupSetCallback(scenarioLoadButton, "ACTION", uiScenarioLoadCb);
    scenarioButton = IupButton("Play scenario", NULL);
    IupSetAttribute(scenarioButton, "PADDING", "4x");
    IupSetCallback(scenarioButton, "ACTION", uiScenarioPlayCb);
    scenarioLabel = IupLabel("scenario: none");
    IupSetAttribute(scenarioLabel, "EXPAND", "HORIZONTAL");

    dialog = IupDialog(
        dialogVBox = IupVbox(
            topFrame,
            tabs,
            IupHbox(scenarioLoadButton, scenarioButton, scenarioLabel, NULL),
            statusLabel,
            NULL
        )
    );
    IupSetAttribute(dialog, "TITLE", "clumsy " CLUMSY_VERSION);
    IupSetAttribute(dialog, "SIZE", "640x");
    IupSetAttribute(dialog, "RESIZE", "YES");
    IupSetAttributeHandle(dialog, "MENU", buildMenu());
    IupSetCallback(dialog, "SHOW_CB", (Icallback)uiOnDialogShow);
    IupSetAttribute(dialogVBox, "ALIGNMENT", "ACENTER");
    IupSetAttribute(dialogVBox, "NCMARGIN", "4x4");
    IupSetAttribute(dialogVBox, "NCGAP", "4x2");

    timer = IupTimer();
    IupSetAttribute(timer, "TIME", STR(ICON_UPDATE_MS));
    IupSetCallback(timer, "ACTION_CB", uiTimerCb);

    scenarioTimer = IupTimer();
    IupSetAttribute(scenarioTimer, "TIME", "100");
    IupSetCallback(scenarioTimer, "ACTION_CB", uiScenarioTickCb);

    statsTimer = IupTimer();
    IupSetAttribute(statsTimer, "TIME", "250");
    IupSetCallback(statsTimer, "ACTION_CB", statsTimerCb);

    argValue = IupGetGlobal("timeout");
    if (argValue != NULL) {
        char valueBuf[16];
        snprintf(valueBuf, sizeof(valueBuf), "%s000", argValue); // seconds to milliseconds
        timeoutTimer = IupTimer();
        IupStoreAttribute(timeoutTimer, "TIME", valueBuf);
        IupSetCallback(timeoutTimer, "ACTION_CB", uiTimeoutCb);
        IupSetAttribute(timeoutTimer, "RUN", "YES");
    }

    if (parameterized) {
        applyLegacyArgs();
    }
    configRebuildUiHook = rebuildTabs;   // enable UI rebuilds now the dialog exists

    if (opt.api) {
        static char token[24];
        char err[MSG_BUFSIZE];
        IupSetCallback(dialog, "POSTMESSAGE_CB", (Icallback)remotePostCb);
        if (opt.apiToken && opt.apiToken[0]) {
            snprintf(token, sizeof(token), "%s", opt.apiToken);
        } else {
            snprintf(token, sizeof(token), "%08x%08x", (unsigned)rngNext(), (unsigned)rngNext());
        }
        if (remoteStart(opt.apiPort, token, remoteEnqueueToUi, err, sizeof(err))) {
            char msg[MSG_BUFSIZE];
            snprintf(msg, sizeof(msg), "Remote API on http://127.0.0.1:%d  token: %s", opt.apiPort, token);
            LOG("%s", msg);
            showStatus(msg);
        } else {
            LOG("remote API failed: %s", err);
        }
    }
}

// headless: never show the window. Elevate silently (must already be admin),
// start filtering, and pump the IUP loop so timers run until timeout or kill.
static int headlessTimeoutCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    headlessStop = 1;
    return IUP_CLOSE;
}

static void runHeadless(void) {
    char err[MSG_BUFSIZE];
    char *to;
    if (tryElevate(NULL, TRUE)) {
        LOG("headless requires running as Administrator");
        return;
    }
    if (!engineStart(err, sizeof(err))) {
        LOG("headless start failed: %s", err);
        return;
    }
    to = IupGetGlobal("timeout");
    if (to) {
        char ms[16];
        Ihandle *t = IupTimer();
        snprintf(ms, sizeof(ms), "%s000", to);
        IupStoreAttribute(t, "TIME", ms);
        IupSetCallback(t, "ACTION_CB", headlessTimeoutCb);
        IupSetAttribute(t, "RUN", "YES");
    }
    LOG("headless running");
    while (!headlessStop && IupLoopStepWait() != IUP_CLOSE) {
        /* pump timers and the engine's UI-thread work */
    }
    engineStop();
}

int main(int argc, char *argv[]) {
    cliMaybeExit(argc, argv);   // --help / --version / --list exit here
    clockInit();
    packetPoolInit();
    rngSeed(0);
    LOG("Is Run As Admin: %d", IsRunAsAdmin());
    LOG("Is Elevated: %d", IsElevated());
    init(argc, argv);

    if (headlessMode) {
        runHeadless();
    } else {
        IupShowXY(dialog, IUP_CENTER, IUP_CENTER);
        IupMainLoop();
    }

    winuiShutdown();
    if (remoteRunning()) {
        remoteStop();
    }
    if (engineIsRunning()) {
        engineStop();
    }
    pcapClose();
    IupDestroy(timer);
    if (scenarioTimer) IupDestroy(scenarioTimer);
    if (statsTimer) IupDestroy(statsTimer);
    if (statsDialog) IupDestroy(statsDialog);
    if (timeoutTimer) IupDestroy(timeoutTimer);
    IupClose();
    endTimePeriod();
    ruleSetClear();
    packetPoolShutdown();
    logShutdown();
    return 0;
}
