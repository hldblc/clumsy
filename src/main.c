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
static int dialogMapped = 0;
static int ruleSerial = 1;
static LONG64 lastSent = 0, lastFailed = 0;

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

static int uiFilterTextCb(Ihandle *ih) {
    UNREFERENCED_PARAMETER(ih);
    IupSetAttribute(presetList, "VALUE", "0");
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
    Ihandle *modulesVbox, *functionsFrame, *tab, *label, *tabBox;
    int i;

    label = IupLabel("Filter:");
    filterText = IupText(NULL);
    IupSetAttribute(filterText, "EXPAND", "HORIZONTAL");
    IupStoreAttribute(filterText, "VALUE", r->filter);
    IupSetCallback(filterText, "VALUECHANGED_CB", uiFilterTextCb);
    enabledToggle = IupToggle("Enabled", NULL);
    IupSetAttribute(enabledToggle, "VALUE", r->enabled ? "ON" : "OFF");
    IupSetAttribute(enabledToggle, "_CLUMSY_RULE", (char *)r);
    IupSetCallback(enabledToggle, "ACTION", (Icallback)uiRuleEnabledCb);
    filterRow = IupHbox(label, filterText, enabledToggle, NULL);
    IupSetAttribute(filterRow, "ALIGNMENT", "ACENTER");
    IupSetAttribute(filterRow, "GAP", "4");

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

    tabBox = IupVbox(filterRow, procRow, functionsFrame, NULL);
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
    if (!exit && parameterized) {
        LOG("parameterized, start filtering immediately");
        uiStartCb(startButton);
    }
    return exit ? IUP_CLOSE : IUP_DEFAULT;
}

static void init(int argc, char *argv[]) {
    Ihandle *topFrame, *controlHbox, *dialogVBox, *noneIcon, *doingIcon, *errorIcon, *presetLabel;
    Rule *first;
    UINT ix;
    char *argValue;

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

    controlHbox = IupHbox(stateIcon, startButton, IupFill(), presetLabel, presetList, addRuleButton, removeRuleButton, advancedToggle, NULL);
    IupSetAttribute(controlHbox, "ALIGNMENT", "ACENTER");
    IupSetAttribute(controlHbox, "GAP", "4");
    IupSetAttribute(controlHbox, "NCMARGIN", "4x4");
    topFrame = IupFrame(controlHbox);
    IupSetAttribute(topFrame, "TITLE", "Control");
    IupSetAttribute(topFrame, "EXPAND", "HORIZONTAL");

    tabs = IupTabs(NULL);
    IupSetAttribute(tabs, "EXPAND", "YES");

    first = ruleCreate("Rule 1", filters[0].filterValue);
    ruleSetAdd(first);
    uiAddRuleTab(first);

    dialog = IupDialog(
        dialogVBox = IupVbox(
            topFrame,
            tabs,
            statusLabel,
            NULL
        )
    );
    IupSetAttribute(dialog, "TITLE", "clumsy " CLUMSY_VERSION);
    IupSetAttribute(dialog, "SIZE", "640x");
    IupSetAttribute(dialog, "RESIZE", "YES");
    IupSetCallback(dialog, "SHOW_CB", (Icallback)uiOnDialogShow);
    IupSetAttribute(dialogVBox, "ALIGNMENT", "ACENTER");
    IupSetAttribute(dialogVBox, "NCMARGIN", "4x4");
    IupSetAttribute(dialogVBox, "NCGAP", "4x2");

    timer = IupTimer();
    IupSetAttribute(timer, "TIME", STR(ICON_UPDATE_MS));
    IupSetCallback(timer, "ACTION_CB", uiTimerCb);

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
}

int main(int argc, char *argv[]) {
    clockInit();
    packetPoolInit();
    rngSeed(0);
    LOG("Is Run As Admin: %d", IsRunAsAdmin());
    LOG("Is Elevated: %d", IsElevated());
    init(argc, argv);

    IupShowXY(dialog, IUP_CENTER, IUP_CENTER);
    IupMainLoop();

    if (engineIsRunning()) {
        engineStop();
    }
    IupDestroy(timer);
    if (timeoutTimer) IupDestroy(timeoutTimer);
    IupClose();
    endTimePeriod();
    ruleSetClear();
    packetPoolShutdown();
    logShutdown();
    return 0;
}
