#include "cli.h"
#include "rules.h"
#include "profiles.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "iup.h"

// Release builds are a windowed subsystem app with no console. When launched
// from a terminal, attach to it so --help / --version / --list print there;
// otherwise fall back to a message box.
static int consoleReady = 0;
static int consoleIsOurs = 0;

static void ensureConsole(void) {
    if (consoleReady) return;
    if (GetConsoleWindow() != NULL) {
        consoleReady = 1;
        return;
    }
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        consoleReady = 1;
        consoleIsOurs = 1;
    }
}

static void outText(const char *text) {
    ensureConsole();   // windowed build: attach to the launching terminal if any
    // a console build (or an attached terminal) has a working stdout; use it.
    if (fputs(text, stdout) >= 0) {
        fflush(stdout);
        return;
    }
    // truly no console (double-clicked windowed build): fall back to a box
    MessageBox(NULL, (LPCSTR)text, (LPCSTR)"clumsy", MB_OK);
}

static void buildUsage(char *buf, size_t size) {
    size_t used = 0;
    int i, j;
#define OUT(...) do { int w = snprintf(buf + used, size - used, __VA_ARGS__); if (w > 0 && (size_t)w < size - used) used += (size_t)w; } while (0)
    OUT("clumsy %s - interactive network condition simulator\n\n", CLUMSY_VERSION);
    OUT("Usage: clumsy [options]\n\n");
    OUT("General:\n");
    OUT("  --help                 show this help and exit\n");
    OUT("  --version              show the version and exit\n");
    OUT("  --list                 list modules, parameters and profiles\n");
    OUT("  --seed <n>             fix the random seed for reproducible runs\n");
    OUT("  --timeout <seconds>    auto-close after this long\n");
    OUT("  --load <file.clumsy>   load a saved configuration\n");
    OUT("  --profile <name>       apply a link profile to the first rule\n");
    OUT("  --headless on          run without showing the window (must be elevated)\n");
    OUT("  --start on             begin filtering on launch\n");
    OUT("  --api on               start the loopback control API (127.0.0.1)\n");
    OUT("  --api-port <n>         API port (default 8998)\n");
    OUT("  --api-token <t>        API token (auto-generated if omitted)\n\n");
    OUT("Single-rule shortcuts (the classic form):\n");
    OUT("  --filter \"<expr>\"      set the capture filter\n");
    OUT("  --<module> on|off      enable a module (e.g. --lag on)\n");
    OUT("  --<module>-<param> <v> set a parameter (e.g. --lag-time 100, --drop-chance 5)\n");
    OUT("                         per-direction values accept in/out, e.g. 20/80\n\n");
    OUT("Example:\n");
    OUT("  clumsy --filter \"udp and outbound\" --lag on --lag-time 100 --start on --timeout 30\n");
#undef OUT
}

static void buildList(char *buf, size_t size) {
    size_t used = 0;
    int i, j, p;
#define OUT(...) do { int w = snprintf(buf + used, size - used, __VA_ARGS__); if (w > 0 && (size_t)w < size - used) used += (size_t)w; } while (0)
    OUT("Modules and parameters:\n");
    for (i = 0; i < moduleDescCount; ++i) {
        const ModuleDesc *d = moduleDescs[i];
        OUT("  %-10s %s\n", d->shortName, d->displayName);
        for (j = 0; j < d->paramCount; ++j) {
            const ParamDesc *pd = &d->params[j];
            char range[64] = "";
            if (pd->type == PT_ENUM) {
                int n = paramEnumCount(pd), k;
                size_t ru = 0;
                for (k = 0; k < n; ++k) {
                    char nm[32];
                    paramEnumName(pd, k, nm, sizeof(nm));
                    ru += (size_t)snprintf(range + ru, sizeof(range) - ru, k ? "|%s" : "%s", nm);
                    if (ru >= sizeof(range)) break;
                }
            } else if (pd->type == PT_BOOL) {
                snprintf(range, sizeof(range), "on|off");
            } else {
                snprintf(range, sizeof(range), "%d..%d", pd->min, pd->max);
            }
            OUT("      --%s-%-10s %s%s\n", d->shortName, pd->name, range,
                (pd->flags & PF_PERDIR) ? "  (per-direction, in/out)" : "");
        }
    }
    OUT("\nProfiles (--profile <name>):\n");
    for (p = 0; p < profileCount(); ++p) {
        OUT("  %s\n", profileName(p));
    }
#undef OUT
}

static int hasFlag(int argc, char *argv[], const char *a, const char *b) {
    int i;
    for (i = 1; i < argc; ++i) {
        if (strieq(argv[i], a) || (b && strieq(argv[i], b))) return 1;
    }
    return 0;
}

void cliMaybeExit(int argc, char *argv[]) {
    static char buf[8192];
    if (hasFlag(argc, argv, "--help", "-h") || hasFlag(argc, argv, "/?", NULL)) {
        buildUsage(buf, sizeof(buf));
        outText(buf);
        exit(0);
    }
    if (hasFlag(argc, argv, "--version", "-v")) {
        snprintf(buf, sizeof(buf), "clumsy %s\n", CLUMSY_VERSION);
        outText(buf);
        exit(0);
    }
    if (hasFlag(argc, argv, "--list", NULL)) {
        buildList(buf, sizeof(buf));
        outText(buf);
        exit(0);
    }
}

void cliReadOptions(CliOptions *opt) {
    char *v;
    memset(opt, 0, sizeof(*opt));
    v = IupGetGlobal("seed");
    if (v) { opt->haveSeed = 1; opt->seed = (uint64_t)_strtoui64(v, NULL, 10); }
    v = IupGetGlobal("headless");
    if (v && (strieq(v, "on") || strieq(v, "1") || strieq(v, "yes"))) opt->headless = 1;
    v = IupGetGlobal("start");
    if (v && (strieq(v, "on") || strieq(v, "1") || strieq(v, "yes"))) opt->autostart = 1;
    opt->loadPath = IupGetGlobal("load");
    opt->profile = IupGetGlobal("profile");
    v = IupGetGlobal("api");
    if (v && (strieq(v, "on") || strieq(v, "1") || strieq(v, "yes"))) opt->api = 1;
    v = IupGetGlobal("api-port");
    opt->apiPort = v ? atoi(v) : 8998;
    if (opt->apiPort <= 0 || opt->apiPort > 65535) opt->apiPort = 8998;
    opt->apiToken = IupGetGlobal("api-token");
}
