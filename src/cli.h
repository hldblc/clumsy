// Command line front end. Handles --help / --version / --list before the GUI
// starts and exposes the parsed options the rest of startup reads. Roadmap 17.
#pragma once
#include "common.h"

typedef struct {
    int headless;        // run without showing the window
    int autostart;       // start filtering on launch
    int haveSeed;
    uint64_t seed;
    const char *loadPath; // --load <file>, or NULL
    const char *profile;  // --profile <name>, or NULL
} CliOptions;

// Handle --help/--version/--list and exit the process if one was given.
// Returns only when normal startup should continue.
void cliMaybeExit(int argc, char *argv[]);

// Read the structured options from the IUP globals set by parseArgs.
void cliReadOptions(CliOptions *opt);
