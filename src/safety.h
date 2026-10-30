// Driver diagnostics and recovery. The WinDivert kernel service can get stuck
// (left running by a crashed program, blocked, or a mismatched version), which
// is the cause behind the common "failed to open device" reports. These helpers
// report its state and can stop + remove it so a clean copy installs next run.
// Roadmap item 23.
#pragma once
#include "common.h"

// Write a human-readable description of the WinDivert service state into msg.
void safetyDriverStatus(char *msg, size_t size);

// Stop and delete the WinDivert service. Needs Administrator. 1 on success.
int  safetyRemoveDriverService(char *msg, size_t size);
