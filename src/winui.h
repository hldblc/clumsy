// Global hotkeys and a tray icon (roadmap item 20). Subclasses the main
// window to handle WM_HOTKEY and the tray notifications. All callbacks run on
// the UI thread, so they may touch IUP and the engine directly.
//
//   F5            start filtering
//   F6            stop filtering
//   Ctrl+Alt+F12  panic: stop and restore the network at once
#pragma once
#include "common.h"

typedef struct {
    void (*start)(void);
    void (*stop)(void);
    void (*panic)(void);
    void (*showWindow)(void);
    void (*quit)(void);
} WinUiCallbacks;

void winuiInstall(HWND hwnd, HINSTANCE hinst, const WinUiCallbacks *cb);
void winuiShutdown(void);
void winuiSetTip(const char *tip);
