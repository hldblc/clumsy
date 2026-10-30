#include "winui.h"
#include <shellapi.h>

#define HK_START 0xC1A1
#define HK_STOP  0xC1A2
#define HK_PANIC 0xC1A3

#define TRAY_MSG      (WM_APP + 17)
#define TRAY_ICON_ID  1

#define CMD_SHOW  0x3001
#define CMD_START 0x3002
#define CMD_STOP  0x3003
#define CMD_PANIC 0x3004
#define CMD_EXIT  0x3005

static HWND mainHwnd = NULL;
static WNDPROC prevProc = NULL;
static WinUiCallbacks cbs;
static NOTIFYICONDATA nid;
static int trayAdded = 0;

static void call(void (*fn)(void)) { if (fn) fn(); }

static void showTrayMenu(void) {
    HMENU m = CreatePopupMenu();
    POINT pt;
    if (m == NULL) return;
    AppendMenu(m, MF_STRING, CMD_SHOW, (LPCSTR)"Show clumsy");
    AppendMenu(m, MF_SEPARATOR, 0, NULL);
    AppendMenu(m, MF_STRING, CMD_START, (LPCSTR)"Start (F5)");
    AppendMenu(m, MF_STRING, CMD_STOP, (LPCSTR)"Stop (F6)");
    AppendMenu(m, MF_STRING, CMD_PANIC, (LPCSTR)"Panic restore (Ctrl+Alt+F12)");
    AppendMenu(m, MF_SEPARATOR, 0, NULL);
    AppendMenu(m, MF_STRING, CMD_EXIT, (LPCSTR)"Exit");
    GetCursorPos(&pt);
    SetForegroundWindow(mainHwnd);   // so the menu dismisses on focus loss
    TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, mainHwnd, NULL);
    DestroyMenu(m);
}

static LRESULT CALLBACK subclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_HOTKEY:
        if (wParam == HK_START) call(cbs.start);
        else if (wParam == HK_STOP) call(cbs.stop);
        else if (wParam == HK_PANIC) call(cbs.panic);
        return 0;
    case TRAY_MSG:
        if (lParam == WM_LBUTTONDBLCLK) {
            call(cbs.showWindow);
        } else if (lParam == WM_RBUTTONUP) {
            showTrayMenu();
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case CMD_SHOW:  call(cbs.showWindow); return 0;
        case CMD_START: call(cbs.start); return 0;
        case CMD_STOP:  call(cbs.stop); return 0;
        case CMD_PANIC: call(cbs.panic); return 0;
        case CMD_EXIT:  call(cbs.quit); return 0;
        default: break;
        }
        break;
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED && trayAdded) {
            ShowWindow(hwnd, SW_HIDE);   // minimize to tray
            return 0;
        }
        break;
    default:
        break;
    }
    return CallWindowProc(prevProc, hwnd, msg, wParam, lParam);
}

void winuiInstall(HWND hwnd, HINSTANCE hinst, const WinUiCallbacks *cb) {
    mainHwnd = hwnd;
    cbs = *cb;

    RegisterHotKey(hwnd, HK_START, 0, VK_F5);
    RegisterHotKey(hwnd, HK_STOP, 0, VK_F6);
    RegisterHotKey(hwnd, HK_PANIC, MOD_CONTROL | MOD_ALT, VK_F12);

    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = TRAY_MSG;
    nid.hIcon = LoadIcon(hinst, (LPCSTR)"CLUMSY_ICON");
    if (nid.hIcon == NULL) nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    lstrcpyn(nid.szTip, (LPCSTR)"clumsy", (int)sizeof(nid.szTip));
    trayAdded = Shell_NotifyIcon(NIM_ADD, &nid) ? 1 : 0;

    prevProc = (WNDPROC)SetWindowLongPtr(hwnd, GWLP_WNDPROC, (LONG_PTR)subclassProc);
}

void winuiShutdown(void) {
    if (mainHwnd == NULL) return;
    UnregisterHotKey(mainHwnd, HK_START);
    UnregisterHotKey(mainHwnd, HK_STOP);
    UnregisterHotKey(mainHwnd, HK_PANIC);
    if (trayAdded) {
        Shell_NotifyIcon(NIM_DELETE, &nid);
        trayAdded = 0;
    }
    if (prevProc) {
        SetWindowLongPtr(mainHwnd, GWLP_WNDPROC, (LONG_PTR)prevProc);
        prevProc = NULL;
    }
    mainHwnd = NULL;
}

void winuiSetTip(const char *tip) {
    if (!trayAdded) return;
    nid.uFlags = NIF_TIP;
    lstrcpyn(nid.szTip, (LPCSTR)tip, (int)sizeof(nid.szTip));
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}
