#include "safety.h"
#include <stdlib.h>

#define WINDIVERT_SERVICE "WinDivert"

static const char *stateName(DWORD s) {
    switch (s) {
    case SERVICE_STOPPED:          return "stopped";
    case SERVICE_START_PENDING:    return "starting";
    case SERVICE_STOP_PENDING:     return "stopping";
    case SERVICE_RUNNING:          return "running";
    case SERVICE_CONTINUE_PENDING: return "resuming";
    case SERVICE_PAUSE_PENDING:    return "pausing";
    case SERVICE_PAUSED:           return "paused";
    default:                       return "unknown";
    }
}

void safetyDriverStatus(char *msg, size_t size) {
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        snprintf(msg, size, "Cannot open the service manager (%lu). Run as Administrator.", GetLastError());
        return;
    }
    svc = OpenService(scm, (LPCSTR)WINDIVERT_SERVICE, SERVICE_QUERY_STATUS);
    if (svc == NULL) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) {
            snprintf(msg, size, "WinDivert service: not installed (a clean copy installs on Start).");
        } else {
            snprintf(msg, size, "WinDivert service: cannot query (%lu).", e);
        }
        CloseServiceHandle(scm);
        return;
    }
    if (QueryServiceStatus(svc, &st)) {
        snprintf(msg, size, "WinDivert service: %s. %s",
                 stateName(st.dwCurrentState),
                 st.dwCurrentState == SERVICE_RUNNING
                     ? "If Start fails, use Remove WinDivert service, then Start again."
                     : "This is normal.");
    } else {
        snprintf(msg, size, "WinDivert service: present, state query failed (%lu).", GetLastError());
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

int safetyRemoveDriverService(char *msg, size_t size) {
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    DWORD e;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        snprintf(msg, size, "Cannot open the service manager (%lu). Run as Administrator.", GetLastError());
        return 0;
    }
    svc = OpenService(scm, (LPCSTR)WINDIVERT_SERVICE, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (svc == NULL) {
        e = GetLastError();
        CloseServiceHandle(scm);
        if (e == ERROR_SERVICE_DOES_NOT_EXIST) {
            snprintf(msg, size, "WinDivert service is not installed; nothing to remove.");
            return 1;
        }
        snprintf(msg, size, "Cannot open the WinDivert service (%lu). Run as Administrator.", e);
        return 0;
    }
    // best-effort stop, then delete
    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        Sleep(300);
    }
    if (DeleteService(svc)) {
        snprintf(msg, size, "Removed the WinDivert service. A clean copy installs next time you Start.");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 1;
    }
    e = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (e == ERROR_SERVICE_MARKED_FOR_DELETE) {
        snprintf(msg, size, "The service is marked for deletion; reboot to finish removing it.");
        return 1;
    }
    snprintf(msg, size, "Could not delete the WinDivert service (%lu).", e);
    return 0;
}
