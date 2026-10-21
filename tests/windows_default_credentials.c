/* Development-only default-SSPI test launcher, equivalent to runas /netonly.
 * Explicit lab credentials are read from EWR_NETONLY_USER/DOMAIN/PASSWORD.
 * Only the new child's logon session receives these outbound credentials.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int required_environment(const wchar_t *name, wchar_t *buffer, DWORD capacity) {
    DWORD length = GetEnvironmentVariableW(name, buffer, capacity);
    return length > 0 && length < capacity;
}

int wmain(void) {
    wchar_t user[512], domain[512], password[1024], command[32768];
    if (!required_environment(L"EWR_NETONLY_USER", user, 512) ||
        !required_environment(L"EWR_NETONLY_DOMAIN", domain, 512) ||
        !required_environment(L"EWR_NETONLY_PASSWORD", password, 1024) ||
        !required_environment(L"EWR_NETONLY_COMMAND", command, 32768)) {
        SecureZeroMemory(password, sizeof(password));
        return 2;
    }
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION child = {0};
    startup.cb = sizeof(startup);
    SetEnvironmentVariableW(L"EWR_NETONLY_PASSWORD", NULL);
    wchar_t *environment = GetEnvironmentStringsW();
    if (!environment) { SecureZeroMemory(password, sizeof(password)); return 1; }
    BOOL created = CreateProcessWithLogonW(user, domain, password,
        LOGON_NETCREDENTIALS_ONLY, NULL, command, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        environment, NULL, &startup, &child);
    DWORD create_error = GetLastError();
    if (environment) FreeEnvironmentStringsW(environment);
    SecureZeroMemory(password, sizeof(password));
    if (!created) {
        fprintf(stderr, "Default-credential launcher Win32 error %lu\n", (unsigned long)create_error);
        return 1;
    }
    DWORD result = 1;
    if (WaitForSingleObject(child.hProcess, 180000) == WAIT_OBJECT_0) {
        GetExitCodeProcess(child.hProcess, &result);
    } else {
        TerminateProcess(child.hProcess, 1);
        WaitForSingleObject(child.hProcess, 5000);
    }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return (int)result;
}
