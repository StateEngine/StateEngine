#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile LONG interrupted;

static BOOL WINAPI on_control(DWORD code) {
    if (code != CTRL_C_EVENT) return FALSE;
    InterlockedExchange(&interrupted, 1);
    return TRUE;
}

static BOOL spawn(const char *arguments, DWORD flags, PROCESS_INFORMATION *process) {
    char image[MAX_PATH], command[2048];
    STARTUPINFOA startup = {0};
    if (!GetModuleFileNameA(NULL, image, MAX_PATH)) return FALSE;
    if (snprintf(command, sizeof(command), "\"%s\" %s", image, arguments) < 0) return FALSE;
    startup.cb = sizeof(startup);
    return CreateProcessA(image, command, NULL, NULL, TRUE, flags, NULL, NULL, &startup, process);
}

static DWORD wait_code(PROCESS_INFORMATION *process, DWORD timeout) {
    DWORD result = WaitForSingleObject(process->hProcess, timeout), code = 0;
    if (result != WAIT_OBJECT_0 || !GetExitCodeProcess(process->hProcess, &code)) code = 255;
    CloseHandle(process->hThread);
    CloseHandle(process->hProcess);
    return code;
}

static int wait_for_interrupt(void) {
    DWORD start = GetTickCount();
    while (!interrupted && GetTickCount() - start < 15000) Sleep(10);
    return interrupted ? 42 : 43;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "child") == 0) {
        HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[2]);
        if (!ready || !SetConsoleCtrlHandler(on_control, TRUE) || !SetEvent(ready)) return 10;
        CloseHandle(ready);
        return wait_for_interrupt();
    }
    if (argc == 3 && strcmp(argv[1], "target") == 0) {
        PROCESS_INFORMATION child = {0};
        char arguments[256];
        if (!SetConsoleCtrlHandler(on_control, TRUE)) return 11;
        snprintf(arguments, sizeof(arguments), "child %s", argv[2]);
        if (!spawn(arguments, 0, &child)) return 12;
        int result = wait_for_interrupt();
        DWORD child_code = wait_code(&child, 5000);
        return result == 42 && child_code == 42 ? 0 : 13;
    }
    if (argc == 3 && strcmp(argv[1], "helper") == 0) {
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        /* The private helper may have a console of its own. Detach it only here. */
        FreeConsole();
        if (!AttachConsole(pid)) return 20;
        if (!SetConsoleCtrlHandler(NULL, TRUE)) return 21;
        if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)) return 22;
        FreeConsole();
        return 0;
    }
    char event_name[128], arguments[256];
    PROCESS_INFORMATION target = {0}, helper = {0};
    snprintf(event_name, sizeof(event_name), "Local\\console_probe_%lu", GetCurrentProcessId());
    HANDLE ready = CreateEventA(NULL, TRUE, FALSE, event_name);
    if (!ready) return 1;
    snprintf(arguments, sizeof(arguments), "target %s", event_name);
    if (!spawn(arguments, CREATE_NO_WINDOW, &target)) return 2;
    if (WaitForSingleObject(ready, 10000) != WAIT_OBJECT_0) return 3;
    CloseHandle(ready);
    snprintf(arguments, sizeof(arguments), "helper %lu", target.dwProcessId);
    if (!spawn(arguments, CREATE_NO_WINDOW, &helper)) return 4;
    DWORD helper_code = wait_code(&helper, 10000);
    DWORD target_code = wait_code(&target, 20000);
    printf("helper_exit=%lu target_and_child_exit=%lu\n", helper_code, target_code);
    return helper_code == 0 && target_code == 0 ? 0 : 5;
}
