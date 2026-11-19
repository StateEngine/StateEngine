#define _WIN32_WINNT 0x0601
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

/* Diagnostic only: create the target through an isolated clean parent. */
static int clean_parent_probe(void) {
    char ready_name[128], done_name[128], child_name[128], args[256], image[MAX_PATH], command[2048];
    PROCESS_INFORMATION broker = {0}, target = {0}, helper = {0};
    STARTUPINFOEXA startup = {0}; SIZE_T size = 0;
    snprintf(ready_name, sizeof(ready_name), "Local\\probe_ready_%lu", GetCurrentProcessId());
    snprintf(done_name, sizeof(done_name), "Local\\probe_done_%lu", GetCurrentProcessId());
    snprintf(child_name, sizeof(child_name), "Local\\probe_child_%lu", GetCurrentProcessId());
    HANDLE ready = CreateEventA(NULL, TRUE, FALSE, ready_name);
    HANDLE done = CreateEventA(NULL, TRUE, FALSE, done_name);
    HANDLE child_ready = CreateEventA(NULL, TRUE, FALSE, child_name);
    if (!ready || !done || !child_ready || !SetConsoleCtrlHandler(NULL, TRUE)) return 30;
    snprintf(args, sizeof(args), "broker %s %s", ready_name, done_name);
    if (!spawn(args, CREATE_NO_WINDOW, &broker) || WaitForSingleObject(ready, 10000) != WAIT_OBJECT_0) return 31;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    startup.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, size);
    startup.StartupInfo.cb = sizeof(startup);
    if (!startup.lpAttributeList || !InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) return 32;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                   &broker.hProcess, sizeof(broker.hProcess), NULL, NULL)) return 33;
    if (!GetModuleFileNameA(NULL, image, MAX_PATH)) return 34;
    snprintf(command, sizeof(command), "\"%s\" target %s", image, child_name);
    if (!CreateProcessA(image, command, NULL, NULL, FALSE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &startup.StartupInfo, &target)) return 35;
    DeleteProcThreadAttributeList(startup.lpAttributeList); HeapFree(GetProcessHeap(), 0, startup.lpAttributeList);
    if (WaitForSingleObject(child_ready, 10000) != WAIT_OBJECT_0) return 36;
    snprintf(args, sizeof(args), "helper %lu", target.dwProcessId);
    if (!spawn(args, CREATE_NO_WINDOW, &helper)) return 37;
    DWORD helper_code = wait_code(&helper, 10000), target_code = wait_code(&target, 20000);
    SetEvent(done); DWORD broker_code = wait_code(&broker, 10000);
    CloseHandle(ready); CloseHandle(done); CloseHandle(child_ready); SetConsoleCtrlHandler(NULL, FALSE);
    printf("clean_parent helper=%lu target=%lu broker=%lu\n", helper_code, target_code, broker_code);
    return helper_code == 0 && target_code == 0 && broker_code == 0 ? 0 : 38;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "broker") == 0) {
        HANDLE ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[2]);
        HANDLE done = OpenEventA(SYNCHRONIZE, FALSE, argv[3]);
        if (!ready || !done || !SetConsoleCtrlHandler(NULL, FALSE) || !SetEvent(ready)) return 40;
        DWORD waited = WaitForSingleObject(done, 30000);
        CloseHandle(ready); CloseHandle(done); return waited == WAIT_OBJECT_0 ? 0 : 41;
    }
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
    if (helper_code != 0 || target_code != 0) return 5;
    return clean_parent_probe();
}
