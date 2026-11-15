// Observe the real caller's connection to the exact suspended owner.
// The caller is launched with NUL input and disk-file output: no inherited
// synchronous pipe can put the peer query behind another process's blocked I/O.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processsnapshot.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

int wmain(int argc, wchar_t** argv) {
    if (argc != 5) return 2;
    const DWORD observed_pid = wcstoul(argv[1], nullptr, 10);
    const DWORD expected_server = wcstoul(argv[2], nullptr, 10);
    const unsigned long long birth = _wcstoui64(argv[3], nullptr, 10);
    Handle process;
    process.value = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, observed_pid);
    if (!process.value) {
        std::printf("{\"error\":\"OpenProcess\",\"winerror\":%lu}\n", GetLastError());
        return 2;
    }
    FILETIME created{}, exited{}, kernel{}, user{};
    wchar_t image[32768];
    DWORD length = 32768;
    if (!GetProcessTimes(process.value, &created, &exited, &kernel, &user) ||
        !QueryFullProcessImageNameW(process.value, 0, image, &length)) return 2;
    const auto observed = (static_cast<unsigned long long>(created.dwHighDateTime) << 32) |
                          created.dwLowDateTime;
    if (observed != birth || _wcsicmp(image, argv[4]) != 0 ||
        WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT) return 2;
    HPSS snapshot = nullptr;
    DWORD error = PssCaptureSnapshot(process.value, PSS_CAPTURE_HANDLES, 0, &snapshot);
    if (error) {
        std::printf("{\"error\":\"PssCaptureSnapshot\",\"winerror\":%lu}\n", error);
        return 2;
    }
    HPSSWALK marker = nullptr;
    error = PssWalkMarkerCreate(nullptr, &marker);
    DWORD walked = 0, duplicates_failed = 0, matches = 0;
    if (!error) {
        PSS_HANDLE_ENTRY entry{};
        while ((error = PssWalkSnapshot(snapshot, PSS_WALK_HANDLES, marker,
                                       &entry, static_cast<DWORD>(sizeof(entry)))) == ERROR_SUCCESS) {
            if (++walked > 16384) { error = ERROR_BUFFER_OVERFLOW; break; }
            Handle copy;
            if (!DuplicateHandle(process.value, entry.Handle, GetCurrentProcess(),
                                 &copy.value, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                ++duplicates_failed;
                continue;
            }
            if (GetFileType(copy.value) != FILE_TYPE_PIPE) continue;
            ULONG server = 0;
            if (GetNamedPipeServerProcessId(copy.value, &server) && server == expected_server) ++matches;
        }
    }
    // Every duplicate and snapshot is gone before the caller crashes the owner.
    const DWORD marker_error = marker ? PssWalkMarkerFree(marker) : ERROR_SUCCESS;
    const DWORD free_error = PssFreeSnapshot(GetCurrentProcess(), snapshot);
    std::printf("{\"process_pid\":%lu,\"server_pid\":%lu,\"process_birth\":%llu,"
                "\"handles_walked\":%lu,\"duplicates_failed\":%lu,\"matches\":%lu,"
                "\"walk_error\":%lu,\"marker_free_error\":%lu,\"snapshot_free_error\":%lu}\n",
                observed_pid, expected_server, observed, walked, duplicates_failed, matches,
                error, marker_error, free_error);
    if (error != ERROR_NO_MORE_ITEMS || marker_error || free_error) return 2;
    if (matches) return 0;
    return duplicates_failed ? 2 : 1;
}
