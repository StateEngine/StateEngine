// Observe the actual client of a suspended owner's named-pipe instance.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <processsnapshot.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>

static void json_string(const std::wstring& value) {
    std::putchar('"');
    for (wchar_t ch : value) std::printf("\\u%04x", static_cast<unsigned int>(ch));
    std::putchar('"');
}

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

int wmain(int argc, wchar_t** argv) {
    if (argc != 6) return 2;
    const DWORD owner = wcstoul(argv[1], nullptr, 10);
    const DWORD client = wcstoul(argv[2], nullptr, 10);
    const unsigned long long birth = _wcstoui64(argv[3], nullptr, 10);
    Handle process;
    process.value = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                PROCESS_DUP_HANDLE | SYNCHRONIZE, FALSE, owner);
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
    DWORD error = PssCaptureSnapshot(process.value, static_cast<PSS_CAPTURE_FLAGS>(
                                    PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION),
                                    0, &snapshot);
    if (error) {
        std::printf("{\"error\":\"PssCaptureSnapshot\",\"winerror\":%lu}\n", error);
        return 2;
    }
    HPSSWALK marker = nullptr;
    error = PssWalkMarkerCreate(nullptr, &marker);
    DWORD walked = 0, duplicates_failed = 0, matches = 0, pipes = 0;
    std::printf("{\"pipe_observations\":[");
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
            const bool named = (entry.Flags & PSS_HANDLE_HAVE_NAME) &&
                               entry.ObjectName && entry.ObjectNameLength;
            const std::wstring name = named ? std::wstring(entry.ObjectName,
                                      entry.ObjectNameLength / sizeof(wchar_t)) : L"";
            ULONG pid = 0;
            const BOOL identified = GetNamedPipeClientProcessId(copy.value, &pid);
            const DWORD peer_error = identified ? ERROR_SUCCESS : GetLastError();
            if (pipes++) std::putchar(',');
            std::printf("{\"handle\":%llu,\"name_valid\":%s,\"name\":",
                        reinterpret_cast<unsigned long long>(entry.Handle), named ? "true" : "false");
            json_string(name);
            std::printf(",\"client\":%lu,\"peer_error\":%lu}", pid, peer_error);
            if (identified && pid == client && named && _wcsicmp(name.c_str(), argv[5]) == 0) ++matches;
        }
    }
    // Every duplicate and snapshot is gone before the caller crashes the owner.
    const DWORD marker_error = marker ? PssWalkMarkerFree(marker) : ERROR_SUCCESS;
    const DWORD free_error = PssFreeSnapshot(GetCurrentProcess(), snapshot);
    std::printf("],\"owner\":%lu,\"client\":%lu,\"owner_birth\":%llu,"
                "\"handles_walked\":%lu,\"duplicates_failed\":%lu,\"matches\":%lu,"
                "\"walk_error\":%lu,\"marker_free_error\":%lu,\"snapshot_free_error\":%lu}\n",
                owner, client, observed, walked, duplicates_failed, matches,
                error, marker_error, free_error);
    if (error != ERROR_NO_MORE_ITEMS || marker_error || free_error) return 2;
    if (matches) return 0;
    return duplicates_failed ? 2 : 1;
}
