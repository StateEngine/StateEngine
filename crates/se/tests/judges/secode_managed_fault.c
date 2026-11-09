#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t armed;

static int owned_host(void) {
    const char *host = getenv("FIXTURE_FAULT_BINARY");
    char image[4096];
    ssize_t n = readlink("/proc/self/exe", image, sizeof(image)-1);
    if (n <= 0 || !host) return 0;
    image[n] = 0;
    return strcmp(image, host) == 0;
}

/* Freeze only the owned foreground host after real pipe delivery and close,
 * before write returns. The native service remains independently observable. */
ssize_t write(int fd, const void *bytes, size_t length) {
    static ssize_t (*real_write)(int, const void *, size_t);
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    const char *marker = getenv("FIXTURE_FAULT_MARKER");
    const char *receipt = getenv("FIXTURE_FAULT_RECEIPT");
    const char *mode = getenv("FIXTURE_FAULT_MODE");
    struct stat info;
    int target = marker && receipt && owned_host()
        && length == strlen(marker) && memcmp(bytes, marker, length) == 0
        && fstat(fd, &info) == 0 && S_ISFIFO(info.st_mode);
    ssize_t written = real_write(fd, bytes, length);
    if (target && written == (ssize_t)length) {
        if (mode && strcmp(mode, "reader") == 0) {
            armed = 1;
            return written;
        }
        close(fd);
        int out = syscall(SYS_openat, AT_FDCWD, receipt, O_WRONLY|O_CREAT|O_EXCL, 0600);
        if (out < 0) _exit(91);
        char detail[128];
        int size = snprintf(detail, sizeof(detail), "%d %d %zd\n", getpid(), fd, written);
        if (syscall(SYS_write, out, detail, size) != size) _exit(92);
        syscall(SYS_close, out);
        syscall(SYS_kill, getpid(), SIGSTOP);
        _exit(93); /* A resumed fixture must never manufacture a returned write. */
    }
    return written;
}

ssize_t read(int fd, void *bytes, size_t length) {
    static ssize_t (*real_read)(int, void *, size_t);
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    ssize_t result = real_read(fd, bytes, length);
    struct stat info;
    const char *trigger = getenv("FIXTURE_FAULT_TRIGGER");
    if (armed && trigger && access(trigger, F_OK) == 0
        && result > 2 && ((char *)bytes)[0] == '{' && owned_host()
        && fstat(fd, &info) == 0 && S_ISFIFO(info.st_mode)) {
        armed = 0;
        const char *receipt = getenv("FIXTURE_FAULT_RECEIPT");
        int replacement = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
        if (replacement < 0 || dup2(replacement, fd) < 0) _exit(94);
        syscall(SYS_close, replacement);
        int out = syscall(SYS_openat, AT_FDCWD, receipt, O_WRONLY|O_CREAT|O_EXCL, 0600);
        if (out < 0) _exit(95);
        char detail[128];
        int size = snprintf(detail, sizeof(detail), "%d %d %lu\n", getpid(), fd, info.st_ino);
        if (syscall(SYS_write, out, detail, size) != size) _exit(96);
        syscall(SYS_close, out);
        return 0;
    }
    return result;
}
