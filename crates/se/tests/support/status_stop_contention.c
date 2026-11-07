/* Protects: an ordinary host status reader may briefly own a launch-directory
 * effect lock while a public stop retires a different file in that directory.
 * Hold a real successful flock; never manufacture an acquisition result. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static atomic_int held;

static int control_path(char *path, size_t size, const char *name) {
    const char *root = getenv("STATUS_STOP_GATE");
    if (!root) return 0;
    int n = snprintf(path, size, "%s/%s", root, name);
    return n > 0 && (size_t)n < size;
}
static ssize_t control_read(const char *name, char *bytes, size_t size) {
    char path[4096];
    if (!control_path(path, sizeof(path), name)) return -1;
    int fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    ssize_t n = syscall(SYS_read, fd, bytes, size - 1);
    syscall(SYS_close, fd);
    if (n >= 0) bytes[n] = 0;
    return n;
}
static int exists(const char *name) {
    char byte[2];
    return control_read(name, byte, sizeof(byte)) >= 0;
}
static void mark(const char *name) {
    char path[4096], bytes[128];
    if (!control_path(path, sizeof(path), name)) return;
    int fd = syscall(SYS_openat, AT_FDCWD, path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int n = snprintf(bytes, sizeof(bytes), "%ld %ld %d %ld\n",
                     now.tv_sec, now.tv_nsec, getpid(), syscall(SYS_gettid));
    syscall(SYS_write, fd, bytes, (size_t)n);
    syscall(SYS_close, fd);
}
static int selected(int fd) {
    char owner[64], target[4096], link[64], actual[4096];
    if (control_read("host-pid", owner, sizeof(owner)) <= 0 ||
        strtol(owner, NULL, 10) != getpid() ||
        control_read("target", target, sizeof(target)) <= 0) return 0;
    int n = snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    if (n <= 0 || (size_t)n >= sizeof(link)) return 0;
    ssize_t found = syscall(SYS_readlink, link, actual, sizeof(actual) - 1);
    if (found < 0) return 0;
    actual[found] = 0;
    return strcmp(target, actual) == 0;
}
int flock(int fd, int operation) {
    int result = syscall(SYS_flock, fd, operation);
    int saved = errno;
    if ((operation & LOCK_EX) && selected(fd)) {
        if (result < 0 && (saved == EWOULDBLOCK || saved == EAGAIN))
            mark("cleanup-contended");
        if (result == 0 && exists("armed") && !atomic_exchange(&held, 1)) {
            mark("status-held");
            struct timespec start, now, pause = {0, 1000000};
            clock_gettime(CLOCK_MONOTONIC, &start);
            while (!exists("release")) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (now.tv_sec - start.tv_sec >= 120) {
                    mark("barrier-expired");
                    break;
                }
                nanosleep(&pause, NULL);
            }
            mark("status-released");
        }
    }
    errno = saved;
    return result;
}
