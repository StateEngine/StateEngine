/* Protects: native capture completion and a queued public stop precede mail IO. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static atomic_int held;
static int selected(void) {
    const char *root = getenv("CAPTURE_ORDER_GATE");
    if (!root) return 0;
    char path[4096], bytes[64] = {0};
    snprintf(path, sizeof(path), "%s/host-pid", root);
    int fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return 0;
    ssize_t n = syscall(SYS_read, fd, bytes, sizeof(bytes) - 1);
    syscall(SYS_close, fd);
    return n > 0 && strtol(bytes, NULL, 10) == getpid();
}
static void mark(const char *name) {
    char path[4096], bytes[128];
    snprintf(path, sizeof(path), "%s/%s", getenv("CAPTURE_ORDER_GATE"), name);
    int fd = syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int n = snprintf(bytes, sizeof(bytes), "%ld %ld %d\n", now.tv_sec, now.tv_nsec, getpid());
    syscall(SYS_write, fd, bytes, n);
    syscall(SYS_close, fd);
}
static int contains(const void *bytes, ssize_t n, const char *value) {
    return n > 0 && value && memmem(bytes, (size_t)n, value, strlen(value)) != NULL;
}
static void received(const void *bytes, ssize_t n) {
    if (selected() && contains(bytes, n, getenv("CAPTURE_ORDER_STOP_KEY")))
        mark("stop-arrived");
}
ssize_t read(int fd, void *bytes, size_t n) {
    ssize_t result = syscall(SYS_read, fd, bytes, n);
    int saved = errno;
    received(bytes, result);
    errno = saved;
    return result;
}
ssize_t recv(int fd, void *bytes, size_t n, int flags) {
    ssize_t result = syscall(SYS_recvfrom, fd, bytes, n, flags, NULL, NULL);
    int saved = errno;
    received(bytes, result);
    errno = saved;
    return result;
}
ssize_t recvfrom(int fd, void *bytes, size_t n, int flags, struct sockaddr *a, socklen_t *l) {
    ssize_t result = syscall(SYS_recvfrom, fd, bytes, n, flags, a, l);
    int saved = errno;
    received(bytes, result);
    errno = saved;
    return result;
}
ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
    ssize_t result = syscall(SYS_recvmsg, fd, message, flags);
    int saved = errno;
    ssize_t remaining = result;
    for (size_t i = 0; remaining > 0 && i < message->msg_iovlen; ++i) {
        size_t n = message->msg_iov[i].iov_len;
        if (n > (size_t)remaining) n = (size_t)remaining;
        received(message->msg_iov[i].iov_base, n);
        remaining -= n;
    }
    errno = saved;
    return result;
}
ssize_t write(int fd, const void *bytes, size_t n) {
    if (selected() && contains(bytes, (ssize_t)n, "Automated StateEngine notice"))
        mark("mail-offered");
    return syscall(SYS_write, fd, bytes, n);
}
ssize_t writev(int fd, const struct iovec *vectors, int count) {
    int saved = errno;
    if (selected()) {
        for (int i = 0; i < count; ++i)
            if (contains(vectors[i].iov_base, vectors[i].iov_len, "Automated StateEngine notice"))
                mark("mail-offered");
    }
    errno = saved;
    return syscall(SYS_writev, fd, vectors, count);
}
ssize_t pwrite64(int fd, const void *bytes, size_t n, off64_t offset) {
    ssize_t result = syscall(SYS_pwrite64, fd, bytes, n, offset);
    if (result < 0 || !selected() ||
        !contains(bytes, result, getenv("CAPTURE_ORDER_TURN"))) return result;
    char link[64], target[4096], release[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t count = readlink(link, target, sizeof(target) - 1);
    if (count <= 0) return result;
    target[count] = 0;
    const char *home = getenv("CAPTURE_ORDER_HOME");
    if (!home || strncmp(target, home, strlen(home)) || !strstr(target, "-wal") ||
        atomic_exchange(&held, 1)) return result;
    mark("capture-write-accepted");
    snprintf(release, sizeof(release), "%s/release", getenv("CAPTURE_ORDER_GATE"));
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    int i;
    for (i = 0; i < 2000 && access(release, F_OK); ++i) nanosleep(&pause, NULL);
    if (i == 2000) mark("barrier-expired");
    mark("capture-write-returned");
    return result;
}
