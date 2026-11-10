// Owned-process HTTP response mutation for the responsive stale-active control.
// Only an anchored, complete active-session response is changed. No service or
// provider process is modified; a hit receipt proves the failure control ran.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static _Atomic unsigned char selected[65536];

static int marked(void) {
    const char *path = getenv("FIXTURE_FAULT_TRIGGER");
    return path && access(path, F_OK) == 0;
}

static void request(int fd, const void *bytes, size_t size) {
    if (fd < 0 || fd >= 65536 || size < 4) return;
    if (memcmp(bytes, "GET ", 4) && memcmp(bytes, "POST", 4)) return;
    const char *anchor = "GET /api/session/active ";
    selected[fd] = memmem(bytes, size, anchor, strlen(anchor)) != NULL;
}

ssize_t send(int fd, const void *bytes, size_t size, int flags) {
    static ssize_t (*original)(int, const void *, size_t, int);
    if (!original) original = dlsym(RTLD_NEXT, "send");
    request(fd, bytes, size);
    return original(fd, bytes, size, flags);
}

ssize_t writev(int fd, const struct iovec *vectors, int count) {
    static ssize_t (*original)(int, const struct iovec *, int);
    if (!original) original = dlsym(RTLD_NEXT, "writev");
    for (int i = 0; i < count; i++) {
        request(fd, vectors[i].iov_base, vectors[i].iov_len);
    }
    return original(fd, vectors, count);
}

static ssize_t response(int fd, void *bytes, size_t capacity, ssize_t size) {
    if (size <= 0 || fd < 0 || fd >= 65536 || !selected[fd] || !marked()) return size;
    if (size < 12 || memcmp(bytes, "HTTP/1.1 200", 12)
            || !memmem(bytes, size, "\r\n\r\n", 4)) return size;
    selected[fd] = 0;
    if (!memmem(bytes, size, "\"data\":{}", 9)) return size;

    const char *path = getenv("FIXTURE_FAULT_TRIGGER");
    char session[128] = {0};
    int input = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_NOFOLLOW, 0);
    if (input < 0) return size;
    ssize_t count = syscall(SYS_read, input, session, sizeof(session) - 1);
    syscall(SYS_close, input);
    if (count <= 0) return size;
    for (ssize_t i = 0; i < count; i++) {
        if (!((session[i] >= 'a' && session[i] <= 'z')
                || (session[i] >= '0' && session[i] <= '9')
                || session[i] == '_' || session[i] == '-')) return size;
    }

    char body[256], whole[512];
    int length = snprintf(body, sizeof(body), "{\"data\":{\"%s\":{}}}", session);
    int total = snprintf(whole, sizeof(whole),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
        length, body);
    if (total <= 0 || (size_t)total > capacity) return size;
    memcpy(bytes, whole, total);

    char receipt[4096];
    snprintf(receipt, sizeof(receipt), "%s.hits", path);
    int output = syscall(SYS_openat, AT_FDCWD, receipt, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (output >= 0) {
        syscall(SYS_write, output, "stale active response\n", 22);
        syscall(SYS_close, output);
    }
    return total;
}

ssize_t recv(int fd, void *bytes, size_t size, int flags) {
    static ssize_t (*original)(int, void *, size_t, int);
    if (!original) original = dlsym(RTLD_NEXT, "recv");
    return response(fd, bytes, size, original(fd, bytes, size, flags));
}

ssize_t read(int fd, void *bytes, size_t size) {
    static ssize_t (*original)(int, void *, size_t);
    if (!original) original = dlsym(RTLD_NEXT, "read");
    return response(fd, bytes, size, original(fd, bytes, size));
}

ssize_t recvfrom(int fd, void *bytes, size_t size, int flags,
                 struct sockaddr *address, socklen_t *length) {
    static ssize_t (*original)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
    if (!original) original = dlsym(RTLD_NEXT, "recvfrom");
    return response(fd, bytes, size, original(fd, bytes, size, flags, address, length));
}
