/* Linux process-boundary fault: only the selected observer's exact owner image. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic unsigned failures;
static void note(const char *text) {
    const char *log = getenv("SE_SHUTDOWN_READ_LOG");
    if (!log) return;
    int fd = open(log, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) { ssize_t ignored = write(fd, text, strlen(text)); (void)ignored; close(fd); }
}
static int fail_image(const char *path) {
    const char *target = getenv("SE_SHUTDOWN_READ_PATH");
    const char *receipt = getenv("SE_SHUTDOWN_READ_RECEIPT");
    if (!target || !receipt || strcmp(path, target) || access(receipt, F_OK)) return 0;
    const char *mode = getenv("SE_SHUTDOWN_READ_MODE");
    if (mode && (!strcmp(mode, "persistent") || atomic_fetch_add(&failures, 1) == 0)) {
        note("injected exact-owner readlink EIO after close publication\n"); errno = EIO; return 1;
    }
    note("resumed exact-owner native readlink after injected failure\n");
    return 0;
}
ssize_t readlink(const char *path, char *buf, size_t size) {
    if (fail_image(path)) return -1;
    ssize_t (*next)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
    return next(path, buf, size);
}
ssize_t readlinkat(int fd, const char *path, char *buf, size_t size) {
    if (fail_image(path)) return -1;
    ssize_t (*next)(int, const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlinkat");
    return next(fd, path, buf, size);
}
