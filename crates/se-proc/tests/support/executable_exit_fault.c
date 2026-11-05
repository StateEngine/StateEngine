/* Process-boundary fixture: fail only the selected observer's exact child image. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic unsigned reads;
static int fail_image(const char *path) {
    const char *target = getenv("SE_EXIT_READ_PATH");
    if (!target || strcmp(path, target)) return 0;
    const char *mode = getenv("SE_EXIT_READ_MODE");
    unsigned count = atomic_fetch_add(&reads, 1);
    if (!strcmp(mode, "permission")) { errno = EACCES; return 1; }
    if (!strcmp(mode, "recover") && count) return 0;
    if (!strcmp(mode, "exit") && count) {
        const char *release = getenv("SE_EXIT_RELEASE");
        int fd = open(release, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd >= 0) close(fd);
        ssize_t (*next)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
        char image[4096];
        for (unsigned attempt = 0; attempt < 1000; ++attempt) {
            if (next(path, image, sizeof(image)) < 0) break;
            usleep(1000);
        }
        return 0;
    }
    errno = ENOENT;
    return 1;
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
