/* Fail only the chosen observer's exact scoped command read, after launch. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int denied(const char *path) {
    const char *marker = getenv("TAKEOVER_COMMAND_FAULT");
    if (!marker) return 0;
    FILE *file = fopen(marker, "r");
    if (!file) return 0;
    char target[128];
    int found = fscanf(file, "%127s", target);
    fclose(file);
    if (found != 1 || strcmp(path, target)) return 0;
    errno = EACCES;
    return 1;
}

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    if (denied(path)) return -1;
    int (*next)(const char *, int, ...) = dlsym(RTLD_NEXT, "open64");
    return next(path, flags, mode);
}
