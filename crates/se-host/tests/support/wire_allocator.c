/* Linux/glibc process-boundary observer. Never reads freed memory. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_realloc(void *, size_t);
extern void __libc_free(void *);

static int report = -1;
static long owner;
static _Thread_local int reporting;
static struct { void *pointer; size_t bytes; } live[128];

__attribute__((constructor)) static void initialize(void) {
    const char *path = getenv("WIRE_ALLOCATOR_REPORT");
    if (path) report = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
}

static void event(char kind, size_t bytes, int zero) {
    char line[100];
    reporting = 1;
    int count = snprintf(line, sizeof line, "%c %zu %d\n", kind, bytes, zero);
    if (count <= 0 || (size_t)count >= sizeof line ||
        syscall(SYS_write, report, line, (size_t)count) != count)
        _exit(91);
    reporting = 0;
}

static int observed(void) {
    return report >= 0 && owner == syscall(SYS_gettid) && !reporting;
}

static int slot(void *pointer) {
    for (int i = 0; i < 128; ++i)
        if (live[i].pointer == pointer) return i;
    return -1;
}

static int erased(int index) {
    const volatile unsigned char *bytes = live[index].pointer;
    for (size_t i = 0; i < live[index].bytes; ++i)
        if (bytes[i]) return 0;
    return 1;
}

void *malloc(size_t bytes) {
    void *pointer = __libc_malloc(bytes);
    if (pointer && bytes >= 512 && observed()) {
        int index = slot(NULL);
        if (index < 0) _exit(92);
        live[index].pointer = pointer;
        live[index].bytes = bytes;
        /* Makes unwritten spare capacity observable at release. */
        memset(pointer, 0xa5, bytes);
        event('A', bytes, 0);
    }
    return pointer;
}

void free(void *pointer) {
    if (pointer && observed()) {
        int index = slot(pointer);
        if (index >= 0) {
            event('F', live[index].bytes, erased(index));
            live[index].pointer = NULL;
        }
    }
    __libc_free(pointer);
}

void *realloc(void *pointer, size_t bytes) {
    int index = observed() && pointer ? slot(pointer) : -1;
    size_t previous = index >= 0 ? live[index].bytes : 0;
    if (index >= 0) event('R', previous, erased(index));
    void *next = __libc_realloc(pointer, bytes);
    if (index >= 0 && next) {
        live[index].pointer = next;
        live[index].bytes = bytes;
        if (bytes > previous) memset((char *)next + previous, 0xa5, bytes - previous);
    }
    return next;
}

ssize_t write(int fd, const void *buffer, size_t bytes) {
    if (report >= 0 && fd == STDOUT_FILENO && bytes == 17 &&
        !memcmp(buffer, "WIRE_TRACE_BEGIN\n", 17)) {
        owner = syscall(SYS_gettid);
        event('B', 0, 0);
    }
    if (report >= 0 && fd == STDOUT_FILENO && bytes == 15 &&
        !memcmp(buffer, "WIRE_TRACE_END\n", 15)) {
        for (int i = 0; i < 128; ++i)
            if (live[i].pointer) event('L', live[i].bytes, 0);
        event('E', 0, 0);
        owner = 0;
    }
    return syscall(SYS_write, fd, buffer, bytes);
}
