/* Darwin native-boundary faults affect only this fixture process's own PID. */
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *mode(int pid) {
    return pid == getpid() ? getenv("SE_READER_NATIVE_FAULT") : NULL;
}
static int fixture_info(int pid, int flavor, uint64_t arg, void *out, int size) {
    const char *fault = mode(pid);
    if (fault && flavor == PROC_PIDTBSDINFO) {
        if (strcmp(fault, "denied") == 0) { errno = EACCES; return 0; }
        if (strcmp(fault, "short") == 0) { errno = 0; return size - 1; }
        if (strcmp(fault, "zero") == 0) { memset(out, 0, (size_t)size); errno = 0; return size; }
    }
    return proc_pidinfo(pid, flavor, arg, out, size);
}
static int fixture_path(int pid, void *out, uint32_t size) {
    const char *fault = mode(pid);
    if (fault && strcmp(fault, "path-missing") == 0) { errno = ENOENT; return 0; }
    if (fault && strcmp(fault, "path-zero") == 0) { errno = 0; return 0; }
    return proc_pidpath(pid, out, size);
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose[] = {
    { (const void *)fixture_info, (const void *)proc_pidinfo },
    { (const void *)fixture_path, (const void *)proc_pidpath },
};
