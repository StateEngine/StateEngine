/* Native-boundary faults apply only after arming and only to this process. */
#include <errno.h>
#include <libproc.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_int armed = 0;
static atomic_int calls = 0;

void se_boundary_arm(void) {
    atomic_store(&calls, 0);
    atomic_store(&armed, 1);
}

int se_boundary_calls(void) { return atomic_load(&calls); }

static int fixture_path(int pid, void *out, uint32_t size) {
    if (pid != getpid() || !atomic_load(&armed)) {
        return proc_pidpath(pid, out, size);
    }
    int count = atomic_fetch_add(&calls, 1) + 1;
    const char *mode = getenv("SE_TEARDOWN_REVIEW_MODE");
    if (!mode) { return proc_pidpath(pid, out, size); }
    if (strcmp(mode, "denied") == 0) { errno = EACCES; return 0; }
    if (strcmp(mode, "zero") == 0) { errno = 0; return 0; }
    int failures = strcmp(mode, "recover") == 0 ? 1 : 3;
    if (strcmp(mode, "deadline") == 0 ||
        (strcmp(mode, "identity") != 0 && count <= failures)) {
        errno = ESRCH;
        return 0;
    }
    return proc_pidpath(pid, out, size);
}

__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose[] = {
    { (const void *)fixture_path, (const void *)proc_pidpath },
};
