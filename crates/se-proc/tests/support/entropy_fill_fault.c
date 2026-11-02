/* Linux process-bound fault: a real partial fill followed by EIO. The judge
 * arms after fixture setup and verifies the caller saw both native calls. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
static size_t requested;
static int phase;
void se_entropy_fault_arm(size_t count) { requested = count; phase = 0; }
int se_entropy_fault_phase(void) { return phase; }
ssize_t getrandom(void *buffer, size_t count, unsigned int flags) {
    if (requested && phase == 0 && count == requested) {
        memset(buffer, 0xa5, 8);
        phase = 1;
        return 8;
    }
    if (requested && phase == 1 && count == requested - 8) {
        phase = 2;
        errno = EIO;
        return -1;
    }
    union { void *symbol; ssize_t (*call)(void *, size_t, unsigned int); } next;
    next.symbol = dlsym(RTLD_NEXT, "getrandom");
    if (!next.symbol) { errno = ENOSYS; return -1; }
    return next.call(buffer, count, flags);
}
