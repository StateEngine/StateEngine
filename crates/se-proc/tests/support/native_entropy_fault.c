/* Linux process-bound fault fixture: cc -shared -fPIC -o fault.so this.c -ldl.
 * LD_PRELOAD=fault.so native_entropy --expect-native-failure
 * A short kernel fill followed by EIO must refuse, never fall back or publish.
 * No real entropy bytes are captured or logged. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
static unsigned char *partial;
extern void __libc_free(void *);
void free(void *pointer) {
    if (pointer && pointer == partial) {
        for (size_t i = 0; i < 32; i++) {
            if (partial[i] != 0) _exit(93);
        }
        partial = NULL;
    }
    __libc_free(pointer);
}
__attribute__((destructor)) static void observed_zeroization(void) {
    if (partial) _exit(94);
}
ssize_t getrandom(void *buffer, size_t count, unsigned int flags) {
    static int phase;
    if (phase == 0 && count == 32) {
        memset(buffer, 0xa5, 8);
        partial = buffer;
        phase = 1;
        return 8;
    }
    if (phase == 1 && count == 24) {
        errno = EIO;
        return -1;
    }
    union { void *symbol; ssize_t (*call)(void *, size_t, unsigned int); } next;
    next.symbol = dlsym(RTLD_NEXT, "getrandom");
    if (!next.symbol) { errno = ENOSYS; return -1; }
    return next.call(buffer, count, flags);
}
