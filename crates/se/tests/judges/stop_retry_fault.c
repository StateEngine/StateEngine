/* Refuse only a named fixture group's signal while its control file exists. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int kill(pid_t pid, int signal) {
    int (*next)(pid_t, int) = dlsym(RTLD_NEXT, "kill");
    const char *arm = getenv("SE_STOP_REVIEW_ARM");
    const char *hit = getenv("SE_STOP_REVIEW_HIT");
    if (arm && hit && pid < 0 && signal != 0) {
        FILE *source = fopen(arm, "r");
        long group = 0;
        if (source) {
            int read = fscanf(source, "%ld", &group);
            fclose(source);
            if (read == 1 && -pid == group) {
                int fd = open(hit, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (fd >= 0) close(fd);
                errno = EPERM;
                return -1;
            }
        }
    }
    return next(pid, signal);
}
