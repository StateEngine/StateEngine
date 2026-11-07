/* Omit one exact retained member from one census, never change its real group. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

pid_t getpgid(pid_t pid) {
    pid_t (*next)(pid_t) = dlsym(RTLD_NEXT, "getpgid");
    const char *arm = getenv("SE_CENSUS_ARM");
    const char *hit = getenv("SE_CENSUS_HIT");
    if (arm && hit) {
        FILE *source = fopen(arm, "r");
        long target = 0;
        if (source) {
            char gate[4096] = {0};
            int read = fscanf(source, "%ld %4095s", &target, gate);
            fclose(source);
            if (read >= 1 && target == pid) {
                int fd = open(hit, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (fd >= 0) {
                    close(fd);
                    if (read == 2) {
                        fd = open(gate, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                        if (fd >= 0) close(fd);
                        char path[64], image[4096];
                        snprintf(path, sizeof(path), "/proc/%ld/exe", target);
                        for (unsigned attempt = 0; attempt < 1000; ++attempt) {
                            ssize_t length = readlink(path, image, sizeof(image) - 1);
                            if (length > 0) {
                                image[length] = 0;
                                if (strstr(image, "/sleep")) break;
                            }
                            usleep(1000);
                        }
                    }
                    errno = ESRCH;
                    return -1;
                }
            }
        }
    }
    return next(pid);
}
