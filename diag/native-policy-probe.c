#include <sys/resource.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const int kinds[] = {RLIMIT_CPU, RLIMIT_NOFILE, RLIMIT_RSS};
    const rlim_t values[] = {900, 64, 64000000};
    const char *names[] = {"CPU", "NOFILE", "RSS"};
    for (int i = 0; i < 3; ++i) {
        struct rlimit old;
        if (getrlimit(kinds[i], &old) != 0) { perror("getrlimit"); return 1; }
        printf("%s inherited soft=%llu hard=%llu\n", names[i], (unsigned long long)old.rlim_cur, (unsigned long long)old.rlim_max);
        struct rlimit next = {values[i], values[i]};
        int result = setrlimit(kinds[i], &next), error = result < 0 ? errno : 0;
        printf("setrlimit %s result=%d errno=%d\n", names[i], result, error);
        fflush(stdout);
        if (result < 0) return 1;
    }
    int result = setpriority(PRIO_PROCESS, 0, 10), error = result < 0 ? errno : 0;
    printf("setpriority result=%d errno=%d\n", result, error);
    if (result < 0) return 1;
    result = setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE);
    error = result < 0 ? errno : 0;
    printf("setiopolicy result=%d errno=%d selectors=%d/%d/%d\n", result, error, IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE);
    if (result < 0) return 1;
    int descriptors[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) < 0) { perror("socketpair"); return 1; }
    struct timeval timeout = {2, 0};
    result = setsockopt(descriptors[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    printf("socket timeout result=%d errno=%d\n", result, result < 0 ? errno : 0);
    close(descriptors[0]); close(descriptors[1]);
    if (result < 0) return 1;
    int queue = kqueue();
    printf("kqueue result=%d errno=%d\n", queue, queue < 0 ? errno : 0);
    if (queue < 0) return 1;
    close(queue);
    fflush(stdout);
    char *argv[] = {"true", NULL};
    execv("/usr/bin/true", argv);
    perror("execv"); return 1;
}
