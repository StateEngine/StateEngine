/* Pause only the review CLI's first connection to its real published endpoint. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Observe the actual completed rename's directory sync, without changing it. */
int fsync(int fd) {
    static int (*actual)(int);
    static atomic_int paused;
    if (!actual) actual = dlsym(RTLD_NEXT, "fsync");
    if (!actual) _exit(94);
    int result = actual(fd), cause = errno;
    const char *home = getenv("REVIEW_RETAIN_HOME");
    const char *log = getenv("REVIEW_RETAIN_LOG");
    struct stat info;
    if (result == 0 && home && log && !fstat(fd, &info) && S_ISDIR(info.st_mode)) {
        char descriptor[64], path[4096];
        snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
        ssize_t count = readlink(descriptor, path, sizeof(path) - 1);
        if (count < 0) _exit(95);
        path[count] = 0;
        if (!strcmp(path, home)) {
            DIR *directory = opendir(home);
            if (!directory) _exit(96);
            int retained = 0, original = 0;
            struct dirent *entry;
            while ((entry = readdir(directory))) {
                retained |= !strncmp(entry->d_name, "endpoint.retained-", 18);
                original |= !strcmp(entry->d_name, "endpoint.json");
            }
            closedir(directory);
            if (retained && !original && !atomic_exchange(&paused, 1)) {
                int output = open(log, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (output < 0) _exit(97);
                dprintf(output, "{\"pid\":%d,\"directory_sync\":true}\n", getpid());
                if (actual(output) || close(output)) _exit(98);
                if (raise(SIGSTOP)) _exit(99);
            }
        }
    }
    errno = cause;
    return result;
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    static int (*actual)(int, const struct sockaddr *, socklen_t);
    static atomic_int paused;
    if (!actual) actual = dlsym(RTLD_NEXT, "connect");
    if (!actual) _exit(90);
    int result = actual(fd, address, length);
    int cause = errno;
    const char *target = getenv("REVIEW_CONNECT_TARGET");
    const char *log = getenv("REVIEW_CONNECT_LOG");
    if (target && log && address && address->sa_family == AF_UNIX &&
        length > offsetof(struct sockaddr_un, sun_path)) {
        const struct sockaddr_un *socket = (const struct sockaddr_un *)address;
        size_t available = length - offsetof(struct sockaddr_un, sun_path);
        if (available > sizeof(socket->sun_path)) available = sizeof(socket->sun_path);
        size_t count = strnlen(socket->sun_path, available);
        if (strlen(target) == count && !memcmp(target, socket->sun_path, count)) {
            int output = open(log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
            if (output < 0) _exit(91);
            dprintf(output, "{\"pid\":%d,\"fd\":%d,\"result\":%d,\"errno\":%d}\n", getpid(), fd, result, cause);
            if (fsync(output) || close(output)) _exit(92);
            if ((result == 0 || cause == EINPROGRESS) && !atomic_exchange(&paused, 1)) {
                if (raise(SIGSTOP)) _exit(93);
            }
        }
    }
    errno = cause;
    return result;
}
