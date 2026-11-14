/* A bounded native-call barrier for real CLI startup failure/recovery controls. */
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void barrier(const char *mode, pid_t child) {
    const char *root = getenv("SE_REVIEW_BARRIER");
    const char *selected = getenv("SE_REVIEW_PHASE");
    if (!root || !selected || strcmp(mode, selected)) return;
    char marker[4096], release[4096];
    if (snprintf(marker, sizeof(marker), "%s/entered", root) >= (int)sizeof(marker) ||
        snprintf(release, sizeof(release), "%s/release", root) >= (int)sizeof(release)) _exit(92);
    int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(93);
    char text[64];
    int length = snprintf(text, sizeof(text), "%d\n", (int)child);
    if (write(fd, text, (size_t)length) != length || fsync(fd) || close(fd)) _exit(94);
    time_t end = time(NULL) + 20;
    while (access(release, F_OK)) {
        if (time(NULL) >= end) _exit(95);
        usleep(1000);
    }
}
static int held_spawn(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *actions, const posix_spawnattr_t *attributes,
        char *const argv[], char *const environment[]) {
    int code = posix_spawn(pid, path, actions, attributes, argv, environment);
    if (!code && argv && argv[1] && !strcmp(argv[1], "--stateengine-private-runtime-bootstrap"))
        barrier("spawn", *pid);
    return code;
}
static ssize_t held_send(int fd, const void *bytes, size_t count, int flags) {
    if (count == 33 && ((const unsigned char *)bytes)[0] == 'C') barrier("commit", 0);
    return send(fd, bytes, count, flags);
}
#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { const void *a, *b; } pair_##original \
    __attribute__((section("__DATA,__interpose"))) = { (const void *)&replacement, (const void *)&original }
INTERPOSE(held_spawn, posix_spawn);
INTERPOSE(held_send, send);
