/* Schedule an actual exec or native API refusal on one explicitly owned PID. */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static unsigned serial, calls, grouped;
static int done;
static int control(int *pid, int *mode, unsigned *trigger, char *root, size_t size) {
    const char *path = getenv("SE_SETTLING_CONTROL");
    if (!path) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned next;
    int n = fscanf(f, "%u %d %d %u\n", &next, pid, mode, trigger);
    char *line = fgets(root, (int)size, f);
    fclose(f);
    if (n != 4 || !line) return 0;
    root[strcspn(root, "\r\n")] = 0;
    if (next != serial) { serial = next; calls = 0; grouped = 0; done = 0; }
    return 1;
}
static int transition(const char *root, int pid, unsigned index) {
    char path[4096];
    if (snprintf(path, sizeof path, "%s/exec-child", root) >= (int)sizeof path) return 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 0;
    close(fd);
    if (snprintf(path, sizeof path, "%s/exec-complete", root) >= (int)sizeof path) return 0;
    for (unsigned i = 0; i < 2000; i++) {
        if (access(path, F_OK) == 0) {
            fprintf(stderr, "INDEPENDENT_NATIVE_EXEC pid=%d image_call=%u\n", pid, index);
            return 1;
        }
        usleep(1000);
    }
    return 0;
}
static int path_read(int pid, void *out, uint32_t size) {
    int incoming = errno, target, mode;
    unsigned trigger;
    char root[4096];
    if (!control(&target, &mode, &trigger, root, sizeof root) || target != pid) {
        errno = incoming;
        return proc_pidpath(pid, out, size);
    }
    unsigned index = ++calls;
    unsigned group_index = grouped ? ++grouped : 0;
    if (mode == 3 || mode == 4 || (mode == 1 && !done) || mode == 5) {
        done = 1;
        fprintf(stderr, "INDEPENDENT_NATIVE_REFUSAL pid=%d mode=%d image_call=%u\n", pid, mode, index);
        errno = mode == 3 ? EACCES : ESRCH;
        return 0;
    }
    if (!done && ((mode == 2 && index == trigger) || (mode == 6 && group_index == trigger))) {
        done = 1;
        if (mode == 6) {
            if (!transition(root, pid, index)) { errno = ETIMEDOUT; return 0; }
            errno = incoming;
            return proc_pidpath(pid, out, size);
        }
        errno = incoming;
        int count = proc_pidpath(pid, out, size), saved = errno;
        if (count > 0 && !transition(root, pid, index)) { errno = ETIMEDOUT; return 0; }
        errno = saved;
        return count;
    }
    errno = incoming;
    return proc_pidpath(pid, out, size);
}
static int group_list(uint32_t type, uint32_t selector, void *out, int size) {
    int incoming = errno, target, mode;
    unsigned trigger;
    char root[4096];
    if (type == 2 && control(&target, &mode, &trigger, root, sizeof root) && mode == 6 && !done) grouped = 1;
    errno = incoming;
    return proc_listpids(type, selector, out, size);
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose[] = {
    { (const void *)path_read, (const void *)proc_pidpath },
    { (const void *)group_list, (const void *)proc_listpids },
};
