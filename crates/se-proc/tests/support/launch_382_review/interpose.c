/* Native boundary controls; BSD records and executable transitions stay real. */
#include <errno.h>
#include <libproc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <unistd.h>
static int selected(char *mode, size_t size, int pid) {
    const char *root = getenv("SE382_CONTROL_DIR");
    char path[4096]; int target = 0;
    if (!root || snprintf(path, sizeof path, "%s/fault", root) >= (int)sizeof path) return 0;
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    int valid = fscanf(file, "%63s %d", mode, &target) == 2;
    fclose(file);
    return valid && size >= 64 && target == pid;
}
static void event(const char *mode, int pid) {
    const char *root = getenv("SE382_CONTROL_DIR"); char path[4096];
    if (!root || snprintf(path, sizeof path, "%s/calls", root) >= (int)sizeof path) return;
    FILE *file = fopen(path, "a");
    if (file) { fprintf(file, "%s %d\n", mode, pid); fclose(file); }
}
static int path_read(int pid, void *out, uint32_t size) {
    int incoming = errno; char mode[64];
    if (!selected(mode, sizeof mode, pid)) { errno = incoming; return proc_pidpath(pid, out, size); }
    event(mode, pid);
    if (!strcmp(mode, "esrch")) { errno = ESRCH; return 0; }
    if (!strcmp(mode, "denied")) { errno = EACCES; return 0; }
    if (!strcmp(mode, "zero")) { errno = 0; return 0; }
    if (!strcmp(mode, "exec-once")) {
        errno = incoming;
        int count = proc_pidpath(pid, out, size); int saved = errno;
        const char *root = getenv("SE382_CONTROL_DIR"); char path[4096], home[4096];
        snprintf(path, sizeof path, "%s/fault", root); unlink(path);
        snprintf(path, sizeof path, "%s/native-home", root);
        FILE *file = fopen(path, "r");
        if (!file || !fgets(home, sizeof home, file)) { if (file) fclose(file); errno = EIO; return 0; }
        fclose(file); home[strcspn(home, "\r\n")] = 0;
        if (snprintf(path, sizeof path, "%s/exec-child", home) >= (int)sizeof path) { errno = ENAMETOOLONG; return 0; }
        file = fopen(path, "w"); if (!file) return 0; fclose(file);
        if (snprintf(path, sizeof path, "%s/exec-complete", home) >= (int)sizeof path) { errno = ENAMETOOLONG; return 0; }
        for (int n = 0; n < 5000; ++n) {
            if (!access(path, F_OK)) { errno = saved; return count; }
            usleep(1000);
        }
        errno = ETIMEDOUT; return 0;
    }
    errno = incoming; return proc_pidpath(pid, out, size);
}
static int info_read(int pid, int flavor, uint64_t arg, void *out, int size) {
    int incoming = errno; char mode[64];
    int change = selected(mode, sizeof mode, pid) && !strcmp(mode, "birth") && flavor == PROC_PIDTBSDINFO;
    errno = incoming;
    int count = proc_pidinfo(pid, flavor, arg, out, size); int saved = errno;
    if (change && count == (int)sizeof(struct proc_bsdinfo)) {
        ((struct proc_bsdinfo *)out)->pbi_start_tvsec += 1; event(mode, pid);
    }
    errno = saved; return count;
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose[] = {
    { (const void *)path_read, (const void *)proc_pidpath },
    { (const void *)info_read, (const void *)proc_pidinfo },
};
