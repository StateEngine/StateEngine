/* Process-local native ABI faults. The outside observer is a separate process. */
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
static int fault(char *out, size_t size, int *pid) {
    const char *root = getenv("SE_MACOS_JUDGE_ROOT");
    if (!root) return 0;
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/fault", root) >= (int)sizeof(path)) return 0;
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    int found = fgets(out, (int)size, file) != NULL;
    fclose(file);
    if (!found) return 0;
    if (snprintf(path, sizeof(path), "%s/fault-pid", root) >= (int)sizeof(path)) return 0;
    file = fopen(path, "r");
    if (!file) return 0;
    found = fscanf(file, "%d", pid) == 1;
    fclose(file);
    return found;
}
static int fixture_info(int pid, int flavor, uint64_t arg, void *out, int size) {
    char mode[32]; int target = 0;
    if (fault(mode, sizeof(mode), &target) && pid == target && flavor == PROC_PIDTBSDINFO) {
        if (strcmp(mode, "denied") == 0) { errno = EACCES; return 0; }
        if (strcmp(mode, "short") == 0) { errno = 0; return size - 1; }
        if (strcmp(mode, "zero") == 0) { memset(out, 0, (size_t)size); errno = 0; return size; }
        if (strcmp(mode, "replacement") == 0) {
            int count = proc_pidinfo(pid, flavor, arg, out, size);
            if (count == (int)sizeof(struct proc_bsdinfo)) ((struct proc_bsdinfo *)out)->pbi_start_tvsec += 1;
            return count;
        }
    }
    return proc_pidinfo(pid, flavor, arg, out, size);
}
static int fixture_list(uint32_t type, uint32_t selector, void *out, int size) {
    char mode[32]; int target = 0;
    if (fault(mode, sizeof(mode), &target) && strcmp(mode, "enumeration") == 0) { errno = EACCES; return 0; }
    return proc_listpids(type, selector, out, size);
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } interpose[] = {
    { (const void *)fixture_info, (const void *)proc_pidinfo },
    { (const void *)fixture_list, (const void *)proc_listpids },
};
