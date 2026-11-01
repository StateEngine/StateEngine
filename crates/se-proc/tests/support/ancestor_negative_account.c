/* The existing NSS fault stays confined to the dedicated fixture child. */
#include "ancestor_account_switch.c"
#include <grp.h>

int getgrgid_r(gid_t gid, struct group *entry, char *buffer, size_t size,
               struct group **result) {
    typedef int (*lookup)(gid_t, struct group *, char *, size_t, struct group **);
    lookup native = (lookup)dlsym(RTLD_NEXT, "getgrgid_r");
    if (!native) { *result = NULL; return ENOSYS; }
    int status = native(gid, entry, buffer, size, result);
    if (status != 0 || !*result) return status;
    const char *path = getenv("SE_ANCESTOR_NSS_CONTROL");
    FILE *control = path ? fopen(path, "r") : NULL;
    int mode = control ? fgetc(control) : EOF;
    if (control) fclose(control);
    if (mode == 'F') {
        static char foreign[] = "stateengine-test-foreign-member";
        static char *members[] = {foreign, NULL};
        entry->gr_mem = members;
    }
    return status;
}
