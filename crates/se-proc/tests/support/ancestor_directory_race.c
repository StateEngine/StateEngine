/* Directory changes are confined to the parent fixture in this NSS child. */
#include "ancestor_account_switch.c"
#include <grp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
int getgrgid_r(gid_t gid, struct group *entry, char *buffer, size_t size,
               struct group **result) {
    typedef int (*lookup)(gid_t, struct group *, char *, size_t, struct group **);
    lookup native = (lookup)dlsym(RTLD_NEXT, "getgrgid_r");
    if (!native) { *result = NULL; return ENOSYS; }
    int status = native(gid, entry, buffer, size, result);
    const char *parent = getenv("SE_ANCESTOR_RACE_PARENT");
    const char *mode = getenv("SE_ANCESTOR_RACE_MODE");
    static unsigned calls = 0;
    if (status || !*result || !parent || !mode || gid != getegid()) return status;
    if (!strcmp(mode, "continuous") || calls == 0) {
        char path[4096];
        int n=snprintf(path,sizeof(path),"%s/sibling-%u",parent,calls);
        if (n<0 || (size_t)n>=sizeof(path)) { *result=NULL;return EIO; }
        int fd=open(path,O_CREAT|O_EXCL|O_WRONLY,0600);
        if (fd<0) { *result=NULL;return errno; }
        close(fd);
        if (!strcmp(mode,"unsafe") && chmod(parent,0777)) { *result=NULL;return errno; }
    }
    calls++;
    return status;
}
