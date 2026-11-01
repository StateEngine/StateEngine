/* Only the dedicated child fixture loads this boundary fault. Real NSS is used
 * until its private control file requests EIO; no real account is changed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
int getpwent_r(struct passwd *entry, char *buffer, size_t size, struct passwd **result) {
    const char *path = getenv("SE_ANCESTOR_NSS_CONTROL");
    FILE *control = path ? fopen(path, "r") : NULL;
    int mode = control ? fgetc(control) : EOF;
    if (control) fclose(control);
    if (mode != '0') { *result = NULL; return EIO; }
    typedef int (*lookup)(struct passwd *, char *, size_t, struct passwd **);
    lookup native = (lookup)dlsym(RTLD_NEXT, "getpwent_r");
    if (!native) { *result = NULL; return EIO; }
    return native(entry, buffer, size, result);
}
