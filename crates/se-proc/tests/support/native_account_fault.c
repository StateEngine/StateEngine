/* Linux NSS boundary fixture, compiled as a process-local LD_PRELOAD library.
 * getgrgid still observes the real empty gr_mem. The first enumerated passwd
 * either adds an account with our primary GID, or returns EIO when
 * SE_JUDGE_NSS_ERROR=1. Neither mode changes /etc or a real account. */
#define _GNU_SOURCE
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int getpwent_r(struct passwd *entry, char *buffer, size_t size, struct passwd **result) {
    const char *name = "other-primary-member-judge";
    if (getenv("SE_JUDGE_NSS_ERROR")) { *result = NULL; return EIO; }
    if (size < strlen(name) + 1) { *result = NULL; return ERANGE; }
    memset(entry, 0, sizeof(*entry));
    strcpy(buffer, name);
    entry->pw_name = buffer;
    entry->pw_gid = getgid();
    entry->pw_uid = geteuid() + 1;
    *result = entry;
    return 0;
}
