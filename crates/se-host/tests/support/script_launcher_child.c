#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
static void name(char *out, const char *home, const char *leaf) {
    int n = snprintf(out, PATH_MAX, "%s/%s", home, leaf);
    if (n < 0 || n >= PATH_MAX) exit(10);
}
int main(int argc, char **argv) {
    if (argc < 3) return 11;
    char path[PATH_MAX];
    name(path, argv[1], "ready");
    FILE *f = fopen(path, "w");
    if (!f) return 12;
    fprintf(f, "%ld\n%s", (long)getpid(), argv[2]);
    if (fclose(f)) return 13;
    struct timespec pause = {0, 5000000};
    for (int i = 0; i < 6000; ++i) {
        name(path, argv[1], "finish");
        if (access(path, F_OK) == 0) return 0;
        name(path, argv[1], "swap");
        if (argc == 4 && access(path, F_OK) == 0) {
            char *next[] = {argv[3], argv[1], argv[2], NULL};
            execv(argv[3], next);
            return 14;
        }
        nanosleep(&pause, NULL);
    }
    return 15;
}
