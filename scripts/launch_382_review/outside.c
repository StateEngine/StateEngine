/* Read-only independent original-birth observer, never a stop authority. */
#include <errno.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int pid = atoi(argv[1]); if (pid <= 0) return 2;
    struct proc_bsdinfo value = {0}; errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 1, &value, sizeof value);
    int cause = errno;
    if (count == 0 && cause == ESRCH) { puts("{\"state\":\"absent\"}"); return 0; }
    if (count != (int)sizeof value || value.pbi_pid != (unsigned)pid) return 3;
    printf("{\"state\":\"record\",\"pid\":%u,\"parent\":%u,\"status\":%u,\"seconds\":%llu,\"microseconds\":%llu}\n",
        value.pbi_pid, value.pbi_ppid, value.pbi_status,
        (unsigned long long)value.pbi_start_tvsec, (unsigned long long)value.pbi_start_tvusec);
    return 0;
}
