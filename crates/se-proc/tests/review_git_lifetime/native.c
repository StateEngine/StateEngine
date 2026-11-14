/* Native observation/fault boundary for a reviewer-owned executable. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char evidence[4096];
static int fault_mode;

void review_configure(const char *root, int mode) {
    if (snprintf(evidence, sizeof(evidence), "%s/fault-events-%d.jsonl", root, getpid()) >= (int)sizeof(evidence)) _exit(91);
    fault_mode = mode;
}

#ifndef REVIEW_OBSERVER_ONLY
static void event(const char *kind, int target) {
    int fd = open(evidence, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) _exit(92);
    dprintf(fd, "{\"kind\":\"%s\",\"actor\":%d,\"target\":%d}\n", kind, getpid(), target);
    int children[16] = {0};
    int count = proc_listchildpids(getpid(), children, sizeof(children));
    for (int i=0; i<count && i<16; ++i) {
        struct proc_bsdinfo info = {0};
        char image[PROC_PIDPATHINFO_MAXSIZE] = {0};
        if (proc_pidinfo(children[i], PROC_PIDTBSDINFO, 1, &info, sizeof(info)) != (int)sizeof(info)) continue;
        if (proc_pidpath(children[i], image, sizeof(image)) <= 0) continue;
        /* Child image is independently checked against the copied fixture by the controller. */
        dprintf(fd, "{\"kind\":\"child\",\"pid\":%d,\"ppid\":%u,\"seconds\":%llu,\"micros\":%llu}\n",
                children[i], info.pbi_ppid, info.pbi_start_tvsec, info.pbi_start_tvusec);
    }
    fsync(fd);
    close(fd);
}

int proc_pid_rusage(int pid, int flavor, rusage_info_t *buffer) {
    static int (*actual)(int,int,rusage_info_t*);
    if (!actual) actual = dlsym(RTLD_NEXT, "proc_pid_rusage");
    if (!actual) _exit(93);
    if (fault_mode == 1) { event("first-unreadable",pid); fault_mode=0; errno=EPERM; return -1; }
    int result = actual(pid, flavor, buffer);
    if (fault_mode == 2 && result == 0 && flavor == RUSAGE_INFO_V4) {
        event("first-over-budget",pid); fault_mode=0;
        ((struct rusage_info_v4 *)buffer)->ri_lifetime_max_phys_footprint=80ULL*1024*1024;
    }
    return result;
}
int kill(pid_t pid, int number) {
    static int (*actual)(pid_t,int);
    if (!actual) actual = dlsym(RTLD_NEXT, "kill");
    if (!actual) _exit(94);
    if (fault_mode == 3 && number == SIGKILL) { event("kill-denied",pid); errno=EPERM; return -1; }
    return actual(pid,number);
}
#endif

uint64_t review_peak(int pid) {
    struct rusage_info_v4 usage={0};
    if (proc_pid_rusage(pid,RUSAGE_INFO_V4,(rusage_info_t*)&usage)<0) return UINT64_MAX;
    return usage.ri_lifetime_max_phys_footprint > usage.ri_resident_size ? usage.ri_lifetime_max_phys_footprint : usage.ri_resident_size;
}

#ifdef REVIEW_PROBE
int main(int argc, char **argv) {
    char mode=argc>1 ? argv[argc-1][0] : '0';
    struct rlimit cpu={0},fds={0};
    if (getrlimit(RLIMIT_CPU,&cpu) || getrlimit(RLIMIT_NOFILE,&fds)) return 80;
    dprintf(1,"{\"cpu_soft\":%llu,\"cpu_hard\":%llu,\"fd_soft\":%llu,\"fd_hard\":%llu}\n",
            cpu.rlim_cur,cpu.rlim_max,fds.rlim_cur,fds.rlim_max);
    if (mode=='0') return 0;
    if (mode=='4' || mode=='5') {
        char output[4096]; memset(output,'x',sizeof(output));
        int fd=mode=='4'?1:2;
        for (int i=0;i<(mode=='4'?18:2);i++) if (write(fd,output,sizeof(output))<0) return 81;
    }
    if (mode=='2') {
        volatile char *memory=malloc(96ULL*1024*1024);
        if (!memory) return 82;
        for (size_t n=0;n<96ULL*1024*1024;n+=4096) memory[n]=1;
    }
    if (mode=='1') { volatile uint64_t count=0; for (;;) count++; }
    for (;;) usleep(10000);
}
#endif
