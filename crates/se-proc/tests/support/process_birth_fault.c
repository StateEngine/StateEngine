/* Process-local Linux OS-boundary fixtures; never alter the real procfs/clock. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
long sysconf(int name) {
    const char *rate=getenv("SE_JUDGE_TICK_RATE");
    if(name==_SC_CLK_TCK && rate){long value=strtol(rate,NULL,10);if(value<=0){errno=EIO;return -1;}return value;}
    union{void *symbol;long(*call)(int);}real;real.symbol=dlsym(RTLD_NEXT,"sysconf");
    if(!real.symbol){errno=ENOSYS;return -1;}return real.call(name);
}
int open64(const char *path,int flags,...) {
    static unsigned int epoch_reads;
    mode_t mode=0;if(flags&O_CREAT){va_list args;va_start(args,flags);mode=va_arg(args,mode_t);va_end(args);}
    if(strcmp(path,"/proc/stat")==0) {
        const char *fixture=getenv("SE_JUDGE_PROC_STAT");
        const char *next=getenv("SE_JUDGE_PROC_STAT_NEXT");
        if(next && epoch_reads++)fixture=next;
        if(fixture){if(strcmp(fixture,"EACCES")==0){errno=EACCES;return -1;}path=fixture;}
    }
    union{void *symbol;int(*call)(const char*,int,...);}real;real.symbol=dlsym(RTLD_NEXT,"open64");
    if(!real.symbol){errno=ENOSYS;return -1;}return real.call(path,flags,mode);
}
