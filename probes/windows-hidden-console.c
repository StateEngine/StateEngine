#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    const char *x = "\"C:\\Program Files (x86)\\Windows Kits\\10\\Windows Performance Toolkit\\xperf.exe\"";
    char command[2048], line[8192];
    snprintf(command, sizeof(command), "%s -on PROC_THREAD+CSWITCH", x);
    int start = system(command); printf("trace_start=%d\n", start); if (start) return 2;
    Sleep(2000);
    snprintf(command, sizeof(command), "%s -d idle-format.etl", x);
    int stop = system(command); printf("trace_stop=%d\n", stop); if (stop) return 3;
    snprintf(command, sizeof(command), "%s -i idle-format.etl -o idle-format.txt -a dumper", x);
    int dump = system(command); printf("trace_dump=%d\n", dump); if (dump) return 4;
    FILE *input = fopen("idle-format.txt", "r"); if (!input) return 5;
    unsigned headers = 0, switches = 0, threads = 0;
    while (fgets(line, sizeof(line), input)) {
        if (headers++ < 80) printf("HEADER: %s", line);
        if (strstr(line, "CSwitch") && switches++ < 6) printf("SWITCH: %s", line);
        if ((strstr(line, "Thread/Start") || strstr(line, "Thread/DCStart")) && threads++ < 6) printf("THREAD: %s", line);
    }
    fclose(input);
    printf("diagnostic finished; intentionally stop before product build\n");
    return 1;
}
