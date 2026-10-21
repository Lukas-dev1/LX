// Syscall cost: time N cheap syscalls (getppid) and N 1-byte writes to /dev/null.
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 200000;
    int fd = open("/dev/null", O_WRONLY);
    double t0 = now();
    for (int i = 0; i < n; i++) syscall(SYS_getppid);
    double t1 = now();
    for (int i = 0; i < n; i++) write(fd, "x", 1);
    double t2 = now();
    printf("getppid: %.0f ns/call   write(/dev/null): %.0f ns/call   (n=%d)\n", (t1 - t0) / n, (t2 - t1) / n, n);
    return 0;
}
