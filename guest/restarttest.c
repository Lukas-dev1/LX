// SA_RESTART: a read() interrupted by a handled signal continues instead of failing with EINTR.
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
static volatile int hits;
static void on_alarm(int s) { (void)s; hits++; }
int main(void) {
    int p[2]; pipe(p);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm; sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, 0);
    if (fork() == 0) { usleep(600000); write(p[1], "x", 1); _exit(0); }
    close(p[1]);
    ualarm(200000, 0); // interrupts the read below
    char c; ssize_t n = read(p[0], &c, 1);
    printf("read=%zd errno=%s hits=%d\n", n, n < 0 ? strerror(errno) : "-", hits);
    return n == 1 ? 0 : 1;
}
