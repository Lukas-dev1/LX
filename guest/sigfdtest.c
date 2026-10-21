// signalfd the way postgres 18's latches use it: SIGURG blocked and read through a signalfd in an epoll
// set; another process's SIGUSR1 runs a handler that kill()s us with SIGURG, which must wake the epoll
// wait at once. Prints "OK <ms>".
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void usr1(int s) { (void)s; kill(getpid(), SIGURG); }

static long ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(void) {
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGURG);
    sigprocmask(SIG_BLOCK, &m, 0);
    signal(SIGUSR1, usr1);
    int sfd = signalfd(-1, &m, SFD_NONBLOCK | SFD_CLOEXEC);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = sfd};
    if (sfd < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev) < 0) { perror("setup"); return 1; }
    pid_t parent = getpid(), kid = fork();
    if (kid == 0) {
        usleep(300 * 1000);
        kill(parent, SIGUSR1);
        _exit(0);
    }
    long t0 = ms();
    int n;
    do n = epoll_wait(ep, &ev, 1, 60000); while (n < 0); // EINTR while the handler runs
    long took = ms() - t0;
    struct signalfd_siginfo si;
    if (n != 1 || read(sfd, &si, sizeof si) != sizeof si || si.ssi_signo != SIGURG) { printf("no SIGURG (n=%d)\n", n); return 1; }
    waitpid(kid, 0, 0);
    if (took > 5000) { printf("slow: %ld ms\n", took); return 1; }
    printf("OK %ld\n", took);
    return 0;
}
