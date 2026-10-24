// A signal from tgkill carries si_code SI_TKILL and the sender's pid and uid: glibc's setuid broadcast
// (SIGSETXID) ignores it otherwise, and setuid then waits forever.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile int code, pid, uid = -1;
static void on(int sig, siginfo_t *si, void *uc) { code = si->si_code, pid = si->si_pid, uid = si->si_uid; }

int main(void) {
    struct sigaction sa = {.sa_sigaction = on, .sa_flags = SA_SIGINFO};
    sigaction(SIGUSR1, &sa, 0);
    syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    printf("sitkill tkill=%d pid=%d uid=%d\n", code == SI_TKILL, pid == getpid(), uid == (int)getuid());
    return 0;
}
