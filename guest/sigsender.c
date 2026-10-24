// A signal from kill() carries its sender: si_code SI_USER, si_pid the sender's pid, si_uid its uid
// (daemons ignore signals from anyone but their parent; LTP's kill10 checks who signalled).
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int code = -1, pid, uid = -1;
static void on(int sig, siginfo_t *si, void *uc) { code = si->si_code, pid = si->si_pid, uid = si->si_uid; }

int main(void) {
    struct sigaction sa = {.sa_sigaction = on, .sa_flags = SA_SIGINFO};
    sigaction(SIGUSR1, &sa, 0);
    pid_t parent = getpid(), c = fork();
    if (c == 0) {
        kill(parent, SIGUSR1);
        _exit(0);
    }
    while (code == -1) pause();
    int child = code == SI_USER && pid == c && uid == (int)getuid();
    waitpid(c, 0, 0);
    code = -1;
    kill(getpid(), SIGUSR1);
    int self = code == SI_USER && pid == getpid();
    printf("sigsender child=%d self=%d\n", child, self);
    return 0;
}
