// waitid: P_PID with WEXITED, WNOWAIT (the child stays waitable), a death by signal, WNOHANG with none ready.
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    pid_t a = fork();
    if (a == 0) _exit(7);
    siginfo_t si = {0};
    waitid(P_PID, a, &si, WEXITED | WNOWAIT);
    int peek = si.si_pid == a && si.si_code == CLD_EXITED && si.si_status == 7;
    si = (siginfo_t){0};
    waitid(P_ALL, 0, &si, WEXITED);
    int reap = si.si_pid == a && si.si_status == 7;
    pid_t b = fork();
    if (b == 0) { pause(); _exit(0); }
    kill(b, SIGKILL);
    si = (siginfo_t){0};
    waitid(P_PID, b, &si, WEXITED);
    int killed = si.si_code == CLD_KILLED && si.si_status == SIGKILL;
    pid_t c = fork();
    if (c == 0) { sleep(2); _exit(0); }
    si = (siginfo_t){0};
    int none = waitid(P_PID, c, &si, WEXITED | WNOHANG) == 0 && si.si_pid == 0;
    kill(c, SIGKILL); waitpid(c, 0, 0);
    printf("peek=%d reap=%d killed=%d none=%d\n", peek, reap, killed, none);
    return !(peek && reap && killed && none);
}
