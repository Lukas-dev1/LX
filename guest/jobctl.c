// Job control: SIGSTOP stops a child (its threads stop making progress), waitpid(WUNTRACED) reports it,
// SIGCONT continues it (WCONTINUED), and a child that raises SIGSTOP itself shows as CLD_STOPPED to waitid.
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    volatile long *count = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t c = fork();
    if (c == 0) {
        for (;;) (*count)++; // spins in guest code: has to be stopped there
    }
    usleep(100000);
    kill(c, SIGSTOP);
    int st = 0;
    int stopped = waitpid(c, &st, WUNTRACED) == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP;
    long a = *count;
    usleep(200000);
    int frozen = *count == a;
    kill(c, SIGCONT);
    int cont = waitpid(c, &st, WCONTINUED) == c && WIFCONTINUED(st);
    usleep(100000);
    int moving = *count != a;
    kill(c, SIGKILL);
    int killed = waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;

    pid_t s = fork();
    if (s == 0) {
        raise(SIGSTOP);
        _exit(7); // after SIGCONT
    }
    siginfo_t si = {0};
    int self = waitid(P_PID, s, &si, WSTOPPED) == 0 && si.si_code == CLD_STOPPED && si.si_status == SIGSTOP;
    kill(s, SIGCONT);
    int after = waitpid(s, &st, 0) == s && WIFEXITED(st) && WEXITSTATUS(st) == 7;
    printf("jobctl stopped=%d frozen=%d cont=%d moving=%d killed=%d self=%d after=%d\n", stopped, frozen, cont, moving, killed, self, after);
    return 0;
}
