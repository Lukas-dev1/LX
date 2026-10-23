// Process groups: kill(-pgid) reaches a grandchild too (timeout, LTP and shells rely on it).
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int p[2]; pipe(p);
    pid_t child = fork();
    if (child == 0) {
        setpgid(0, 0);
        if (fork() == 0) { pause(); _exit(0); } // the grandchild holds p[1] until it dies
        pause(); _exit(0);
    }
    close(p[1]);
    setpgid(child, child); // both sides set it, as shells do, so it doesn't matter who runs first
    usleep(300000);
    int same = getpgid(child) == child && getpgid(0) != child;
    kill(-child, SIGTERM);
    alarm(5); // if the grandchild survives, the read below never sees EOF
    char c; ssize_t n = read(p[0], &c, 1);
    int st; waitpid(child, &st, 0);
    printf("pgid=%d eof=%d child=%s\n", same, n == 0, WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM ? "TERM" : "?");
    return same && n == 0 ? 0 : 1;
}
