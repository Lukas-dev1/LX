// fork, reap, fork again: a new child must not get the pid of one reaped shortly before, which may still
// be a process group's id (a runner's late `kill -9 -$pgid`). Linux allocates pids sequentially; Windows
// hands a freed one out again soon (about one fork in ten here, without lx's guard).
#include <stdio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    enum { N = 1000 };
    static pid_t seen[N];
    static time_t when[N];
    int reused = 0;
    for (int i = 0; i < N; i++) {
        pid_t p = fork();
        if (p == 0) {
            setpgid(0, 0); // its own group, as test runners do
            _exit(0);
        }
        waitpid(p, 0, 0);
        time_t now = time(0);
        for (int j = 0; j < i; j++)
            if (seen[j] == p && now - when[j] < 50) { reused++; break; } // reaped under 50 s ago
        seen[i] = p, when[i] = now;
    }
    printf("pidreuse reused=%d\n", reused);
    return 0;
}
