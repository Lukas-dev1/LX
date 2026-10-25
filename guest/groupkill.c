// kill(-pgid, SIGKILL) reaches every member: a child, its children, and those orphaned when their parent
// died first (a test runner's cleanup after a timeout; `docker stop` of a container's process tree).
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    volatile pid_t *pids = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t leader = fork();
    if (leader == 0) {
        setpgid(0, 0);
        for (int i = 0; i < 4; i++) {
            pid_t k = fork();
            if (k == 0) {
                if (i == 3 && fork() == 0) { pids[10] = getpid(); for (;;) pause(); } // a grandchild
                pids[i + 1] = getpid();
                for (;;) pause();
            }
        }
        pids[0] = 1;
        for (;;) pause();
    }
    while (!pids[0] || !pids[4] || !pids[10]) usleep(10000);
    kill(pids[4], SIGKILL); // the grandchild's parent dies first: it's orphaned, still in the group
    usleep(200000);
    kill(-leader, SIGKILL);
    usleep(500000);
    int alive = 0;
    for (int i = 1; i <= 10; i++)
        if (pids[i] && i != 4 && kill(pids[i], 0) == 0) alive++;
    waitpid(leader, 0, 0);
    printf("groupkill alive=%d\n", alive);
    return 0;
}
