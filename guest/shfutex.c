// A futex in MAP_SHARED memory, waited on by a child and woken by the parent without changing the value,
// the way LTP's checkpoints do: FUTEX_WAKE must reach the other process and report how many it woke.
#include <linux/futex.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static long futex(unsigned *u, int op, unsigned v, struct timespec *t) { return syscall(SYS_futex, u, op, v, t, 0, 0); }
int main(void) {
    unsigned *f = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *f = 0;
    pid_t c = fork();
    if (c == 0) {
        struct timespec t = {5, 0};
        _exit(futex(f, FUTEX_WAIT, 0, &t) == 0 ? 0 : 1); // woken, not timed out
    }
    int tries = 0;
    while (futex(f, FUTEX_WAKE, 1, 0) != 1 && tries++ < 3000) usleep(1000);
    int st; waitpid(c, &st, 0);
    printf("woke=%d child=%d\n", tries < 3000, WEXITSTATUS(st));
    return tries < 3000 && WEXITSTATUS(st) == 0 ? 0 : 1;
}
