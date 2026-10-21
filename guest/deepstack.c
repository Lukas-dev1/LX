// Stack growth: recurse ~6 MB deep (the kernel would give Linux programs up to 8 MB), then fork from deep down.
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
static int depth(int n) { volatile char pad[4096]; pad[0] = (char)n; return n == 0 ? pad[0] : depth(n - 1) + (pad[0] & 1); }
int main(void) {
    printf("recursed: %d\n", depth(1500)); // ~6 MB of frames
    pid_t p = fork();
    if (p == 0) { printf("child recursed: %d\n", depth(1500)); return 3; }
    int st; waitpid(p, &st, 0);
    printf("child exit %d\n", WEXITSTATUS(st));
    return 0;
}
