// Syscall round-trip cost: N raw getppid() calls (never cached by libc), timed with the monotonic clock.
#include <stdio.h>
#include <time.h>

int main(void) {
    enum { N = 200000 };
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < N; i++) {
        long r;
        __asm__ volatile("mov $110, %%eax\n\tsyscall" : "=a"(r) : : "rcx", "r11", "memory");
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double ns = ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / N;
    printf("%d syscalls, %.0f ns each\n", N, ns);
    return 0;
}
