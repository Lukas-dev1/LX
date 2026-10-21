// Hammers %fs: TLS across preemption + syscalls; then a real segfault must be reported, not looped on.
#include <stdio.h>
#include <unistd.h>
__thread volatile unsigned long tls;
int main(int argc, char **argv) {
    unsigned long sum = 0;
    for (unsigned long i = 0; i < 400000000UL; i++) {
        tls = i; sum += tls;
        if (i % 50000000 == 0) write(1, ".", 1);
    }
    printf("\nsum=%lu tls=%lu\n", sum, tls);
    fflush(stdout);
    if (argc > 1) *(volatile int *)0 = 1; // "crash" arg: a real fault must be reported, not retried forever
    return 0;
}
