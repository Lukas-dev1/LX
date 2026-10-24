// int3 in guest code is SIGTRAP (si_code SI_KERNEL) with the saved rip just past it, as Linux reports it:
// Go's debugger-call protocol (runtime TestDebugCall) and assert macros that trap rely on it.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <ucontext.h>

static volatile int hit, code;
static volatile unsigned long rip;
static void on(int sig, siginfo_t *si, void *uc) {
    hit++, code = si->si_code;
    rip = ((ucontext_t *)uc)->uc_mcontext.gregs[REG_RIP];
}

int main(void) {
    struct sigaction sa = {.sa_sigaction = on, .sa_flags = SA_SIGINFO};
    sigaction(SIGTRAP, &sa, 0);
    unsigned long after;
    __asm__ volatile("lea 1f(%%rip), %0\n\tint3\n1:" : "=r"(after));
    printf("sigtrap hit=%d kernel=%d rip=%d\n", hit, code == 0x80, rip == after);
    return 0;
}
