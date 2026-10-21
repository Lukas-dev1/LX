// lx must not write below a thread's stack pointer during syscalls (a Linux kernel never does).
// Each checker fills 16 KiB below its rsp with a pattern, then, in pure assembly (no stack use at all),
// makes thousands of syscalls and re-checks every byte. Runs on the main thread and 4 threads at once,
// while a signal thread fires SIGUSR1 at the process (handlers run on sigaltstack, so a legitimate
// signal frame never lands in the pattern either), and once more inside a forked child.
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATTERN_BYTES 16384
#define ITERS 20000

static atomic_int signals_seen, stop_signals;

// Fill [rsp-16-PATTERN_BYTES, rsp-16) with a pattern, do ITERS rounds of getpid + sched_yield +
// clock_gettime (into a buffer off-stack), then count corrupted qwords. Uses registers only.
static long check_stack(void *ts_buf) {
    long bad;
    __asm__ volatile(
        "mov %%rsp, %%r8\n\t"
        "lea -16(%%rsp), %%r9\n\t"                        // pattern top (leave 16 bytes of slack)
        "mov %[n], %%r10\n\t"
        "movabs $0x5a5aa5a5c3c33c3c, %%r11\n\t"
        "mov %%r9, %%rdx\n\t"
        "1: sub $8, %%rdx\n\t mov %%r11, (%%rdx)\n\t dec %%r10\n\t jnz 1b\n\t"
        "mov %[iters], %%r12\n\t"
        "2:\n\t"
        "mov $39, %%eax\n\t syscall\n\t"                  // getpid
        "mov $24, %%eax\n\t syscall\n\t"                  // sched_yield
        "mov $228, %%eax\n\t xor %%edi, %%edi\n\t mov %[ts], %%rsi\n\t syscall\n\t" // clock_gettime
        "dec %%r12\n\t jnz 2b\n\t"
        "xor %%rax, %%rax\n\t"
        "mov %[n], %%r10\n\t"
        "mov %%r9, %%rdx\n\t"
        "movabs $0x5a5aa5a5c3c33c3c, %%r11\n\t"
        "3: sub $8, %%rdx\n\t cmp %%r11, (%%rdx)\n\t je 4f\n\t inc %%rax\n\t 4: dec %%r10\n\t jnz 3b\n\t"
        "mov %%r8, %%rsp\n\t"
        : "=a"(bad)
        : [n] "i"(PATTERN_BYTES / 8), [iters] "i"(ITERS), [ts] "m"(ts_buf)
        : "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "memory", "cc");
    return bad;
}

static void on_usr1(int sig) { (void)sig; atomic_fetch_add(&signals_seen, 1); getpid(); }

static void use_altstack(void) {
    stack_t ss = { .ss_sp = malloc(65536), .ss_size = 65536, .ss_flags = 0 };
    sigaltstack(&ss, 0);
}

static void *checker(void *arg) {
    use_altstack();
    long ts[2];
    long bad = check_stack(ts);
    *(long *)arg = bad;
    return 0;
}

static void *signaller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop_signals)) { kill(getpid(), SIGUSR1); usleep(200); }
    return 0;
}

int main(void) {
    struct sigaction sa = { .sa_handler = on_usr1, .sa_flags = SA_ONSTACK | SA_RESTART };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, 0);
    use_altstack();

    pthread_t t[4], s;
    long bad[5] = {0};
    pthread_create(&s, 0, signaller, 0);
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, checker, &bad[i]);
    long ts[2];
    bad[4] = check_stack(ts);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);

    // Fork while the other machinery (signal thread, patched code) is live; the child checks its own stack.
    pid_t p = fork();
    if (p == 0) _exit(check_stack(ts) == 0 ? 0 : 1);
    int st = 0;
    waitpid(p, &st, 0);
    atomic_store(&stop_signals, 1);
    pthread_join(s, 0);

    long total = 0;
    for (int i = 0; i < 5; i++) total += bad[i];
    int child_ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("corrupted qwords: main %ld, threads %ld %ld %ld %ld; forked child %s; signals handled %d %s\n",
           bad[4], bad[0], bad[1], bad[2], bad[3], child_ok ? "clean" : "CORRUPTED", atomic_load(&signals_seen),
           total == 0 && child_ok && atomic_load(&signals_seen) > 0 ? "OK" : "FAIL");
    return total == 0 && child_ok ? 0 : 1;
}
