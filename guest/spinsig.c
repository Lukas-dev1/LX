// A handled signal reaches a thread spinning in guest code (no syscalls to take it at): Linux interrupts
// it; LTP's timer tests, Go's preemption and GC suspension signals rely on that.
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
static volatile int caught, worker_caught, stop;
static void on_alrm(int s) { (void)s; caught = 1; }
static void on_usr1(int s) { (void)s; worker_caught = 1; }
static void *spin(void *a) { (void)a; while (!worker_caught) {} return 0; }
int main(void) {
    signal(SIGALRM, on_alrm);
    signal(SIGUSR1, on_usr1);
    alarm(1);
    while (!caught) {} // the main thread, spinning
    pthread_t t;
    pthread_create(&t, 0, spin, 0);
    usleep(200000);
    pthread_kill(t, SIGUSR1); // a thread spinning, signalled alone
    pthread_join(t, 0);
    printf("main=%d worker=%d\n", caught, worker_caught);
    return 0;
}
