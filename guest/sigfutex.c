// A process-wide signal reaches a program whose threads are all parked in futex waits (Go's idle
// state): the main thread blocks in pthread_join on a thread that waits on a condition forever, and a
// forked child sends SIGTERM to the parent from outside.
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c = PTHREAD_COND_INITIALIZER;

static void on_term(int sig) {
    (void)sig;
    static const char msg[] = "sigfutex OK\n";
    write(1, msg, sizeof msg - 1);
    _exit(0);
}

static void *waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&m);
    for (;;) pthread_cond_wait(&c, &m);
    return 0;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, 0);
    pthread_t t;
    pthread_create(&t, 0, waiter, 0);
    if (fork() == 0) {
        usleep(300 * 1000); // let the parent park
        kill(getppid(), SIGTERM);
        _exit(0);
    }
    pthread_join(t, 0); // a futex wait that never ends on its own
    printf("not reached\n");
    return 1;
}
