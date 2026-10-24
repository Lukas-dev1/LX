// setegid/setuid with other threads: libc signals each thread (glibc SIGSETXID, musl __synccall) and waits
// for all to make the change. A thread blocked in a wait must still run that handler (gosu, Go with cgo).
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c = PTHREAD_COND_INITIALIZER;
static void *waiter(void *_) { pthread_mutex_lock(&m); pthread_cond_wait(&c, &m); pthread_mutex_unlock(&m); return 0; }
static void *sleeper(void *_) { sleep(30); return 0; }
static void *spinner(void *_) { for (volatile long i = 0;; i++) {} return 0; }

int main(void) {
    pthread_t t[3];
    pthread_create(&t[0], 0, waiter, 0);
    pthread_create(&t[1], 0, sleeper, 0);
    pthread_create(&t[2], 0, spinner, 0);
    usleep(100000);
    alarm(10); // a hang dies instead of waiting forever
    int r = setegid(1);
    int g = getegid();
    int r2 = setegid(0);
    printf("setxid r=%d egid=%d back=%d\n", r, g, r2);
    return 0;
}
