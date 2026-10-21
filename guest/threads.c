// Threads under lx: condvar start gate, contended mutex, atomics, per-thread TLS, join values,
// a detached thread that unmaps its own stack on exit, and timed waits. Prints OK/FAIL and exits 0/1.
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define N 8
#define ITERS 50000

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static long counter;
static atomic_long acount;
static atomic_int detached_ran;
static int ready;
static __thread long mine; // must be private to each thread

static void *worker(void *arg) {
    long id = (long)arg;
    pthread_mutex_lock(&m);
    while (!ready) pthread_cond_wait(&cv, &m);
    pthread_mutex_unlock(&m);
    for (int i = 0; i < ITERS; i++) {
        mine++;
        atomic_fetch_add(&acount, 1);
        pthread_mutex_lock(&m);
        counter++;
        pthread_mutex_unlock(&m);
    }
    return (void *)(mine * 100 + id);
}

static void *detached(void *arg) {
    (void)arg;
    atomic_store(&detached_ran, 1);
    pthread_exit(0); // musl unmaps this thread's stack, then exits it
}

int main(void) {
    pthread_t t[N];
    int ok = 1;
    for (long i = 0; i < N; i++)
        if (pthread_create(&t[i], 0, worker, (void *)i)) { puts("pthread_create failed"); return 1; }
    usleep(50000); // let them all block on the condvar
    pthread_mutex_lock(&m);
    ready = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&m);
    for (long i = 0; i < N; i++) {
        void *r;
        pthread_join(t[i], &r);
        if ((long)r != ITERS * 100L + i) { printf("thread %ld returned %ld\n", i, (long)r); ok = 0; }
    }

    pthread_t d;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_create(&d, &a, detached, 0);

    // Timed wait that must time out (nobody signals): exercises FUTEX_WAIT with a timeout.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 100 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    pthread_mutex_lock(&m);
    int rc = pthread_cond_timedwait(&cv, &m, &ts);
    pthread_mutex_unlock(&m);
    usleep(50000);

    long want = (long)N * ITERS;
    int pass = ok && counter == want && acount == want && mine == 0 && rc == 110 /* ETIMEDOUT */ && detached_ran;
    printf("counter=%ld atomic=%ld expected=%ld main_tls=%ld timedwait=%d detached=%d %s\n",
           counter, (long)acount, want, mine, rc, (int)detached_ran, pass ? "OK" : "FAIL");
    return pass ? 0 : 1;
}
