// POSIX timers: a periodic timer_create/timer_settime timer delivers its signal again and again.
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static volatile int hits;
static void on_usr1(int s) { (void)s; hits++; }
int main(void) {
    signal(SIGUSR1, on_usr1);
    struct sigevent ev = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1};
    timer_t t;
    if (timer_create(CLOCK_MONOTONIC, &ev, &t)) { perror("timer_create"); return 1; }
    struct itimerspec its = {.it_interval = {0, 50000000}, .it_value = {0, 50000000}};
    timer_settime(t, 0, &its, 0);
    while (hits < 3) pause();
    struct itimerspec cur;
    timer_gettime(t, &cur);
    timer_delete(t);
    printf("ticks=%d armed=%d\n", hits, cur.it_interval.tv_nsec == 50000000);
    return 0;
}
