// Faults on non-main threads must be reported, not silently kill the process; deep stacks must work.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void *null_write(void *a) { (void)a; *(volatile int *)0 = 1; return 0; }
static void *big_frame(void *a) { (void)a; volatile char buf[6 << 20]; memset((char *)buf, 1, sizeof buf); return (void *)(long)buf[12345]; }
static int depth(int n) { volatile char pad[4096]; pad[0] = n; return depth(n + 1) + pad[0]; }
static void *overflow(void *a) { (void)a; return (void *)(long)depth(0); }
int main(int argc, char **argv) {
    void *(*f)(void *) = !strcmp(argv[1], "null") ? null_write : !strcmp(argv[1], "big") ? big_frame : overflow;
    pthread_t t; void *r;
    pthread_create(&t, 0, f, 0); pthread_join(t, &r);
    printf("%s: thread returned %ld\n", argv[1], (long)r);
    return 0;
}
