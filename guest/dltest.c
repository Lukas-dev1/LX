// Code loaded (and patched by lx) while other threads run: 4 threads hammer libc syscalls and errno (TLS)
// while the main thread dlopen()s, uses and dlclose()s libraries over and over. Prints OK/FAIL.
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static atomic_int stop;
static atomic_long calls;

static void *hammer(void *arg) {
    (void)arg;
    long n = 0;
    while (!atomic_load(&stop)) {
        if (getppid() < 0) return (void *)1;
        errno = 0;
        if (close(-1) != -1 || errno != EBADF) return (void *)1; // errno lives in TLS
        n++;
    }
    atomic_fetch_add(&calls, n);
    return 0;
}

int main(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, hammer, 0);
    int loads = 0, ok = 1;
    for (int round = 0; round < 30; round++) {
        void *z = dlopen("libz.so.1", RTLD_NOW | RTLD_LOCAL);
        void *c = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
        if (!z || !c) { printf("dlopen: %s\n", dlerror()); ok = 0; break; }
        const char *(*zver)(void) = (const char *(*)(void))dlsym(z, "zlibVersion");
        unsigned long (*ossl)(void) = (unsigned long (*)(void))dlsym(c, "OpenSSL_version_num");
        if (!zver || !ossl || strncmp(zver(), "1.", 2) != 0 || ossl() == 0) { ok = 0; break; }
        loads += 2;
        dlclose(c);
        dlclose(z);
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < 4; i++) {
        void *r;
        pthread_join(t[i], &r);
        if (r) ok = 0;
    }
    printf("%d library loads while 4 threads made %ld syscalls %s\n", loads, atomic_load(&calls) * 2, ok ? "OK" : "FAIL");
    return !ok;
}
