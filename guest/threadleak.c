// Threads that end give back what lx kept for them (a 0.5 MB host stack and their state each): a server
// starting a thread per connection must not grow without bound. Measured as VmSize from /proc/self/status.
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void *work(void *_) { usleep(1000); return 0; }

static void run(int n) {
    for (int i = 0; i < n; i += 20) {
        pthread_t t[20];
        for (int k = 0; k < 20; k++) pthread_create(&t[k], 0, work, 0);
        for (int k = 0; k < 20; k++) pthread_join(t[k], 0);
    }
}

static long vm_kb(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long kb = -1;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "VmSize:", 7)) sscanf(line + 7, "%ld", &kb);
    if (f) fclose(f);
    return kb;
}

int main(void) {
    run(100);
    long a = vm_kb();
    run(1000);
    long b = vm_kb();
    printf("threadleak growth-mb=%ld bounded=%d\n", (b - a) / 1024, b - a < 64 * 1024);
    return 0;
}
