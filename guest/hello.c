#include <stdio.h>
__thread int tls_counter = 41; // forces a real %fs: access
int main(int argc, char **argv) {
    tls_counter++;
    printf("hello from linux, argv[0]=%s tls=%d\n", argv[0], tls_counter);
    return 7;
}
