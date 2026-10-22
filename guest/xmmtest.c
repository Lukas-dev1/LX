// Linux preserves every vector register across a syscall; compilers keep values in xmm across the
// inline `syscall` of libc wrappers. Load xmm0-15 with patterns, make syscalls that keep lx busy
// (uname, write, getcwd) in the same asm block, and check nothing changed.
// Prints "xmm OK" or the first clobbered register.
#include <stdio.h>
#include <string.h>

int main(void) {
    static char buf[4096] __attribute__((aligned(16)));
    static unsigned long long in[16][2], out[16][2];
    for (int i = 0; i < 16; i++) {
        in[i][0] = 0x0123456789abcdefULL ^ (unsigned long long)i * 0x1111111111111111ULL;
        in[i][1] = ~in[i][0];
    }
    for (int round = 0; round < 300; round++) {
        long nr = round % 3 == 0 ? 63 : round % 3 == 1 ? 1 : 79; // uname, write, getcwd
        long a0 = nr == 1 ? 1 : (long)buf, a1 = nr == 1 ? (long)"" : (long)sizeof buf, a2 = 0;
        __asm__ volatile(
            "movdqu 0(%[i]), %%xmm0\n movdqu 16(%[i]), %%xmm1\n movdqu 32(%[i]), %%xmm2\n movdqu 48(%[i]), %%xmm3\n"
            "movdqu 64(%[i]), %%xmm4\n movdqu 80(%[i]), %%xmm5\n movdqu 96(%[i]), %%xmm6\n movdqu 112(%[i]), %%xmm7\n"
            "movdqu 128(%[i]), %%xmm8\n movdqu 144(%[i]), %%xmm9\n movdqu 160(%[i]), %%xmm10\n movdqu 176(%[i]), %%xmm11\n"
            "movdqu 192(%[i]), %%xmm12\n movdqu 208(%[i]), %%xmm13\n movdqu 224(%[i]), %%xmm14\n movdqu 240(%[i]), %%xmm15\n"
            "syscall\n"
            "movdqu %%xmm0, 0(%[o])\n movdqu %%xmm1, 16(%[o])\n movdqu %%xmm2, 32(%[o])\n movdqu %%xmm3, 48(%[o])\n"
            "movdqu %%xmm4, 64(%[o])\n movdqu %%xmm5, 80(%[o])\n movdqu %%xmm6, 96(%[o])\n movdqu %%xmm7, 112(%[o])\n"
            "movdqu %%xmm8, 128(%[o])\n movdqu %%xmm9, 144(%[o])\n movdqu %%xmm10, 160(%[o])\n movdqu %%xmm11, 176(%[o])\n"
            "movdqu %%xmm12, 192(%[o])\n movdqu %%xmm13, 208(%[o])\n movdqu %%xmm14, 224(%[o])\n movdqu %%xmm15, 240(%[o])\n"
            : "+a"(nr)
            : [i] "r"(in), [o] "r"(out), "D"(a0), "S"(a1), "d"(a2)
            : "rcx", "r11", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
              "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
        for (int i = 0; i < 16; i++) {
            if (memcmp(in[i], out[i], 16) != 0) {
                printf("xmm%d clobbered (round %d)\n", i, round);
                return 1;
            }
        }
    }
    printf("xmm OK\n");
    return 0;
}
