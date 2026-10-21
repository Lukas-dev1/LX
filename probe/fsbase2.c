#include <windows.h>
#include <stdio.h>
static LONG CALLBACK veh(EXCEPTION_POINTERS *e) {
    printf("exc %lx at rip=%llx addr=%llx\n", e->ExceptionRecord->ExceptionCode, e->ContextRecord->Rip,
           e->ExceptionRecord->NumberParameters > 1 ? e->ExceptionRecord->ExceptionInformation[1] : 0);
    fflush(stdout); ExitProcess(3);
}
int main(void) {
    AddVectoredExceptionHandler(1, veh);
    static unsigned long long slot = 0x1122334455667788ull;
    unsigned long long base = (unsigned long long)&slot, got = 0, rd = 0;
    __asm__ volatile("rdfsbase %0" : "=r"(rd)); printf("initial fsbase=%llx\n", rd); fflush(stdout);
    __asm__ volatile("wrfsbase %0" :: "r"(base));
    __asm__ volatile("movq %%fs:0, %0" : "=r"(got)); printf("immediate read=%llx\n", got); fflush(stdout);
    for (int i = 0; i < 200; i++) {
        Sleep(1);
        __asm__ volatile("rdfsbase %0" : "=r"(rd));
        if (rd != base) { printf("fsbase changed after %d sleeps -> %llx\n", i, rd); return 2; }
    }
    puts("survives"); return 0;
}
