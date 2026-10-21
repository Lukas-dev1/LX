// Probe: can user mode set the FS base (wrfsbase) on this Windows, and does it survive context switches?
#include <windows.h>
#include <stdio.h>

static volatile int faulted;
static LONG CALLBACK veh(EXCEPTION_POINTERS *e) {
    if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        faulted = 1; e->ContextRecord->Rip += 5; // wrfsbase rax = f3 48 0f ae d0
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);
    static unsigned long long slot = 0x1122334455667788ull;
    unsigned long long base = (unsigned long long)&slot, got = 0;
    __asm__ volatile("wrfsbase %0" :: "r"(base));
    if (faulted) { puts("wrfsbase: FAULT (FSGSBASE not enabled for user mode)"); return 1; }
    for (int i = 0; i < 200; i++) {
        Sleep(1);
        __asm__ volatile("movq %%fs:0, %0" : "=r"(got));
        if (got != slot) { printf("fs lost after %d switches: %llx\n", i, got); return 2; }
    }
    puts("wrfsbase: OK, survives context switches");
    return 0;
}
