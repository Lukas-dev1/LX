#include <windows.h>
#include <stdio.h>
// Busy loop with no syscalls: does preemption alone reset FS base? Run several threads to force switches.
static volatile LONG done;
static DWORD WINAPI spin(LPVOID p) { unsigned long long b = (unsigned long long)p, rd; long long n = 0, lost = 0;
    __asm__ volatile("wrfsbase %0" :: "r"(b));
    ULONGLONG end = GetTickCount64() + 3000; // GetTickCount64 reads shared page, no syscall
    while (GetTickCount64() < end) { __asm__ volatile("rdfsbase %0" : "=r"(rd)); n++; if (rd != b) { lost++; __asm__ volatile("wrfsbase %0" :: "r"(b)); } }
    printf("thread %llx: %lld checks, %lld losses\n", b, n, lost); return 0; }
int main(void) { SYSTEM_INFO si; GetSystemInfo(&si); int t = si.dwNumberOfProcessors * 2; HANDLE h[256];
    for (int i = 0; i < t && i < 256; i++) h[i] = CreateThread(0, 0, spin, (LPVOID)(0x10000ull * (i + 1)), 0, 0);
    WaitForMultipleObjects(t < 64 ? t : 64, h, TRUE, INFINITE); return 0; }
