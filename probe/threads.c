// Probe: where is every thread of a (hung) lx process? threads.exe <pid> suspends each thread, prints its
// rip and rsp, the function it is in and a few frames up (lx's PDB via dbghelp; guest code shows as "-"),
// then resumes it. It found the #102 deadlock: two threads each in NtSuspendThread on the other.
// Build: zig cc -target x86_64-windows-gnu -O1 -o threads.exe threads.c -ldbghelp (lx.pdb next to lx.exe)
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: threads <pid>\n"); return 2; }
    DWORD pid = (DWORD)atoi(argv[1]);
    HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!p) { fprintf(stderr, "OpenProcess %lu\n", GetLastError()); return 2; }
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(p, NULL, TRUE);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof te };
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!t) continue;
        SuspendThread(t);
        CONTEXT c = { 0 };
        c.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(t, &c)) {
            char buf[sizeof(SYMBOL_INFO) + 256] = { 0 };
            SYMBOL_INFO *s = (SYMBOL_INFO *)buf;
            s->SizeOfStruct = sizeof(SYMBOL_INFO);
            s->MaxNameLen = 255;
            DWORD64 disp = 0;
            const char *name = SymFromAddr(p, c.Rip, &disp, s) ? s->Name : "-";
            printf("tid %6lu rip %016llx rsp %016llx rax %llx  %s+%llx\n", te.th32ThreadID, c.Rip, c.Rsp, c.Rax, name, disp);
            // A few return addresses up the stack, for threads parked in Windows code.
            STACKFRAME64 f = { 0 };
            f.AddrPC.Offset = c.Rip; f.AddrPC.Mode = AddrModeFlat;
            f.AddrStack.Offset = c.Rsp; f.AddrStack.Mode = AddrModeFlat;
            f.AddrFrame.Offset = c.Rbp; f.AddrFrame.Mode = AddrModeFlat;
            for (int i = 0; i < 12 && StackWalk64(IMAGE_FILE_MACHINE_AMD64, p, t, &f, &c, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL); i++) {
                if (i == 0) continue;
                const char *n = SymFromAddr(p, f.AddrPC.Offset, &disp, s) ? s->Name : "-";
                printf("        <- %016llx %s+%llx\n", f.AddrPC.Offset, n, disp);
            }
        }
        ResumeThread(t);
        CloseHandle(t);
    }
    return 0;
}
