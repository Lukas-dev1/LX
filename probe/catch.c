// Minimal debugger: run a command under the Win32 debug API and log every first-chance access violation
// and stack overflow (thread, rip, rsp, faulting address, and what's mapped at rsp). A debugger sees
// exceptions before NT tries to dispatch them in the process, so it also catches faults the process
// itself can't handle (no room on the faulting thread's stack for the exception frame).
// Usage: catch.exe <logfile> <command line...>     (children are debugged too: DEBUG_PROCESS)
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: catch <log> <cmd...>\n"); return 2; }
    FILE *log = fopen(argv[1], "w");
    char cmd[32768] = "";
    for (int i = 2; i < argc; i++) {
        strcat(cmd, "\""); strcat(cmd, argv[i]); strcat(cmd, "\" ");
    }
    STARTUPINFOA si = { sizeof si }; PROCESS_INFORMATION pi;
    if (!CreateProcessA(0, cmd, 0, 0, TRUE, DEBUG_PROCESS, 0, 0, &si, &pi)) { fprintf(stderr, "CreateProcess %lu\n", GetLastError()); return 2; }
    DWORD exit_code = 0, live = 0;
    HANDLE threads[4096] = {0}; DWORD tids[4096] = {0}; int nthreads = 0;
    for (;;) {
        DEBUG_EVENT ev; WaitForDebugEvent(&ev, INFINITE);
        DWORD cont = DBG_CONTINUE;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            live++; CloseHandle(ev.u.CreateProcessInfo.hFile);
            if (nthreads < 4096) { threads[nthreads] = ev.u.CreateProcessInfo.hThread; tids[nthreads++] = ev.dwThreadId; }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (nthreads < 4096) { threads[nthreads] = ev.u.CreateThread.hThread; tids[nthreads++] = ev.dwThreadId; }
            break;
        case LOAD_DLL_DEBUG_EVENT: CloseHandle(ev.u.LoadDll.hFile); break;
        case EXIT_PROCESS_DEBUG_EVENT:
            fprintf(log, "pid %lu exit 0x%lx\n", ev.dwProcessId, ev.u.ExitProcess.dwExitCode); fflush(log);
            if (ev.dwProcessId == pi.dwProcessId) exit_code = ev.u.ExitProcess.dwExitCode;
            live--;
            break;
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD *r = &ev.u.Exception.ExceptionRecord;
            cont = DBG_EXCEPTION_NOT_HANDLED; // let the process's own handlers (lx's VEH) run as usual
            if (r->ExceptionCode == EXCEPTION_BREAKPOINT && ev.u.Exception.dwFirstChance) { cont = DBG_CONTINUE; break; } // loader breakpoint
            if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION && r->ExceptionCode != EXCEPTION_STACK_OVERFLOW
                && r->ExceptionCode != EXCEPTION_GUARD_PAGE) break;
            HANDLE th = 0;
            for (int i = 0; i < nthreads; i++) if (tids[i] == ev.dwThreadId) th = threads[i];
            CONTEXT c = { .ContextFlags = CONTEXT_FULL };
            if (th) GetThreadContext(th, &c);
            HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION, 0, ev.dwProcessId);
            MEMORY_BASIC_INFORMATION m = {0}, mb = {0};
            if (ph) { VirtualQueryEx(ph, (void *)(c.Rsp - 1), &m, sizeof m); VirtualQueryEx(ph, (void *)(c.Rsp - 4096), &mb, sizeof mb); CloseHandle(ph); }
            fprintf(log, "pid %lu tid %lu %s code 0x%lx rip 0x%llx rsp 0x%llx addr 0x%llx | at rsp-1: state 0x%lx prot 0x%lx region 0x%llx+0x%llx | rsp-4K: state 0x%lx prot 0x%lx\n",
                    ev.dwProcessId, ev.dwThreadId, ev.u.Exception.dwFirstChance ? "first" : "LAST", r->ExceptionCode,
                    c.Rip, c.Rsp, r->NumberParameters > 1 ? (unsigned long long)r->ExceptionInformation[1] : 0,
                    m.State, m.Protect, (unsigned long long)m.BaseAddress, (unsigned long long)m.RegionSize, mb.State, mb.Protect);
            fflush(log);
            break;
        }
        }
        if (live == 0 && ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont); break; }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    fclose(log);
    return (int)exit_code;
}
