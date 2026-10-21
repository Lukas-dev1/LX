// Probe: does an RtlCloneUserProcess child work for what fork() needs?
// Write to console/pipe via inherited handles, see COW memory, exit with a code the parent can read.
#include <windows.h>
#include <stdio.h>
typedef struct { ULONG Length; HANDLE Process, Thread; HANDLE Pid, Tid; BYTE ImageInfo[64]; } RTL_USER_PROCESS_INFORMATION;
typedef LONG (NTAPI *Clone)(ULONG, PVOID, PVOID, HANDLE, RTL_USER_PROCESS_INFORMATION *);
static int shared = 1;
int main(void) {
    Clone clone = (Clone)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCloneUserProcess");
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE), r, w; DWORD n;
    SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    RTL_USER_PROCESS_INFORMATION pi = { sizeof pi };
    LONG st = clone(2 /*INHERIT_HANDLES*/, 0, 0, 0, &pi);
    if (st == 0x129) { // STATUS_PROCESS_CLONED: we are the child
        shared = 42;
        char msg[64]; int len = sprintf(msg, "child: console write ok, shared=%d\n", shared);
        WriteFile(out, msg, len, &n, 0);
        WriteFile(w, "via-pipe", 8, &n, 0);
        TerminateProcess(GetCurrentProcess(), 7); // ExitProcess may need CSR; see both
    }
    if (st != 0) { printf("clone failed %lx\n", st); return 1; }
    CloseHandle(w);
    char buf[32] = {0}; ReadFile(r, buf, 31, &n, 0);
    WaitForSingleObject(pi.Process, 5000); DWORD code = 0; GetExitCodeProcess(pi.Process, &code);
    printf("parent: pipe got '%s', child exit %lu, parent shared=%d\n", buf, code, shared);
    return 0;
}
