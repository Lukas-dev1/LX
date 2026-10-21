// Probe: can an RtlCloneUserProcess child start a new process (CreateProcessW / NtCreateUserProcess)?
#include <windows.h>
#include <stdio.h>
typedef struct { ULONG Length; HANDLE Process, Thread; HANDLE Pid, Tid; BYTE ImageInfo[64]; } RTL_USER_PROCESS_INFORMATION;
typedef LONG (NTAPI *Clone)(ULONG, PVOID, PVOID, HANDLE, RTL_USER_PROCESS_INFORMATION *);
int main(void) {
    Clone clone = (Clone)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCloneUserProcess");
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE); DWORD n;
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    RTL_USER_PROCESS_INFORMATION pi = { sizeof pi };
    LONG st = clone(2, 0, 0, 0, &pi);
    if (st == 0x129) {
        char msg[128]; STARTUPINFOW si = { sizeof si }; PROCESS_INFORMATION p;
        wchar_t cmd[] = L"cmd.exe /c echo grandchild-ran";
        BOOL ok = CreateProcessW(0, cmd, 0, 0, TRUE, 0, 0, 0, &si, &p);
        int len = sprintf(msg, "child: CreateProcessW=%d err=%lu\n", ok, ok ? 0 : GetLastError());
        WriteFile(out, msg, len, &n, 0);
        if (ok) WaitForSingleObject(p.hProcess, 5000);
        TerminateProcess(GetCurrentProcess(), 9);
    }
    WaitForSingleObject(pi.Process, 10000); DWORD code = 0; GetExitCodeProcess(pi.Process, &code);
    printf("parent: child exit %lu\n", code);
    return 0;
}
