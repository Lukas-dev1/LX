// Probe: can a NON-BLOCKING accept() block when several processes share one listening socket?
// (nginx workers do exactly this: epoll wakes all of them, one wins the connection, the rest must get EAGAIN.)
// Parent: non-blocking listener, 8 children inherit it, then 400 client connects.
// Child: FIONBIO, then WSAPoll + accept in a loop; reports its slowest accept() and how many it got.
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define CHILDREN 8
#define CONNS 400

static int child(SOCKET ls) {
    u_long on = 1;
    if (ioctlsocket(ls, FIONBIO, &on) != 0) { printf("child FIONBIO failed %d\n", WSAGetLastError()); return 1; }
    LARGE_INTEGER f, a, b; QueryPerformanceFrequency(&f);
    double worst = 0; int got = 0, eagain = 0;
    DWORD end = GetTickCount() + 6000;
    while (GetTickCount() < end) {
        WSAPOLLFD p = { ls, POLLRDNORM, 0 };
        if (WSAPoll(&p, 1, 100) <= 0) continue;
        QueryPerformanceCounter(&a);
        SOCKET c = accept(ls, NULL, NULL);
        QueryPerformanceCounter(&b);
        double ms = (b.QuadPart - a.QuadPart) * 1000.0 / f.QuadPart;
        if (ms > worst) worst = ms;
        if (c == INVALID_SOCKET) { if (WSAGetLastError() == WSAEWOULDBLOCK) eagain++; }
        else { got++; closesocket(c); }
    }
    printf("child %lu: %d accepted, %d EWOULDBLOCK, slowest accept() %.1f ms\n", GetCurrentProcessId(), got, eagain, worst);
    return 0;
}

int main(int argc, char **argv) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    if (argc == 2) return child((SOCKET)_strtoui64(argv[1], NULL, 10));

    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa = { AF_INET, 0, { .s_addr = htonl(INADDR_LOOPBACK) } };
    int len = sizeof sa;
    bind(ls, (struct sockaddr *)&sa, sizeof sa); listen(ls, 128); getsockname(ls, (struct sockaddr *)&sa, &len);
    u_long on = 1; ioctlsocket(ls, FIONBIO, &on);
    SetHandleInformation((HANDLE)ls, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    PROCESS_INFORMATION pi[CHILDREN];
    for (int i = 0; i < CHILDREN; i++) {
        char cmd[256]; snprintf(cmd, sizeof cmd, "\"%s\" %llu", argv[0], (unsigned long long)ls);
        STARTUPINFOA si = { sizeof si };
        CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi[i]);
    }
    Sleep(500);
    for (int i = 0; i < CONNS; i++) {
        SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        connect(c, (struct sockaddr *)&sa, sizeof sa);
        closesocket(c);
        if (i % 50 == 0) Sleep(20);
    }
    int stuck = 0;
    for (int i = 0; i < CHILDREN; i++) {
        if (WaitForSingleObject(pi[i].hProcess, 10000) == WAIT_TIMEOUT) {
            printf("child %lu never finished: stuck (in accept?)\n", pi[i].dwProcessId);
            TerminateProcess(pi[i].hProcess, 1);
            stuck++;
        }
    }
    printf("%d of %d children stuck\n", stuck, CHILDREN);
    return stuck != 0;
}
