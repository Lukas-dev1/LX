// A non-blocking pipe write never waits: a full pipe is EAGAIN (a write up to PIPE_BUF all or nothing),
// poll shows no POLLOUT then, and once the reader drains it POLLOUT comes back, also as a new edge for
// edge-triggered epoll. Go writes its pipes so; a blocking write there hung `go test os`.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(void) {
    int p[2];
    pipe2(p, O_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLOUT | EPOLLET, .data.fd = p[1]}, out;
    epoll_ctl(ep, EPOLL_CTL_ADD, p[1], &ev);
    int first = epoll_wait(ep, &out, 1, 1000); // writable at the start
    static char buf[8192];
    long total = 0;
    ssize_t n;
    while ((n = write(p[1], buf, sizeof buf)) > 0) total += n; // fills, then EAGAIN instead of blocking
    int full_eagain = n < 0 && errno == EAGAIN;
    struct pollfd pf = {.fd = p[1], .events = POLLOUT};
    int full_pollout = poll(&pf, 1, 0) == 1 && (pf.revents & POLLOUT);
    int small = write(p[1], buf, 100) < 0 && errno == EAGAIN; // PIPE_BUF: all or nothing
    while (read(p[0], buf, sizeof buf) > 0) {}               // the reader drains it
    int room = poll(&pf, 1, 0) == 1 && (pf.revents & POLLOUT);
    int edge = epoll_wait(ep, &out, 1, 1000) == 1 && (out.events & EPOLLOUT);
    printf("pipenb first=%d filled=%d eagain=%d full-pollout=%d small-eagain=%d room=%d edge=%d\n",
           first, total > 0, full_eagain, full_pollout, small, room, edge);
    return 0;
}
