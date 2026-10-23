// Edge-triggered epoll on a pipe and an eventfd: data that arrives after the reader drained it to EAGAIN
// (before its next epoll_wait) is a new edge, as on Linux. Go reads its pipes this way; missing the edge
// left cgo waiting forever on bytes that were there.
#include <stdint.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>

static int edge_again(int rfd, int wfd, int is_event) {
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.fd = rfd}, out;
    epoll_ctl(ep, EPOLL_CTL_ADD, rfd, &ev);
    uint64_t one = 1, buf[8];
    write(wfd, &one, is_event ? 8 : 1);
    if (epoll_wait(ep, &out, 1, 1000) != 1) return 0; // the first edge
    while (read(rfd, buf, sizeof buf) > 0) {}         // drained to EAGAIN
    write(wfd, &one, is_event ? 8 : 1);                // arrives before the next epoll_wait
    int n = epoll_wait(ep, &out, 1, 1000);             // a new edge
    close(ep);
    return n == 1;
}

int main(void) {
    int p[2];
    pipe2(p, O_NONBLOCK);
    int efd = eventfd(0, EFD_NONBLOCK);
    printf("epollet pipe=%d eventfd=%d\n", edge_again(p[0], p[1], 0), edge_again(efd, efd, 1));
    return 0;
}
