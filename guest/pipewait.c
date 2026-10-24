// A reader blocked in a big read (cat reads 128K) leaves a non-blocking writer room: NT counts the pending
// read against the pipe's quota. The writer must neither get EAGAIN nor miss POLLOUT then, also after it
// filled the pipe and the reader drained it. A FIFO's write end, read through lx's broker, likewise.
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int p[2];
static long got;
static char rbuf[131072];
static void *reader(void *_) {
    ssize_t n;
    while ((n = read(p[0], rbuf, sizeof rbuf)) > 0) got += n;
    return 0;
}

static int pollout(int fd, int ms) {
    struct pollfd pf = {fd, POLLOUT};
    return poll(&pf, 1, ms) == 1 && (pf.revents & POLLOUT);
}

int main(void) {
    static char buf[65536];
    pipe(p);
    fcntl(p[1], F_SETFL, O_NONBLOCK);
    pthread_t t;
    pthread_create(&t, 0, reader, 0);
    usleep(100000); // the reader waits in read(128K)
    int blocked = pollout(p[1], 0) && write(p[1], buf, 100) == 100;
    // Fill it while the reader keeps draining: each EAGAIN must be followed by a POLLOUT.
    long sent = 0;
    int stuck = 0;
    while (sent < (8 << 20) && !stuck) {
        ssize_t n = write(p[1], buf, sizeof buf);
        if (n > 0) sent += n;
        else if (errno != EAGAIN || !pollout(p[1], 3000)) stuck = 1;
    }
    close(p[1]);
    pthread_join(t, 0);
    // A FIFO: its reader is lx's broker, always waiting in a read.
    mkfifo("/pipewait.p", 0600);
    int r = open("/pipewait.p", O_RDONLY | O_NONBLOCK), w = open("/pipewait.p", O_WRONLY | O_NONBLOCK);
    int fifo = pollout(w, 0) && write(w, "x", 1) == 1;
    close(r), close(w), unlink("/pipewait.p");
    printf("pipewait blocked-reader=%d drained=%d fifo=%d\n", blocked, !stuck && got == sent + 100, fifo);
    return 0;
}
