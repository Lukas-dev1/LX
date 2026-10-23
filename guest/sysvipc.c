// SysV semaphores and message queues across fork: a child blocks on a semaphore the parent posts, then
// sends a message the parent receives; IPC_NOWAIT errors, removal, and a lookup by key.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <unistd.h>
struct msg { long type; char text[16]; };
int main(void) {
    int sem = semget(IPC_PRIVATE, 2, 0600), q = msgget(IPC_PRIVATE, 0600);
    if (sem < 0 || q < 0) { perror("get"); return 1; }
    semctl(sem, 0, SETVAL, 0);
    pid_t c = fork();
    if (c == 0) {
        struct sembuf down = {0, -1, 0};
        if (semop(sem, &down, 1)) _exit(2); // waits for the parent's post
        struct msg m = {2, "hello"};
        _exit(msgsnd(q, &m, sizeof m.text, 0) ? 3 : 0);
    }
    usleep(200000);
    int waiting = semctl(sem, 0, GETNCNT);
    struct sembuf up = {0, 1, 0};
    semop(sem, &up, 1);
    struct msg m;
    ssize_t n = msgrcv(q, &m, sizeof m.text, 0, 0);
    int st; waitpid(c, &st, 0);
    struct sembuf try = {0, -1, IPC_NOWAIT};
    int e1 = semop(sem, &try, 1) ? errno : 0;
    int e2 = msgrcv(q, &m, sizeof m.text, 0, IPC_NOWAIT) < 0 ? errno : 0;
    int k = semget(0x4c58, 1, IPC_CREAT | 0600), k2 = semget(0x4c58, 1, 0);
    semctl(sem, 0, IPC_RMID); msgctl(q, IPC_RMID, 0); semctl(k, 0, IPC_RMID);
    int gone = semctl(sem, 0, GETVAL) < 0 && errno == EINVAL;
    printf("sysv waiting=%d got=%s n=%zd child=%d nowait=%s/%s key=%d gone=%d\n", waiting, m.text, n, WEXITSTATUS(st),
           e1 == EAGAIN ? "EAGAIN" : "?", e2 == ENOMSG ? "ENOMSG" : "?", k == k2, gone);
    return 0;
}
