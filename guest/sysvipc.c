// SysV semaphores and message queues across fork: a child blocks on a semaphore the parent posts, then
// sends a message the parent receives; IPC_NOWAIT errors, IPC_STAT, permissions, IPC_INFO, removal and a
// lookup by key.
#define _GNU_SOURCE
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
    struct semid_ds ds;
    int nsems = semctl(sem, 0, IPC_STAT, &ds) == 0 ? (int)ds.sem_nsems : -1;
    pid_t c2 = fork();
    if (c2 == 0) { // someone else may not touch a 0600 set or queue
        if (setuid(65534)) _exit(9);
        struct sembuf any = {0, 1, IPC_NOWAIT};
        int a = semop(sem, &any, 1) < 0 && errno == EACCES;
        int b = msgsnd(q, &m, sizeof m.text, IPC_NOWAIT) < 0 && errno == EACCES;
        _exit(a && b ? 0 : 1);
    }
    int st2; waitpid(c2, &st2, 0);
    struct seminfo si;
    int info = semctl(0, 0, IPC_INFO, &si) >= 0 && si.semmsl > 0;
    int byidx = 0; // SEM_STAT walks the table by index and returns the set's id (ipcs)
    for (int i = 0; i < 128; i++) if (semctl(i, 0, SEM_STAT, &ds) == sem) byidx = 1;
    int k = semget(0x4c58, 1, IPC_CREAT | 0600), k2 = semget(0x4c58, 1, 0);
    semctl(sem, 0, IPC_RMID); msgctl(q, IPC_RMID, 0); semctl(k, 0, IPC_RMID);
    int gone = semctl(sem, 0, GETVAL) < 0 && errno == EINVAL;
    printf("sysv waiting=%d got=%s n=%zd child=%d nowait=%s/%s nsems=%d perm=%d info=%d stat=%d key=%d gone=%d\n", waiting, m.text, n,
           WEXITSTATUS(st), e1 == EAGAIN ? "EAGAIN" : "?", e2 == ENOMSG ? "ENOMSG" : "?", nsems, WEXITSTATUS(st2) == 0, info, byidx, k == k2, gone);
    return 0;
}
