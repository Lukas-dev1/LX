# lx: Linux OCI images on NT without a VM

`lx` runs unmodified x86-64 Linux user-space binaries as ordinary Windows processes. It needs no hypervisor, WSL, or kernel driver. Guest code runs natively on the CPU. Only the kernel boundary (`syscall`) and a few ABI differences are translated.

```
┌──────────────── one Windows process per Linux process ────────────────┐
│  guest ELF code (native x86-64), rewritten at load / mmap(PROT_EXEC):  │
│     syscall   ──jmp──> stub ──> lx_sys_entry (switch to lx stack)  ─┐ │
│     %fs: x    ──jmp──> stub: same access via the guest FS base held │ │
│                        in ThreadState (no FS register, no fault)    │ │
│     unrewritable site ──ud2 / #AV──> vectored exception handler ────┤ │
│                                                                     ▼ │
│  lx runtime (on its own per-thread stack): syscall table → NT/Win32/  │
│  user-space emulation; signals delivered on the way back (iretq)      │
│                                                                       │
│  confinement: job object (+ AppContainer/restricted token, planned)   │
└───────────────────────────────────────────────────────────────────────┘
```

## 1. The NT facts that shape everything (measured on this machine, Win11 26200)

| Fact | Probe | Consequence |
|---|---|---|
| `wrfsbase` works in user mode | `probe/fsbase2.c` | Linux TLS (`%fs:`) can point at guest memory with no kernel help. |
| NT resets FS base to 0 on context switches and kernel transitions | `probe/fsbase2.c`, `probe/fsbase3.c` (~100 losses/s/thread) | We can't rely on FS base. `%fs:` accesses are rewritten to not use it (§4). |
| A raw `syscall` goes to the **NT** kernel with Linux numbers | — | Every `syscall` must be found and rewritten before it runs (§3). |
| The NT exception path writes ~2.7 KB below `rsp` (CONTEXT + XSAVE + dispatcher frames) | `LX_DEBUG` measurement | A Linux kernel never touches the user stack, and Go runs syscalls on 8–16 KB stacks: traps corrupted neighbouring goroutine stacks. Hot paths therefore avoid exceptions entirely (§3, §4). On the trap fallback, the `CONTEXT` being edited sits exactly where a signal frame goes, so there the frame is copied in by a trampoline after `NtContinue`. |
| `ExitThread` frees the stack named by `TEB.DeallocationStack` | crash in `pthread_join` | Guest threads point the TEB at the guest stack (for on-demand growth), so they restore the host thread's TEB stack fields before `ExitThread`. Otherwise the guest's thread mapping (with musl's pthread struct) is freed. |
| `RtlCloneUserProcess` gives a working copy-on-write child… | `probe/clone.c` | …but that child crashes in `CreateProcessW` (`probe/clone2.c`), and a forked shell child must exec. `fork` is spawn-and-copy instead (§5). |
| A **non-blocking** `accept()` on a listening socket shared by several processes can block forever (another process takes the connection between the readiness check and the accept) | `probe/acceptrace.c`: 8 processes share a listener; now and then one never returns from `accept()` | IP listeners accept with an overlapped `AcceptEx` that is cancelled after 10 ms instead (§5). This was the nginx shutdown straggler. |

## 2. ELF loader (`src/elf.rs`)

- Validates the header (ELF64, little-endian, x86-64, `ET_EXEC` or `ET_DYN`). Every offset and size from the file is bounds-checked, because images are untrusted input.
- Reserves the whole `PT_LOAD` span with one `VirtualAlloc`, aligned to 64 KiB because NT reserves memory in 64 KiB units. `ET_EXEC` maps at its linked address. `ET_DYN` (static-pie) maps anywhere with a load bias, and musl's `rcrt1` relocates itself.
- Copies segments, zero-fills `.bss`, patches syscalls, then applies `R/W/X` with `VirtualProtect`.
- Builds the SysV initial stack: `argc, argv[], envp[], auxv[]`, with `AT_PHDR`, `AT_PHNUM`, `AT_ENTRY`, `AT_RANDOM` (BCrypt), `AT_PAGESZ` and the rest, 16-byte aligned. It then jumps to `e_entry` with `rdx = 0`.
- `PT_INTERP`: the interpreter (`ld-musl`, `ld-linux`) is loaded as a second image and gets `AT_BASE`; dynamic linking is then plain `mmap`/`open`. `#!` scripts are resolved by the loader too (up to 4 levels).
- The main thread's stack is reserved at 8 MB with the top 256 KB committed and a guard page below; NT grows it on demand because the TEB describes it.

## 3. Syscall interception: direct jumps, trap fallback

A Linux kernel never writes to the user stack during a syscall, and programs rely on that (Go runs syscalls on 8–16 KB stacks). NT's exception dispatch writes ~2.7 KB below the faulting `rsp`, so the trap path corrupted neighbouring Go stacks. Hence two paths (`src/jump.rs`, `src/syscall.rs`):

**Direct path (default).** At load (and on `mmap`/`mprotect` with `PROT_EXEC`), each executable region is decoded linearly (`iced-x86`). A `syscall` plus the straight-line instructions just before it (≥ 5 bytes, no known branch target inside) becomes `jmp stub`. The stub lives in a stub area within rel32 reach and runs the displaced instructions (relocated by iced's block encoder), then `lea r11, [rip+return]` (a Linux syscall clobbers `rcx`/`r11` anyway) and `jmp [area slot]` to `lx_sys_entry`. That entry switches `rsp` to the thread's own 512 KB lx stack using only `mov`s, which touch neither memory nor flags; its first write is `pushfq` onto the lx stack. It builds a `Context` there, runs the same `dispatch()` and signal delivery as the trap path, and returns with `iretq` from the lx stack, which loads `rip`, `rsp` and `rflags` together. **Nothing is written to the guest stack, and no guest register is borrowed beyond Linux's own `rcx`/`r11`.** Thread start and fork children (`lx_resume`) enter the same way.

Bytes left over at a rewritten site become `int3`. If a jump we couldn't see (computed, or via a table) lands on a displaced instruction, the exception path redirects it to that instruction's copy in the stub. That's slow and logged, but correct.

**Forward displacement.** When a branch or a jump target sits right before a site, there's no room before it, so straight-line instructions *after* it are taken instead. glibc needs this: its syscall wrappers are `[target] mov eax, edx; syscall`, and its `errno` stores (`mov fs:[rbx], ebp`, 3 bytes) follow branches. For `%fs:` sites this is exact (the stub jumps back past everything it took). A forward `syscall` stub is `... ; lea r11, [rip+back] ; jmp entry ; back: <following instructions> ; jmp end`, so `rcx`/`r11` and signal frames see a stub address instead of the original return address. Backward displacement is always preferred, and `LX_PATCHLOG` counts forward sites.

**Trap fallback.** Sites that can't be rewritten in either direction (a `syscall` that is itself a branch target with no straight-line code after it, or a site boxed in by targets and branches on both sides) keep `ud2` + vectored exception handler, as before. `LX_PATCHLOG=1` prints per region how many sites were rewritten or left on the fallback (with disassembly of each fallback site), and at exit how many fallback traps were taken. `LX_NOJUMP=1` disables rewriting (for comparison, or as an escape hatch).

Measured: ld-musl 503 rewritten / 5 fallback, busybox 0 syscall sites (it calls libc), Go test binary 39 / 0. Debian's glibc (`python:3.12`): 475 rewritten (4 forward) / 1 fallback, which is a function that starts with `syscall; ret`. Before forward displacement, glibc had 5 fallback sites and took 9–41 fallback traps per Python run; now no test hits a fallback trap. A raw syscall costs **~119 ns direct vs ~960 ns on the trap path** (same binary, `guest/sysbench.c`). `guest/stacktest.c` fills 16 KB below `rsp` in 5 threads, makes 60k syscalls each from pure assembly while ~16k signals arrive (handlers on `sigaltstack`), then forks: 0 bytes changed on the direct path, 1,712 bytes changed per thread on the trap path.

**Upgrade path:** sites boxed in on both sides need a shorter hook (a 2-byte `jmp rel8` to a nearby padding trampoline, or an `int3`-free trap that doesn't use the guest stack); a vDSO for `clock_gettime`/`gettimeofday`; lazy, control-flow-guided decoding instead of a linear sweep.

## 4. TLS: FS-free `%fs:` sites, fault-and-reload fallback

NT resets FS base to 0 on context switches. The original fix (a fault on the next `%fs:` access, reload, retry) costs the same ~2.7 KB exception frame, and Go reads its `g` via `fs:[-8]` in `runtime.systemstack`, `goexit1` and others, on goroutine stacks. So `%fs:` instructions are rewritten too, and their stubs don't use FS base at all. A temp register T that the instruction doesn't use (iced's used-register info, including implicit ones) is parked in a TEB slot (`mov gs:[scratch], T`). T is loaded with the guest FS base from `ThreadState`; with a base register B it becomes `lea T, [B+T]`. Then the instruction runs with `fs:` removed and T as its base, and T is restored. Only `mov`/`lea`: no stack, no flags, and a context switch anywhere in the sequence is harmless. Stubs that displace an `%fs:` instruction ahead of a `syscall` use the same transformation.

Unrewritten `%fs:` sites keep the exact fault-and-reload fallback: decode the faulting instruction, recompute its address with FS base 0, and compare with the fault address. Measured: Go 460 FS sites rewritten / 0 left, busybox 1524 / 0, ld-musl 91 / 0, glibc 4390+ / 44 (errno accesses boxed in by targets on both sides; before forward displacement 175 were left and a Python run took 2–12 FS faults); 0 FS faults in all tests. The cost lands on TLS-heavy loops: `guest/stress.c` (2 TLS accesses per iteration) 0.21 s → 0.36 s for 800M accesses.

## 5. Syscall surface plan (`src/syscall.rs`, a `match` on the number)

| Group | Linux | NT mapping | Status |
|---|---|---|---|
| Process bootstrap | `arch_prctl`, `set_tid_address`, `exit`, `exit_group` | FS base kept in `ThreadState`; `exit` ends the thread (the last one ends the process), `exit_group` → `TerminateProcess` | ✅ |
| stdio | `read`, `write`, `writev`, `ioctl(TCGETS/TIOCGWINSZ)` | `ReadFile`/`WriteFile` on std handles; `-ENOTTY` | ✅ (no tty yet) |
| Memory | `mmap`, `munmap`, `mprotect`, `mremap`, `brk`, `madvise` | `VirtualAlloc`/`VirtualProtect`. Guest memory lives in a dedicated window (`0x2000_0000_0000`+), free address hints are honoured, and every allocation is registered, so fork can recreate it. `PROT_NONE` is reserve-only (Go reserves hundreds of GB) and is committed on `mprotect`/`MAP_FIXED`. `madvise(MADV_DONTNEED)` decommits + recommits, so pages read back as zero like on Linux (Go's scavenger depends on it). `brk` always fails, and libc falls back to `mmap` | ✅ |
| Files | `openat`, `close`, `fstat`/`newfstatat`, `getdents64`, `lseek`, `pread`/`pwrite`, `readv`/`writev`, `readlinkat`, `sendfile`, `fcntl`, … | std file APIs on paths resolved by `lx`. fd table → owned HANDLEs with CLOEXEC. `/dev/null`/`zero`/`urandom`/`std*`/`fd/N` and `/proc/self/{exe,cwd,root,fd/N}` emulated; `/proc/self` and `/proc/self/fd` are synthetic directories (stat, open, getdents: the open fds as symlinks) | ✅ |
| Time | `clock_gettime`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`, `setitimer`/`alarm` | system time / monotonic since start; sleeps are interruptible by signals; `SIGALRM` from a timer thread | ✅. **Next:** a vDSO, so time calls don't enter lx at all |
| Threads | `clone(CLONE_THREAD)`, `clone3`, `futex`, `set_tid_address`, `membarrier`, `sched_*`, `sigaltstack` | `CreateThread` with the guest's registers/stack/TLS; per-thread `ThreadState` behind a TEB TLS slot; `CHILD_CLEARTID` + futex wake for `pthread_join`; `futex` → `WaitOnAddress`/`WakeByAddress*`; `membarrier` → `FlushProcessWriteBuffers`; host TEB stack fields restored before `ExitThread` (it frees what `DeallocationStack` names) | ✅ pthreads (static + dynamic) 20/20, Go runtime 20/20, Python `ThreadingHTTPServer` |
| Processes | `fork`, `vfork`, `clone` (no threads), `execve`, `wait4`, `pipe2` | **fork** = start `lx --fork`. The child re-reserves every registered guest allocation at the same address and copies the paused parent's memory (`ReadProcessMemory`), along with registers, FS base, syscall-site registry, signal state and fds (handles inherited at the same values), then resumes after the syscall with `rax = 0`. Same idea as Cygwin. **execve** = start `lx --exec` with fds/cwd/argv/env; the old process waits and forwards the exit code. `#!` scripts are handled by the loader. **pipes** = anonymous pipes; EOF works because each fd owns its handle and CLOEXEC handles aren't inherited | ✅ ~23 ms per fork+exec. Faster later: exec in place (one process, not two), and skip the copy when a vfork child execs immediately |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigsuspend`, `rt_sigreturn`, `sigaltstack`, `kill`/`tkill`/`tgkill` | Real dispositions; a blocked mask per thread (inherited by new threads and by fork), pending signals per process. Delivery happens at syscall return, with a Linux-layout frame (`siginfo` + `ucontext`), on the per-thread `sigaltstack` for `SA_ONSTACK` handlers (Go requires it). On the direct path the frame is written straight to the guest stack; on the trap fallback `lx_sig_tramp` places it after `NtContinue`. Handlers return via `rt_sigreturn`. Pending signals are process-wide: the next thread to return from a syscall takes one. SIGCHLD is raised when a child exits; default actions terminate (exit 128+n) or ignore. **Faults** in guest code (an ELF region, or JIT code anywhere outside a Windows module) become synchronous SIGSEGV (`si_addr`, `SEGV_MAPERR`/`SEGV_ACCERR`), SIGFPE or SIGILL for the faulting thread when the guest has an unblocked handler, which may edit `rip` in the ucontext: HotSpot's implicit null checks and safepoint polls. Else exit 139 | ✅. **From outside:** each lx process has a mailbox (shared memory `Local\lx-sig-<pid>` + event) and a watcher thread. A default-terminate signal ends the process at once, even mid-loop. Otherwise the watcher raises the signal and wakes blocking waits (`CancelSynchronousIo` for reads/writes, an event for sleep/poll/wait/sigsuspend), and the handler runs at syscall return. An exec proxy forwards signals, so the container pid stays stable. Ctrl-C → SIGINT (untested). `lx ps`, `lx kill`, `lx stop` (TERM, then KILL after 10 s). **Not yet:** running a *handler* while the guest spins without syscalls (needs thread hijack), process groups |
| I/O multiplexing | `epoll_*`, `poll`, `ppoll`, `pipe2`, `eventfd`/`eventfd2` | epoll over `WSAPoll` with edge-triggered and one-shot emulation (an EAGAIN re-arms the edge, so nginx's ET mode doesn't spin). Waits sleep in `WSAPoll` slices over the registered sockets; other fds (pipes, eventfds) are re-checked each slice. eventfd = counter + condvar, readiness through the same hook (Go's netpoller uses it). Idle nginx uses ~0 CPU | ✅. **Next:** AFD-based waits instead of slices; eventfds aren't carried across fork/exec |
| Sockets | `socket`, `bind`, `listen`, `accept4`, `connect`, `send*`/`recv*`, `sendmsg`/`recvmsg`, `sendmmsg`/`recvmmsg` (glibc's resolver sends A + AAAA in one call), `shutdown`, `get/setsockopt`, `socketpair` | Winsock; every socket is non-blocking underneath (IP listeners accept with an overlapped `AcceptEx`: a plain `accept` on a listener shared by several processes can block, §1), and "blocking" calls wait in slices so signals interrupt them. AF_INET6 10↔23 and option numbers translated; IPv6 sockets dual-stack like Linux. `socketpair` = loopback TCP pair. Host networking (like `--network host`); `/etc/resolv.conf` gets the host's DNS servers | ✅. **Published ports:** `lx run -p [ip:]host:container[/udp]` rewrites bind/connect/getsockname (no proxy); unpublished any-address listeners move to loopback (this PC only). **AF_UNIX** (stream): Windows' native AF_UNIX, socket file at `rootfs\s\<container>\<hash>` (sun_path is 108 bytes), a marker at the guest path, abstract names supported, removed with the container. **AF_UNIX datagrams** (`/dev/log`, sd_notify; Windows has none): a UDP socket on 127.0.0.1, the bound address's host file holds its port, and a `u<port>` file names the sender back for `recvfrom`. **Not yet:** SCM_RIGHTS fd passing, per-container network namespaces |
| Identity | `getpid`, `getuid` and the rest, `uname`, `getrandom` | constants per container; `BCryptGenRandom` | trivial |

Anything unimplemented logs its number and returns `-ENOSYS`, so the trace from each new binary is the work list.

**Out of scope, as the brief says:** namespaces, cgroups, `mount`, `ptrace`, `io_uring`, `bpf`, and device files beyond `/dev/null`, `/dev/zero`, `/dev/urandom`, and `/dev/tty`. `/proc` gets a minimal synthetic `self/exe`, `self/maps`, `cpuinfo`, and `meminfo`, because runtimes read them.

## 6. Images and the filesystem

- OCI pull (✅): fetch the manifest and layers from the registry over HTTPS, then unpack the tar layers in order (whiteouts are `.wh.*` files) into `rootfs/images/<registry>/<repo>/<tag>/rootfs`. A re-pull starts from an empty rootfs.
- `lx build -t name[:tag] [-f Dockerfile] [--build-arg K=V] <dir>` (✅, one stage): the image starts as a hard-link copy of its FROM image (fast, no admin rights; links share the `:lx` mode stream). Each RUN is an `lx run --entrypoint "" --layer <dir> dir:<image so far>` whose kept layer is then moved into the image (whiteouts delete, opaque dirs replace, files are replaced, never written through, since the base may share them; lx's per-run `/etc/resolv.conf` and `/etc/hosts` stay out). COPY/ADD (with `--chown`) copy from the context (files 0644, scripts/ELF 0755, dirs 0755); ENV, ARG, WORKDIR, USER, CMD, ENTRYPOINT, SHELL, EXPOSE and LABEL update the config, with `$VAR`/`${VAR}` expanded except in RUN/CMD/ENTRYPOINT (the shell's job). Not yet: multi-stage (`FROM ... AS`, `COPY --from`), a build cache, ADD of URLs/archives, `.dockerignore`.
- Linux semantics NTFS lacks:
  - **Symlinks** (✅): NTFS symlinks need Developer Mode or a privilege, so they're small marker files that `lx` resolves.
  - **Path resolution** (✅): done in `lx`, component by component, against the guest root. `..` can never climb above the root, and absolute symlink targets are re-rooted.
  - **Names NTFS forbids** (✅): `: \ * ? " < > |` and control characters are stored at U+F000+c in host names (like Cygwin) and decoded in directory listings, so dpkg's `libc6:amd64.list` works and a guest `:` can never name an alternate data stream. Not encoded: trailing dots and spaces. Images pulled before this lack such files (unpack skipped them): re-pull.
  - **Case sensitivity** (planned): set the per-directory case-sensitive flag (`FILE_CASE_SENSITIVE_INFORMATION`) on unpack. This works without admin on directories we create.
  - **Modes and ownership** (✅): permission bits, uid and gid live in an alternate data stream of each entry (`<host>:lx`, three u32s). Unpack writes them from the tar headers; `stat`/`fstat` read them; `chmod`/`chown` (and the f-/l-/at variants) write them through the writable layer, which also gives the directories it creates the image's metadata; `open(O_CREAT)`, `creat` and `mkdir` record `mode & ~umask` and the effective ids. No stream: 0755 root:root (images pulled before this). Volumes' host files get none (chmod there is accepted and ignored). Not enforced: everyone is effectively root for access checks. The stream costs one extra read per `stat` (~7%).

## 7. Isolation and safety model (be honest about it)

The translation layer is **not** a security boundary. Guest code runs natively in our process: it could find `ntdll` and make raw NT calls, or JIT unpatched `syscall`s. The real boundary has to come from the OS:
- **Job object** (done): one per container (`Local\lx-job-<pid>`), made by its first lx process; every later one (fork, exec, `lx exec`) runs inside it. It caps each process's memory (`-m`, default the machine's RAM) and kill-on-close takes the whole container down when PID 1 exits. `lx exec <pid> cmd` joins it, and steps into the container's image, layer, volumes, env, workdir and user from `rootfs/containers/<pid>.json`. `lx run -d` starts the same `lx run` detached (out of the caller's job when allowed, without the caller's std handles) with its output in `rootfs/logs/`, read by `lx logs <pid>`.
- **AppContainer or restricted token** (next): no access to user files outside the granted rootfs directory, and no network unless granted. This is what makes "confine file access to the rootfs" hold even against a hostile image.
- Windows Server Silos are the real container primitive, but they need Server SKUs and admin. They're out of reach on Windows 11 Home, and the project doesn't depend on them.

**Known risks in the prototype:**
- **Trap fallback writes the guest stack.** Rewritten sites never touch it (§3), but a fallback site, an int3 redirect, or an FS fault at an unrewritten `%fs:` site still costs a ~2.7 KB NT exception frame below `rsp`. `LX_PATCHLOG` reports how often that happens; it's zero in all current tests.
- **Linear-sweep desync** can hide a real `syscall` behind data in `.text`. Disagreement between decoded and raw `0F 05` pairs is logged (`LX_DEBUG`); control-flow-guided decoding fixes it.
- **Stub areas are RWX**, so stubs can be added while other threads execute code from the same area. Patching writes the 5-byte `jmp` non-atomically: fine for code that is just becoming executable (`mmap`/`mprotect`), not for code another thread is already executing.
- **Fork from a multithreaded process** copies memory while the other threads keep running (only the forking thread survives, as on Linux). The copy can be torn for data those threads are writing, which is harmless for the common fork-then-exec.
- **`writev` reads the iovec array directly.** A bad pointer crashes `lx` instead of returning `-EFAULT`. Fix with a guarded copy.

## 8. Milestones

1. ✅ Static musl hello world: ELF load, TLS, stdio, exit code. Thread-local storage holds up under preemption.
2. ✅ Unmodified **official Alpine image** binaries: `PT_INTERP` (ld-musl), file-backed `mmap` with syscall patching of libraries loaded at runtime, ~50 syscalls (files, dirs, symlinks, stat, cwd). `ls -la`, `cat`, `grep`, `awk`, `sed`, `find`, `uname`, `sh` builtins, and `apk --version` (libcrypto, libz) all work.
3. ✅ (mostly) Direct-jump syscalls and FS-free TLS, with forward displacement: no exception, and no guest-stack writes, on the hot path (§3, §4). Remaining: a shorter hook for sites boxed in on both sides, vDSO, control-flow-guided decoding.
4. ✅ Threads and `futex`: pthreads and the Go runtime (goroutines on 16 OS threads, channels, mutexes, timers, GC), 20/20 each. `eventfd` and `madvise(MADV_DONTNEED)` (zero-fill) came with it.
5. ✅ Process model: `fork`/`execve`/`wait4`/pipes/signals. Shell entrypoints work, with pipelines, `$(...)`, background jobs + `wait`, `trap`, `#!` scripts and a final `exec` (`guest/entrypoint.sh`).
6. ✅ Networking: the official `nginx:alpine` image serves HTTP, including its default master + workers mode, with graceful `lx stop`. Measured: about 34 MB working set / 22 MB private for the whole container, and ~0 CPU when idle. Outbound DNS + HTTP works (`wget`, Python sockets), and Python's `ThreadingHTTPServer` serves parallel clients. **Fixed:** about 1 in 5 stops used to leave one worker SIGKILLed after ~3 s. It was blocked inside Winsock's `accept()` on the shared listening socket, so it never read the master's terminate commands (§1, `probe/acceptrace.c`). 0 of 20 stops since.
7. ✅ (basic) `lx pull <image>` / `lx run <image> [cmd]`; `python3 /script.py` (the usual Python entrypoint) works since the `fcntl(F_SETFD)` fix. Registry token auth, multi-arch index → linux/amd64, sha256-verified blobs (BCrypt), layers with whiteouts, and Entrypoint/Cmd/Env/WorkingDir from the image config. HTTPS goes through Windows' own `curl.exe`. Tested with `alpine`, `nginx:alpine` (its entrypoint scripts run) and `python:3.12-alpine`. Missing: private registries (credentials), zstd layers, a named/restartable container (each container's layer is deleted when it exits, like `--rm`).
8. ✅ **Debian / glibc images:** `python:3.12` runs `python3 -c`, scripts by path, the threaded server + outbound DNS/HTTP test, and AF_UNIX echo servers (path and abstract names). That needed `time`, `sendmmsg`/`recvmmsg`, `clone3`, and forward displacement (§3). Name lookups: glibc's `socket(AF_UNIX)` succeeds, its connect to the nscd socket gets ENOENT because no nscd runs in the container (as on Linux), and it continues with `/etc/hosts` + DNS. Still missing for glibc images: `AF_NETLINK` (getaddrinfo's address-family check falls back to "both"), `rseq` (glibc copes without it). **apt-get** works: `apt-get update`, `apt-get install -y jq` and running jq (~20 s). That needed fd inheritance through dup2 (a pipe handle shared by several fds stays inheritable if any surviving fd keeps it), POLLOUT on pipe write ends, a 1024 soft `RLIMIT_NOFILE` (apt `fcntl`s every fd below it before each exec), the NTFS name encoding (§6), `sysinfo`, and whiteouts that keep a deleted image file deleted when it is created again. Harmless warnings left: no `/dev/ptmx` (apt's pty log), `mincore`, `sync_file_range`.

## Tests

`sh tests/run.sh` (Git Bash, repo root) builds `lx` and every guest program, prepares `rootfs/` (a pinned, checksummed Alpine minirootfs; images pulled if missing), copies the guest scripts in `guest/` into the images only for the run (they're removed on exit, so no image in the store is modified by hand), and runs:

- unit tests; hello, stress (TLS under preemption), crash → 139, `regress.sh` (shell features), `entrypoint.sh`, deep stack + fork, `dltest` (libraries loaded while threads make syscalls);
- repeated (`REPEAT`, default 20): pthreads static and dynamic, the Go runtime test; the stack-untouched test 10×; all with zero fallback traps and FS faults required;
- a control (`LX_NOJUMP=1` must make the stack test fail) and the syscall cost of both paths;
- Debian (`python:3.12`, glibc): `python3 -c`, a script by path, an AF_UNIX echo server (path + abstract), AF_UNIX datagrams (also on Alpine), the threaded server test, and zero fallback traps / FS faults during it;
- nginx (5 start/request/stop cycles), `wget`, `python3 /nettest.py` on Alpine (sockets + threaded server), `lx stop` with a handler, a busy loop and an exec chain; no `lx` process may be left over.

Internet-dependent tests retry once and warn; an nginx worker killed at stop is a failure. `QUICK=1` skips the network part; `TOOLS=<dir>` points at the toolchains (e.g. the main checkout's, from a git worktree).

Diagnostics: `LX_DEBUG=1` (everything), `LX_SIGLOG=1` (signal events only, light enough not to change timing), `LX_PATCHLOG=1` (rewritten/fallback sites per region, with disassembly of each fallback site; traps and FS faults at exit), `LX_NOJUMP=1` (no rewriting: everything on the trap path).

## Build and run

```sh
# portable toolchains live in tools/ (no PATH or registry changes)
W=$(cygpath -m $PWD); export RUSTUP_HOME=$W/tools/rust/rustup CARGO_HOME=$W/tools/rust/cargo MSYS_NO_PATHCONV=1
tools/rust/cargo/bin/cargo build --release
tools/zig-x86_64-windows-0.15.2/zig.exe cc -target x86_64-linux-musl -static -O2 -o rootfs/hello guest/hello.c
target/release/lx.exe unpack alpine-minirootfs-x86_64.tar.gz rootfs/alpine   # an image layer
target/release/lx.exe rootfs/alpine ls -la /                               # PATH lookup inside the image
target/release/lx.exe pull python:3.12-alpine                                # from Docker Hub
target/release/lx.exe run python:3.12-alpine python3 -c 'print(1+1)'
cp guest/entrypoint.sh rootfs/alpine/ && target/release/lx.exe rootfs/alpine /entrypoint.sh   # shell entrypoint
LX_DEBUG=1 target/release/lx.exe ...                                       # verbose [lx] diagnostics (see Tests)
sh tests/run.sh                                                            # the whole suite
target/release/lx.exe rootfs /hello        # → "hello from linux ... tls=42", exit 7
target/release/lx.exe rootfs /stress       # TLS under preemption; with "crash" arg → exit 139
```
