# lx: Linux OCI images on NT without a VM

`lx` runs unmodified x86-64 Linux user-space binaries as ordinary Windows processes. It needs no hypervisor, WSL, or kernel driver. Guest code runs natively on the CPU. Only the kernel boundary (`syscall`) and a few ABI differences are translated.

```
┌─────────────── one Windows process per Linux process ───────────────┐
│  guest ELF code (native x86-64)                                     │
│     │ syscall ──patched──> ud2 ──#UD──┐                             │
│     │ %fs: access (base lost) ──#AV───┤                             │
│                                       ▼                             │
│  lx runtime: vectored exception handler                             │
│     ├─ syscall table  → NT / Win32 / user-space emulation           │
│     └─ fs_tramp       → wrfsbase + resume (user mode, no kernel)    │
│                                                                     │
│  confinement: job object (+ AppContainer/restricted token, planned) │
└─────────────────────────────────────────────────────────────────────┘
```

## 1. The NT facts that shape everything (measured on this machine, Win11 26200)

| Fact | Probe | Consequence |
|---|---|---|
| `wrfsbase` works in user mode | `probe/fsbase2.c` | Linux TLS (`%fs:`) can point at guest memory with no kernel help. |
| NT resets FS base to 0 on context switches and kernel transitions | `probe/fsbase2.c`, `probe/fsbase3.c` (~100 losses/s/thread) | We can't set FS base once. It must be restored lazily (§4). |
| A raw `syscall` goes to the **NT** kernel with Linux numbers | — | Every `syscall` must be found and rewritten before it runs (§3). |
| The NT exception path writes below `rsp` | — | Exception-based traps can clobber the SysV 128-byte red zone (§7, risk). It also means the `CONTEXT` being edited, and the handler's own frames, sit exactly where a signal frame goes, so signal frames are copied in by a trampoline after `NtContinue` (§5). |
| `RtlCloneUserProcess` gives a working copy-on-write child… | `probe/clone.c` | …but that child crashes in `CreateProcessW` (`probe/clone2.c`), and a forked shell child must exec. `fork` is spawn-and-copy instead (§5). |

## 2. ELF loader (`src/elf.rs`)

- Validates the header (ELF64, little-endian, x86-64, `ET_EXEC` or `ET_DYN`). Every offset and size from the file is bounds-checked, because images are untrusted input.
- Reserves the whole `PT_LOAD` span with one `VirtualAlloc`, aligned to 64 KiB because NT reserves memory in 64 KiB units. `ET_EXEC` maps at its linked address. `ET_DYN` (static-pie) maps anywhere with a load bias, and musl's `rcrt1` relocates itself.
- Copies segments, zero-fills `.bss`, patches syscalls, then applies `R/W/X` with `VirtualProtect`.
- Builds the SysV initial stack: `argc, argv[], envp[], auxv[]`, with `AT_PHDR`, `AT_PHNUM`, `AT_ENTRY`, `AT_RANDOM` (BCrypt), `AT_PAGESZ` and the rest, 16-byte aligned. It then jumps to `e_entry` with `rdx = 0`.
- **Next:** `PT_INTERP`. Load `ld-musl` or `ld-linux` as a second image and pass `AT_BASE`. This is the same code path again. Dynamic linking then becomes plain `mmap` and `open` syscalls.

## 3. Syscall interception: direct jumps, trap fallback

A Linux kernel never writes to the user stack during a syscall, and programs rely on that (Go runs syscalls on 8–16 KB stacks). NT's exception dispatch writes ~2.7 KB below the faulting `rsp`, so the trap path corrupted neighbouring Go stacks. Hence two paths (`src/jump.rs`, `src/syscall.rs`):

**Direct path (default).** At load (and on `mmap`/`mprotect` with `PROT_EXEC`), each executable region is decoded linearly (`iced-x86`). A `syscall` plus the straight-line instructions just before it (≥ 5 bytes, no known branch target inside) becomes `jmp stub`. The stub lives in a stub area within rel32 reach and runs the displaced instructions (relocated by iced's block encoder), then `lea r11, [rip+return]` (a Linux syscall clobbers `rcx`/`r11` anyway) and `jmp [area slot]` to `lx_sys_entry`. That entry switches `rsp` to the thread's own 512 KB lx stack using only `mov`s, which touch neither memory nor flags; its first write is `pushfq` onto the lx stack. It builds a `Context` there, runs the same `dispatch()` and signal delivery as the trap path, and returns with `iretq` from the lx stack, which loads `rip`, `rsp` and `rflags` together. **Nothing is written to the guest stack, and no guest register is borrowed beyond Linux's own `rcx`/`r11`.** Thread start and fork children (`lx_resume`) enter the same way.

Bytes left over at a rewritten site become `int3`. If a jump we couldn't see (computed, or via a table) lands on a displaced instruction, the exception path redirects it to that instruction's copy in the stub. That's slow and logged, but correct.

**Trap fallback.** Sites that can't be rewritten (`syscall` is itself a branch target, a function that starts with `syscall`, or fewer than 5 bytes of straight-line code before it) keep `ud2` + vectored exception handler, as before. `LX_PATCHLOG=1` prints per region how many sites were rewritten or left on the fallback (with disassembly of each fallback site), and at exit how many fallback traps were taken. `LX_NOJUMP=1` disables rewriting (for comparison, or as an escape hatch).

Measured: ld-musl 503 rewritten / 5 fallback, busybox 0 syscall sites (it calls libc), Go test binary 39 / 0. No test hit a fallback trap. A raw syscall costs **~119 ns direct vs ~960 ns on the trap path** (same binary, `guest/sysbench.c`). `guest/stacktest.c` fills 16 KB below `rsp` in 5 threads, makes 60k syscalls each from pure assembly while ~16k signals arrive (handlers on `sigaltstack`), then forks: 0 bytes changed on the direct path, 1,712 bytes changed per thread on the trap path.

**Upgrade path:** forward displacement (`syscall` + following instructions) for the remaining fallback sites; a vDSO for `clock_gettime`/`gettimeofday`; lazy, control-flow-guided decoding instead of a linear sweep.

## 4. TLS: FS-free `%fs:` sites, fault-and-reload fallback

NT resets FS base to 0 on context switches. The original fix (a fault on the next `%fs:` access, reload, retry) costs the same ~2.7 KB exception frame, and Go reads its `g` via `fs:[-8]` in `runtime.systemstack`, `goexit1` and others, on goroutine stacks. So `%fs:` instructions are rewritten too, and their stubs don't use FS base at all. A temp register T that the instruction doesn't use (iced's used-register info, including implicit ones) is parked in a TEB slot (`mov gs:[scratch], T`). T is loaded with the guest FS base from `ThreadState`; with a base register B it becomes `lea T, [B+T]`. Then the instruction runs with `fs:` removed and T as its base, and T is restored. Only `mov`/`lea`: no stack, no flags, and a context switch anywhere in the sequence is harmless. Stubs that displace an `%fs:` instruction ahead of a `syscall` use the same transformation.

Unrewritten `%fs:` sites keep the exact fault-and-reload fallback: decode the faulting instruction, recompute its address with FS base 0, and compare with the fault address. Measured: Go 460 FS sites rewritten / 0 left, busybox 1524 / 0, ld-musl 91 / 0; 0 FS faults in all tests. The cost lands on TLS-heavy loops: `guest/stress.c` (2 TLS accesses per iteration) 0.21 s → 0.36 s for 800M accesses.

## 5. Syscall surface plan (`src/syscall.rs`, a `match` on the number)

| Group | Linux | NT mapping | Status |
|---|---|---|---|
| Process bootstrap | `arch_prctl`, `set_tid_address`, `exit`, `exit_group` | FS emulation, `ExitProcess` | ✅ |
| stdio | `read`, `write`, `writev`, `ioctl(TCGETS/TIOCGWINSZ)` | `ReadFile`/`WriteFile` on std handles; `-ENOTTY` | ✅ (no tty yet) |
| Memory | `mmap`, `munmap`, `mprotect`, `brk`, `madvise` | `VirtualAlloc`/`VirtualProtect`. Guest memory lives in a dedicated window (`0x2000_0000_0000`+) and every allocation is registered, so fork can recreate it. `brk` always fails, and libc falls back to `mmap` | ✅ |
| Files | `openat`, `close`, `fstat`/`newfstatat`, `getdents64`, `lseek`, `readlinkat`, `sendfile`, … | std file APIs on paths resolved by `lx`. fd table → owned HANDLEs with CLOEXEC. `/dev/null`/`zero`/`urandom`/`std*`/`fd/N` emulated | ✅ (`statx`, `pread` next) |
| Time | `clock_gettime`, `nanosleep`, `clock_nanosleep` | `QueryPerformanceCounter`, `NtDelayExecution`, vDSO | partly (no `clock_nanosleep`) |
| Threads | `clone(CLONE_THREAD)`, `futex`, `set_tid_address`, `membarrier`, `sched_*`, `sigaltstack` | `CreateThread` with the guest's registers/stack/TLS; per-thread `ThreadState` behind a TEB TLS slot; `CHILD_CLEARTID` + futex wake for `pthread_join`; `futex` → `WaitOnAddress`/`WakeByAddress*`; `membarrier` → `FlushProcessWriteBuffers`; host TEB stack fields restored before `ExitThread` (it frees what `DeallocationStack` names) | ✅ pthreads (static + dynamic) 20/20, Go runtime 20/20, Python `ThreadingHTTPServer` |
| Processes | `fork`, `vfork`, `clone` (no threads), `execve`, `wait4`, `pipe2` | **fork** = start `lx --fork`. The child re-reserves every registered guest allocation at the same address and copies the paused parent's memory (`ReadProcessMemory`), along with registers, FS base, syscall-site registry, signal state and fds (handles inherited at the same values), then resumes after the syscall with `rax = 0`. Same idea as Cygwin. **execve** = start `lx --exec` with fds/cwd/argv/env; the old process waits and forwards the exit code. `#!` scripts are handled by the loader. **pipes** = anonymous pipes; EOF works because each fd owns its handle and CLOEXEC handles aren't inherited | ✅ ~23 ms per fork+exec. Faster later: exec in place (one process, not two), and skip the copy when a vfork child execs immediately |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigsuspend`, `rt_sigreturn`, `kill`/`tkill`/`tgkill` | Real dispositions and mask. Delivery happens at syscall return, with a Linux-layout frame (`siginfo` + `ucontext`) placed by `lx_sig_tramp` after `NtContinue`. Handlers return via `rt_sigreturn`. SIGCHLD is raised when a child exits; default actions terminate (exit 128+n) or ignore | ✅. **From outside:** each lx process has a mailbox (shared memory `Local\lx-sig-<pid>` + event) and a watcher thread. A default-terminate signal ends the process at once, even mid-loop. Otherwise the watcher raises the signal and wakes blocking waits (`CancelSynchronousIo` for reads/writes, an event for sleep/poll/wait/sigsuspend), and the handler runs at syscall return. An exec proxy forwards signals, so the container pid stays stable. Ctrl-C → SIGINT (untested). `lx ps`, `lx kill`, `lx stop` (TERM, then KILL after 10 s). **Not yet:** running a *handler* while the guest spins without syscalls (needs thread hijack), process groups |
| I/O multiplexing | `epoll_*`, `poll`, `ppoll`, `pipe2` | epoll over `WSAPoll` with edge-triggered and one-shot emulation (an EAGAIN re-arms the edge, so nginx's ET mode doesn't spin). Waits sleep in `WSAPoll` slices over the registered sockets; other fds are re-checked each slice. Idle nginx uses ~0 CPU | ✅. **Next:** `eventfd` (nginx logs it and carries on), AFD-based waits instead of slices |
| Sockets | `socket`, `bind`, `listen`, `accept4`, `connect`, `send*`/`recv*`, `sendmsg`/`recvmsg`, `shutdown`, `get/setsockopt`, `socketpair` | Winsock; every socket is non-blocking underneath and "blocking" calls wait in slices so signals interrupt them. AF_INET6 10↔23 and option numbers translated; IPv6 sockets dual-stack like Linux. `socketpair` = loopback TCP pair. Host networking (like `--network host`); `/etc/resolv.conf` gets the host's DNS servers | ✅. **Not yet:** AF_UNIX, SCM_RIGHTS fd passing, port mapping (`-p`) |
| Identity | `getpid`, `getuid` and the rest, `uname`, `getrandom` | constants per container; `BCryptGenRandom` | trivial |

Anything unimplemented logs its number and returns `-ENOSYS`, so the trace from each new binary is the work list.

**Out of scope, as the brief says:** namespaces, cgroups, `mount`, `ptrace`, `io_uring`, `bpf`, and device files beyond `/dev/null`, `/dev/zero`, `/dev/urandom`, and `/dev/tty`. `/proc` gets a minimal synthetic `self/exe`, `self/maps`, `cpuinfo`, and `meminfo`, because runtimes read them.

## 6. Images and the filesystem

- OCI pull: fetch the manifest and layers from the registry over HTTPS, then unpack the tar layers in order (whiteouts are `.wh.*` files) into `rootfs/<image-id>/`.
- Linux semantics NTFS lacks:
  - **Case sensitivity:** set the per-directory case-sensitive flag (`FILE_CASE_SENSITIVE_INFORMATION`) on unpack. This works without admin on directories we create.
  - **Symlinks:** NTFS symlinks need Developer Mode or a privilege. Otherwise, store them as small marker files and resolve them in `lx`.
  - **Modes and ownership:** keep them in an alternate data stream (`:lx.meta`) and return them from `stat`.
  - **Path resolution:** done in `lx`, component by component, against the guest root. `..` can never climb above the root, and absolute symlink targets are re-rooted.

## 7. Isolation and safety model (be honest about it)

The translation layer is **not** a security boundary. Guest code runs natively in our process: it could find `ntdll` and make raw NT calls, or JIT unpatched `syscall`s. The real boundary has to come from the OS:
- **Job object** (done): 512 MiB memory cap, and kill-on-close takes down the whole process tree.
- **AppContainer or restricted token** (next): no access to user files outside the granted rootfs directory, and no network unless granted. This is what makes "confine file access to the rootfs" hold even against a hostile image.
- Windows Server Silos are the real container primitive, but they need Server SKUs and admin. They're out of reach on Windows 11 Home, and the project doesn't depend on them.

**Known risks in the prototype:**
- **Trap fallback writes the guest stack.** Rewritten sites never touch it (§3), but a fallback site, an int3 redirect, or an FS fault at an unrewritten `%fs:` site still costs a ~2.7 KB NT exception frame below `rsp`. `LX_PATCHLOG` reports how often that happens; it's zero in all current tests.
- **Linear-sweep desync** can hide a real `syscall` behind data in `.text`. It's logged, and lazy translation fixes it.
- **Stub areas are RWX**, so stubs can be added while other threads execute code from the same area. Patching writes the 5-byte `jmp` non-atomically: fine for code that is just becoming executable (`mmap`/`mprotect`), not for code another thread is already executing.
- **Fork from a multithreaded process** copies memory while the other threads keep running (only the forking thread survives, as on Linux). The copy can be torn for data those threads are writing, which is harmless for the common fork-then-exec.
- **`writev` reads the iovec array directly.** A bad pointer crashes `lx` instead of returning `-EFAULT`. Fix with a guarded copy.

## 8. Milestones

1. ✅ Static musl hello world: ELF load, TLS, stdio, exit code. Thread-local storage holds up under preemption.
2. ✅ Unmodified **official Alpine image** binaries: `PT_INTERP` (ld-musl), file-backed `mmap` with syscall patching of libraries loaded at runtime, ~50 syscalls (files, dirs, symlinks, stat, cwd). `ls -la`, `cat`, `grep`, `awk`, `sed`, `find`, `uname`, `sh` builtins, and `apk --version` (libcrypto, libz) all work.
3. ✅ (mostly) Direct-jump syscalls and FS-free TLS: no exception, and no guest-stack writes, on the hot path (§3, §4). Remaining: forward displacement for the last fallback sites, vDSO, control-flow-guided decoding.
4. ✅ Threads and `futex`: pthreads and the Go runtime (goroutines on 16 OS threads, channels, mutexes, timers, GC), 20/20 each. `eventfd` and `madvise(MADV_DONTNEED)` (zero-fill) came with it.
5. ✅ Process model: `fork`/`execve`/`wait4`/pipes/signals. Shell entrypoints work, with pipelines, `$(...)`, background jobs + `wait`, `trap`, `#!` scripts and a final `exec` (`guest/entrypoint.sh`).
6. ✅ Networking: the official `nginx:alpine` image serves HTTP, including its default master + workers mode, with graceful `lx stop`. Measured: about 34 MB working set / 22 MB private for the whole container, and ~0 CPU when idle. Outbound DNS + HTTP works (`wget`, Python sockets). Python's `http.server` needs threads (milestone 4).
7. ✅ (basic) `lx pull <image>` / `lx run <image> [cmd]`. Registry token auth, multi-arch index → linux/amd64, sha256-verified blobs (BCrypt), layers with whiteouts, and Entrypoint/Cmd/Env/WorkingDir from the image config. HTTPS goes through Windows' own `curl.exe`. Tested with `alpine`, `nginx:alpine` (its entrypoint scripts run) and `python:3.12-alpine`. Missing: private registries (credentials), zstd layers, and a per-container copy-on-write layer (containers currently write into the pulled image).

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
LX_DEBUG=1 target/release/lx.exe ...                                       # verbose [lx] diagnostics
target/release/lx.exe rootfs /hello        # → "hello from linux ... tls=42", exit 7
target/release/lx.exe rootfs /stress       # TLS under preemption; with "crash" arg → exit 139
```
