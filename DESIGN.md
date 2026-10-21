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

## 3. Syscall interception

**Now:** linear-sweep decode of each executable segment (`iced-x86`). Each real `syscall` (`0F 05`) becomes `ud2` (`0F 0B`), which is the same length, so no code moves. Any `0F 05` byte pair that isn't an instruction is logged and left alone. A raw byte scan broke the second test binary: it patched an `imul` immediate.

**Dispatch:** the `#UD` reaches a vectored exception handler. If its RIP is in the sorted patch-site list, the handler runs `dispatch()` with Linux registers (`rax` = nr; args in `rdi rsi rdx r10 r8 r9`). It writes back `rax` (result or `-errno`), plus `rcx`/`r11` as the kernel would, and resumes at `rip + 2`. Other faults in guest code report `signal 11` and exit 139.

**Cost:** about 1–2 µs per syscall (exception round trip). That's fine for correctness work but too slow for I/O-heavy servers. **Upgrade path, in order:**
1. **Lazy translation.** Mark guest code non-executable, decode basic blocks on first execution (following control flow, so no desync on embedded data), and replace each `syscall` with a direct `call` into a host-side stub. This removes the exception round trip and solves the red-zone issue (§7). It is the "DBT" of the brief, but only at syscall sites. Everything else still runs natively.
2. **vDSO.** Map a fake vDSO page with `clock_gettime` and `gettimeofday`, implemented from `KUSER_SHARED_DATA`, so the hottest syscalls never trap at all.
3. Self-modifying code and JITs (V8, the JVM, LuaJIT) hook `mprotect(PROT_EXEC)`, so re-scan the pages when they flip to executable.

## 4. TLS: lazy FS-base restore

`arch_prctl(ARCH_SET_FS)` stores the guest thread pointer. When NT zeroes FS base, the next `%fs:` access touches a near-null or kernel address and faults. The handler decodes the faulting instruction, recomputes its address with FS base = 0, and compares the result with the fault address:
- **Equal:** the base was lost. Resume through `lx_fs_tramp`, which skips the red zone, saves `rax`, runs `wrfsbase`, and jumps back to the faulting instruction.
- **Different:** this is a real bug, so it's reported as SIGSEGV.

Every return to the guest goes through the trampoline, because `NtContinue` also loses FS base.

This is exact, not a heuristic. A timing-based version failed under 16-way CPU contention. Measured: 16 concurrent 400M-iteration TLS loops are all correct, with 37–364 reloads each. The cost is one exception per context switch, which is negligible.

## 5. Syscall surface plan (`src/syscall.rs`, a `match` on the number)

| Group | Linux | NT mapping | Status |
|---|---|---|---|
| Process bootstrap | `arch_prctl`, `set_tid_address`, `exit`, `exit_group` | FS emulation, `ExitProcess` | ✅ |
| stdio | `read`, `write`, `writev`, `ioctl(TCGETS/TIOCGWINSZ)` | `ReadFile`/`WriteFile` on std handles; `-ENOTTY` | ✅ (no tty yet) |
| Memory | `mmap`, `munmap`, `mprotect`, `brk`, `madvise` | `VirtualAlloc`/`VirtualProtect`. Guest memory lives in a dedicated window (`0x2000_0000_0000`+) and every allocation is registered, so fork can recreate it. `brk` always fails, and libc falls back to `mmap` | ✅ |
| Files | `openat`, `close`, `fstat`/`newfstatat`, `getdents64`, `lseek`, `readlinkat`, `sendfile`, … | std file APIs on paths resolved by `lx`. fd table → owned HANDLEs with CLOEXEC. `/dev/null`/`zero`/`urandom`/`std*`/`fd/N` emulated | ✅ (`statx`, `pread` next) |
| Time | `clock_gettime`, `nanosleep`, `clock_nanosleep` | `QueryPerformanceCounter`, `NtDelayExecution`, vDSO | partly (no `clock_nanosleep`) |
| Threads | `clone(CLONE_VM\|CLONE_THREAD)`, `futex`, `set_robust_list`, `rseq` → `-ENOSYS` | `CreateThread` + per-thread TEB TLS slots; `futex` → `WaitOnAddress` / `WakeByAddress*` | Go and multithreaded C need it |
| Processes | `fork`, `vfork`, `clone` (no threads), `execve`, `wait4`, `pipe2` | **fork** = start `lx --fork`. The child re-reserves every registered guest allocation at the same address and copies the paused parent's memory (`ReadProcessMemory`), along with registers, FS base, syscall-site registry, signal state and fds (handles inherited at the same values), then resumes after the syscall with `rax = 0`. Same idea as Cygwin. **execve** = start `lx --exec` with fds/cwd/argv/env; the old process waits and forwards the exit code. `#!` scripts are handled by the loader. **pipes** = anonymous pipes; EOF works because each fd owns its handle and CLOEXEC handles aren't inherited | ✅ ~23 ms per fork+exec. Faster later: exec in place (one process, not two), and skip the copy when a vfork child execs immediately |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigsuspend`, `rt_sigreturn`, `kill`/`tkill`/`tgkill` | Real dispositions and mask. Delivery happens at syscall return, with a Linux-layout frame (`siginfo` + `ucontext`) placed by `lx_sig_tramp` after `NtContinue`. Handlers return via `rt_sigreturn`. SIGCHLD is raised when a child exits; default actions terminate (exit 128+n) or ignore | ✅ in-process. **Next:** cross-process `kill` (`docker stop` → SIGTERM to pid 1) needs a per-process signal channel; async delivery into a busy loop needs thread hijack (`SuspendThread`/`SetThreadContext`) |
| I/O multiplexing | `epoll_*`, `poll`, `ppoll`, `eventfd`, `pipe2` | AFD (`\Device\Afd`, `IOCTL_AFD_POLL`) for sockets, the way wepoll and libuv do it; pipes via named-pipe pairs | needed by every server |
| Sockets | `socket`, `bind`, `listen`, `accept4`, `connect`, `sendto`/`recvfrom`, `setsockopt` | Winsock, with flag and struct translation | with epoll |
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
- **Red zone.** The NT exception dispatcher writes below the guest `rsp`. A leaf function holding live data in its red zone across a `syscall` would be corrupted. musl's wrappers aren't affected in practice, but lazy translation (§3.1) removes the trap entirely.
- **Linear-sweep desync** can hide a real `syscall` behind data in `.text`. It's logged, and lazy translation fixes it.
- **Single guest thread.** `LX_GUEST_FS` and `LX_RESUME_RIP` are globals. They move to TEB TLS slots (`gs:[0x1480+8*i]`) when `clone` lands.
- **`writev` reads the iovec array directly.** A bad pointer crashes `lx` instead of returning `-EFAULT`. Fix with a guarded copy.

## 8. Milestones

1. ✅ Static musl hello world: ELF load, TLS, stdio, exit code. Thread-local storage holds up under preemption.
2. ✅ Unmodified **official Alpine image** binaries: `PT_INTERP` (ld-musl), file-backed `mmap` with syscall patching of libraries loaded at runtime, ~50 syscalls (files, dirs, symlinks, stat, cwd). `ls -la`, `cat`, `grep`, `awk`, `sed`, `find`, `uname`, `sh` builtins, and `apk --version` (libcrypto, libz) all work.
3. Lazy translation (replaces linear sweep and the exception round trip).
4. Threads and `futex`: static Go binaries (`hello`, then `net/http` once epoll exists).
5. ✅ Process model: `fork`/`execve`/`wait4`/pipes/signals. Shell entrypoints work, with pipelines, `$(...)`, background jobs + `wait`, `trap`, `#!` scripts and a final `exec` (`guest/entrypoint.sh`).
6. AFD epoll and Winsock: an Alpine nginx or node image serves HTTP.
7. OCI pull/unpack and a `docker run`-shaped CLI.

## Build and run

```sh
# portable toolchains live in tools/ (no PATH or registry changes)
W=$(cygpath -m $PWD); export RUSTUP_HOME=$W/tools/rust/rustup CARGO_HOME=$W/tools/rust/cargo MSYS_NO_PATHCONV=1
tools/rust/cargo/bin/cargo build --release
tools/zig-x86_64-windows-0.15.2/zig.exe cc -target x86_64-linux-musl -static -O2 -o rootfs/hello guest/hello.c
target/release/lx.exe unpack alpine-minirootfs-x86_64.tar.gz rootfs/alpine   # an image layer
target/release/lx.exe rootfs/alpine ls -la /                               # PATH lookup inside the image
cp guest/entrypoint.sh rootfs/alpine/ && target/release/lx.exe rootfs/alpine /entrypoint.sh   # shell entrypoint
LX_DEBUG=1 target/release/lx.exe ...                                       # verbose [lx] diagnostics
target/release/lx.exe rootfs /hello        # → "hello from linux ... tls=42", exit 7
target/release/lx.exe rootfs /stress       # TLS under preemption; with "crash" arg → exit 139
```
