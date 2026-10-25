<div align="center">

# lx

**Run Linux containers natively on Windows. No VM. No WSL. No Hyper-V.**

`lx` runs unmodified Docker / OCI images as ordinary Windows processes.<br>
Linux code runs directly on your CPU, and only the system calls are translated.

[Quick start](#quick-start) · [How it works](#how-it-works) · [Compatibility](#compatibility) · [Design doc](DESIGN.md)

</div>

---

```console
> lx run -p 8080:80 nginx:alpine
> curl http://localhost:8080
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
...
```

That nginx is a plain `nginx` process in Task Manager. No virtual machine boots, no Linux kernel sits in memory, and nothing runs once the container has stopped.

## Why

Docker on Windows means a hidden Linux VM. It holds gigabytes of RAM, runs a whole second kernel, and uses CPU even when every container is idle. You pay all of that just to run a few Linux processes.

`lx` drops the VM:

- **Nothing to install.** It's one `.exe`. You don't need admin rights, drivers, Windows features or a reboot.
- **No idle cost.** A container is just its processes. An idle Python `http.server` uses about 0.08 CPU-seconds per 30 s.
- **Native speed.** Guest code isn't emulated or JIT-compiled. It runs as is, and only the kernel boundary is translated.
- **Native integration.** Containers show up in Task Manager and use your normal network stack. Volumes are plain Windows folders.
- **Familiar CLI.** `pull`, `run`, `exec`, `build`, `compose`, `logs`, `ps` and `stop` work the way Docker's do.

## Quick start

Build it with a Rust toolchain:

```console
> git clone https://github.com/Lukas-dev1/docker_but_better
> cd docker_but_better
> cargo build --release
```

The binary is `target\release\lx.exe`. Then:

```console
> lx run --rm alpine sh -c "uname -a; cat /etc/os-release"
> lx run -d --name db -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:16
> lx exec db psql -U postgres -c "select version()"
> lx build -t myapp .
> lx compose up -d
```

## Usage

| Command | |
|---|---|
| `lx pull <image>` | Pull an image from Docker Hub or another registry |
| `lx run [opts] <image> [cmd...]` | Run a container (`-d` runs it in the background) |
| `lx exec [-e] [-w] [-u] <name> <cmd...>` | Run a command in a running container |
| `lx build -t name[:tag] [-f Dockerfile] <dir>` | Build an image from a Dockerfile |
| `lx compose [-f file] up [-d] \| down \| ps \| logs` | Run a compose file's services |
| `lx ps` · `lx logs` · `lx stop` · `lx kill` | Manage running containers |
| `lx images` · `lx rmi` | Manage local images |

`run` options: `-p [ip:]host:port[/udp]` · `-v C:\host:/path[:ro]` · `-e NAME=value` · `-w dir` · `-u user[:group]` · `-m 2g` · `--name` · `--add-host` · `--entrypoint` · `--rm`

> [!NOTE]
> Images, containers and volumes live in `rootfs\` in the current directory. Run `lx ps`, `lx exec` and `lx stop` from the same directory you ran `lx run` from.

## How it works

```
┌─────────────── one Windows process per Linux process ───────────────┐
│                                                                     │
│   Linux ELF code, running natively on the CPU                       │
│        │                                                            │
│        │  `syscall` and `%fs:` accesses are rewritten at load        │
│        │  time and at mmap(PROT_EXEC)                                │
│        ▼                                                            │
│   lx runtime: Linux syscall table → NT / Win32                      │
│        files · processes · threads · signals · sockets · pipes ·    │
│        epoll · futex · mmap · /proc · ptys · job control            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

- **Loading:** `lx` loads the ELF binary itself, either static or through the image's own `ld.so`.
- **Rewriting:** before any guest code runs, `lx` rewrites every `syscall` instruction and every TLS access so it jumps into the runtime.
- **The runtime** implements the Linux kernel ABI on top of NT:
  - `fork` is spawn-and-copy.
  - Signals are delivered cooperatively.
  - Each container gets its own loopback IP (`127.x.y.z`), and `-p` maps its ports to the host.
- **Isolation:** each container runs inside a Windows job object.

Read [DESIGN.md](DESIGN.md) for the details: the NT behaviour that shaped the design, measured on real hardware.

## Compatibility

Tested with real, unmodified images from Docker Hub:

| | Works |
|---|---|
| **Distros** | Alpine (`apk`), Debian and Ubuntu (`apt`) |
| **Languages** | Python · Node.js · Go · Java · Ruby · PHP · Rust |
| **Servers** | nginx · PostgreSQL · MariaDB · Redis · RabbitMQ |
| **Tooling** | Dockerfile builds · Compose · published ports · volumes · `exec` · signals · job control |

Two upstream test suites run on lx:

- **Go standard library tests:** `os` passes 164 of 165. `net/http`, `crypto/tls`, `os/exec`, `syscall` and many other packages pass.
- **Linux Test Project (LTP) syscall tests:** 43.9 % pass. The project tracks this number.

### Known limitations

- **x86-64 images only.**
- **Go programs and faults:** Windows writes about 2.8 KB below the stack pointer on every CPU fault. A Go program that recovers from nil-pointer panics under heavy load can corrupt a neighbouring goroutine's stack. There's no fix for this in user mode.
- **.NET** doesn't run yet, because of how it maps W^X memory.
- **Missing:** `AF_UNIX` `SOCK_SEQPACKET`, and namespaces and cgroups beyond what job objects provide.
- **Not a security boundary yet.** Don't run untrusted images.

## Performance

Measured on an Intel Core i7-13620H laptop with 16 GB RAM and an SSD, running Windows 11:

| | lx |
|---|---|
| `alpine` start and exit | 76 ms |
| `python:3.12-alpine` start and exit | 160 ms |
| `nginx` start to first response | 1.14 s |
| Idle nginx + redis + postgres | 707 MB (28 processes) |
| nginx keep-alive throughput | 3,438 req/s |
| Shell `fork` + `exec` | 52 ms |
| Create 5,000 small files | 3.2 s |

For rough context only, published Docker Desktop figures from a different machine (macOS) put a container start at 1.5–1.9 s, with a 1.8–3 GB VM running in the background. This is not a head-to-head comparison.

**Weak spot:** `fork` + `exec` takes about 50 ms, against roughly 1 ms on real Linux, because Windows has no cheap fork. That's why nginx needs 1.1 s to start: its entrypoint runs about 20 of them.

## lx vs Docker Desktop

| | lx | Docker Desktop (WSL 2) |
|---|---|---|
| Virtual machine | none | Hyper-V utility VM |
| Linux kernel | none, syscalls are translated | real kernel |
| Install | one `.exe`, no admin rights | installer, WSL, Windows features, reboot |
| Idle cost | zero once containers stop | VM keeps its RAM and CPU |
| Processes | visible in Task Manager | hidden inside the VM |
| Compatibility | most common images (see above) | everything Linux runs |

Docker Desktop is the right choice if you need full Linux kernel behaviour. lx is for running everyday containers without the VM.

## Development

```console
> cargo test --release      # unit tests
> bash tests/run.sh         # integration suite: pulls real images, needs network and disk space
```

| Path | |
|---|---|
| `src/` | the runtime: loader, syscall translation, fs, net, signals, processes, CLI |
| `guest/` | small Linux C programs used as tests |
| `tests/` | integration suite |
| `probe/` | experiments that measure the NT behaviour the design relies on |

Contributions are welcome. Keep pull requests small and single-purpose, each with a test.
