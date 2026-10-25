# lx

Run unmodified Linux Docker/OCI images natively on Windows. There's no VM, no WSL, no Hyper-V and no driver.

Each Linux process is an ordinary Windows process. Its x86-64 code runs directly on the CPU, and only the Linux system calls are translated to NT. Nothing boots and there's no guest kernel sitting in RAM, so an idle container costs about as much as an idle Windows program.

## Build

You need a Rust toolchain (edition 2024).

```
cargo build --release
```

The binary is `target/release/lx.exe`.

## Use

```
lx pull nginx:alpine
lx run -p 8080:80 nginx:alpine
lx run -d --name db -e POSTGRES_PASSWORD=pw postgres:16
lx exec db psql -U postgres
lx build -t myapp .
lx compose up -d
lx ps | lx logs <name> | lx stop <name> | lx images | lx rmi <image>
```

Run `lx` with no arguments for the full usage.

Images and volumes are stored under `rootfs/` in the current directory. Run `lx stop`, `lx ps` and `lx exec` from the same directory you ran `lx run` from.

## What works

- **Shells and distributions:** Alpine, Debian and Ubuntu shells, with `apk` and `apt`.
- **Language runtimes:** Python, Node, Go, Java, Ruby, PHP and Rust toolchains.
- **Servers:** nginx, PostgreSQL, MariaDB, Redis and RabbitMQ.
- **Docker features:** Dockerfile builds, compose files, published ports, volumes, `exec`, signals and job control.

Most of the Go standard library test suite passes.

## Known limits

- **Faults in Go programs.** On every fault, Windows writes about 2.8 KB below the faulting stack pointer. That can corrupt a neighbouring goroutine stack when a Go program recovers from nil-pointer panics under load.
- **.NET** doesn't run yet, because of how it maps W^X memory.
- **Missing features:** `AF_UNIX` `SOCK_SEQPACKET` isn't implemented.
- **Architecture:** x86-64 images only.

See [DESIGN.md](DESIGN.md) for how it works and why.

## Tests

```
cargo test --release
bash tests/run.sh
```

`tests/run.sh` is the integration suite. It pulls real images, so it needs disk space and network access.
