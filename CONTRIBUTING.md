# Contributing to bpflite

First off, thank you for considering contributing to `bpflite`! It's people like you that make the open-source community such an amazing place to learn, inspire, and create.

## Project Structure
`bpflite` is a CO-RE (Compile Once, Run Everywhere) eBPF tool. The codebase is roughly split into two parts:
- **eBPF C Code**: Located in `bpf/probe.bpf.c`. This code runs in kernel space.
- **Go Userspace Code**: Located in `cmd/` and `internal/`. This code loads the eBPF programs, reads the ring buffers, and formats the output.

## Local Development Setup

1. You must be running on a Linux machine with Kernel 5.8+ (for eBPF ring buffer support).
2. Ensure you have the necessary build tools installed:
   ```bash
   sudo apt-get update
   sudo apt-get install clang llvm make golang
   ```
3. Verify your kernel has BTF info enabled (`/sys/kernel/btf/vmlinux` should exist).

## Build Pipeline

We use `make` and `go generate` to compile the C code into eBPF bytecode using `cilium/ebpf/cmd/bpf2go`.

```bash
make all
```

This command will:
1. Compile `bpf/probe.bpf.c` into `.o` bytecode objects.
2. Generate the Go scaffold files (`bpf/probe_bpfel.go` and `bpf/probe_bpfeb.go`).
3. Compile the final `bpflite` binary into the `bin/` directory.

## Rules for eBPF code (`bpf/probe.bpf.c`)
- **No BCC:** We rely strictly on `libbpf` and CO-RE. Do not use BCC wrappers.
- **Struct Alignment:** Any event struct you define in C (e.g. `struct exec_event`) **MUST** be byte-for-byte identical to the Go struct defined in `internal/event/event.go`.
- **Verifier Limits:** Keep eBPF programs simple. The kernel verifier will reject programs with unbounded loops, uninitialized variables, or pointer arithmetic on context pointers without bounds checking. Always read directly from the struct using standard direct-reads (or `bpf_probe_read_kernel` where necessary).

## Submitting a Pull Request

1. Fork the repo and create your branch from `main`.
2. Make sure your code compiles via `make all` without any eBPF verifier errors.
3. Test your changes locally. If you add a new tracepoint, verify that the events stream cleanly via `sudo bin/bpflite trace <new_command>`.
4. Keep commits atomic and descriptive.
5. Open a Pull Request! A GitHub Action will automatically run `make all` on your PR to verify compilation across architectures.

Thank you for contributing!
