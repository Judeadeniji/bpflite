# bpflite

`bpflite` is a lightweight, CO-RE (Compile Once, Run Everywhere) eBPF-based tracer written in Go. It attaches to kernel tracepoints to observe process lifecycle (`execve`) and file activity (`openat`) in real-time.

It features a live, streaming Bubble Tea TUI, as well as a script-friendly JSON output mode.

## Features

- **`execve` tracing:** Monitor all new processes spawning across the system, including full arguments.
- **`openat` tracing:** Monitor files being opened, optionally filtered to a specific PID.
- **CO-RE:** Uses `cilium/ebpf` and `bpf2go`. No runtime `clang` or kernel headers required on the target machine.
- **TUI & JSON:** View data in a pretty, scrollable terminal UI, or pipe JSON output to `jq`.

## Requirements

- Linux Kernel 5.8+ (for eBPF ring buffer support).
- Kernel built with `CONFIG_DEBUG_INFO_BTF=y` (verify with `ls /sys/kernel/btf/vmlinux`).
- `sudo` (or `CAP_BPF` + `CAP_PERFMON` capabilities).

## Building from source

Use the provided `Makefile` to generate the eBPF bytecode and compile the Go binary:

```bash
make all
```

This will run `go generate` and `go build` with the proper ldflags for versioning.

## Usage

```bash
# Trace all new processes in the TUI
sudo bin/bpflite trace exec

# Trace all new processes, output as JSON
sudo bin/bpflite trace exec --json | jq

# Trace all files being opened in the TUI
sudo bin/bpflite trace open

# Trace files opened by a specific PID
sudo bin/bpflite trace open --pid 1234
```

### Running without `sudo`
You can grant the compiled binary the necessary Linux capabilities so it doesn't require full root privileges to attach eBPF probes:
```bash
sudo setcap cap_bpf,cap_perfmon+ep bin/bpflite
bin/bpflite trace exec
```

## Check version
```bash
bin/bpflite --version
```
