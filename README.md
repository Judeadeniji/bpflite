# bpflite

[![Build](https://github.com/Judeadeniji/bpflite/actions/workflows/build.yml/badge.svg)](https://github.com/Judeadeniji/bpflite/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`bpflite` is a lightweight, CO-RE (Compile Once, Run Everywhere) eBPF-based systems tracer written in Go. It attaches to kernel tracepoints to observe process lifecycle (`execve`), file activity (`openat`), and network state changes (TCP lifecycle) in real-time.

It features a live, streaming Bubble Tea TUI, an invisible background daemon for historical SQLite logging, and a highly scriptable JSON output mode.

## Features

- **`execve` tracing:** Monitor all new processes spawning across the system, including full arguments.
- **`openat` tracing:** Monitor files being opened, optionally filtered to a specific PID.
- **TCP Network tracing:** Observe TCP connection lifecycles across the system (connect, accept, close) using the `inet_sock_set_state` tracepoint.
- **Daemon & SQLite Logging:** Fork the tracer into the background as a headless daemon (`record`) to persistently log events to a local SQLite database.
- **CLI Querying:** Use the `history` and `dump` commands to query historical logs with powerful `text/template` formats or raw JSON.
- **CO-RE:** Uses `cilium/ebpf` and `bpf2go`. No runtime `clang` or kernel headers required on the target machine.

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

### Live Tracing (TUI & JSON)
```bash
# Trace all new processes in the TUI
sudo bin/bpflite trace exec

# Trace all network TCP state changes
sudo bin/bpflite trace net

# Trace files opened by a specific PID
sudo bin/bpflite trace open --pid 1234

# Output any trace strictly as JSON (great for jq)
sudo bin/bpflite trace exec --json | jq
```

### Background Daemon (Recording)
```bash
# Start logging all events to a SQLite database in the background
sudo bin/bpflite record --daemon

# Stop the daemon gracefully
sudo bin/bpflite stop
```

### Querying History
```bash
# Pretty-print the last 50 events recorded by the daemon
./bin/bpflite history

# Use a custom Go template format (like Docker/Git)
./bin/bpflite history --format "{{.Timestamp}} | PID: {{.Pid}} | {{.Type}} | {{.Comm}}"

# Print history as JSON
./bin/bpflite history --json

# Dump the entire database to JSON lines (bypass limit)
./bin/bpflite dump
```

### Running without `sudo`
You can grant the compiled binary the necessary Linux capabilities so it doesn't require full root privileges to attach eBPF probes:
```bash
sudo setcap cap_bpf,cap_perfmon+ep bin/bpflite
bin/bpflite trace exec
```

## Contributing
Pull requests are welcome! Please ensure that your eBPF C code satisfies the verifier and that `make all` successfully embeds your bytecode before submitting.

## License
MIT License. See [LICENSE](LICENSE) for more information.
