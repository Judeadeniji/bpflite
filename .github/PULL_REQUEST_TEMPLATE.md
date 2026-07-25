## Description
<!-- Please include a summary of the changes and the related issue. -->
<!-- Describe the problem you are fixing and how this PR solves it. -->

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## eBPF Checklist
<!-- If this PR modifies the eBPF C code, please check the following: -->
- [ ] The eBPF program passes the kernel verifier without issues.
- [ ] Any C structs modified in `bpf/probe.bpf.c` have been exactly mirrored in `internal/event/event.go`.
- [ ] I have successfully run `make all` and the bytecode embeds correctly.

## Testing

- [ ] I have tested this locally on a Linux kernel 5.8+ system.
- [ ] I have verified the TUI / JSON output looks correct.
