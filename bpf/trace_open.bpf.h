#ifndef __TRACE_OPEN_BPF_H
#define __TRACE_OPEN_BPF_H

#include "types.bpf.h"

struct openat_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    int dfd;
    u32 pad3;
    const char *filename;
    int flags;
    umode_t mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_openat(struct openat_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct open_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_OPEN;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_OPEN_BPF_H */
