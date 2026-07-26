#ifndef __TRACE_BPF_BPF_H
#define __TRACE_BPF_BPF_H

#include "types.bpf.h"

struct bpf_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    int cmd;
    u32 pad3;
    union bpf_attr *attr;
    u32 size;
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_sys_bpf(struct bpf_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct bpf_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_BPF;
    e->pid = pid;
    e->cmd = ctx->cmd;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_BPF_BPF_H */
