#ifndef __TRACE_SIGNAL_BPF_H
#define __TRACE_SIGNAL_BPF_H

#include "types.bpf.h"

struct kill_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    pid_t pid;
    int sig;
};

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_sys_kill(struct kill_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid && *target_pid != ctx->pid) {
        return 0; // only trace if sender or target matches filter
    }

    struct signal_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_SIGNAL;
    e->pid = pid;
    e->tpid = ctx->pid;
    e->sig = ctx->sig;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_SIGNAL_BPF_H */
