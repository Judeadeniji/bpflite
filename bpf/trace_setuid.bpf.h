#ifndef __TRACE_SETUID_BPF_H
#define __TRACE_SETUID_BPF_H

#include "types.bpf.h"

struct setuid_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    uid_t uid;
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_sys_setuid(struct setuid_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct setuid_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_SETUID;
    e->pid = pid;
    e->uid = ctx->uid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_SETUID_BPF_H */
