#ifndef __TRACE_MOUNT_BPF_H
#define __TRACE_MOUNT_BPF_H

#include "types.bpf.h"

struct mount_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    char *dev_name;
    char *dir_name;
    char *type;
    unsigned long flags;
    void *data;
};

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_sys_mount(struct mount_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct mount_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_MOUNT;
    e->pid = pid;
    e->flags = ctx->flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_probe_read_user_str(&e->dev_name, sizeof(e->dev_name), ctx->dev_name);
    bpf_probe_read_user_str(&e->dir_name, sizeof(e->dir_name), ctx->dir_name);
    bpf_probe_read_user_str(&e->fs_type, sizeof(e->fs_type), ctx->type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_MOUNT_BPF_H */
