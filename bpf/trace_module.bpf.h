#ifndef __TRACE_MODULE_BPF_H
#define __TRACE_MODULE_BPF_H

#include "types.bpf.h"

struct finit_module_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    int fd;
    u32 pad3;
    const char *param_values;
    int flags;
};

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_sys_finit_module(struct finit_module_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct module_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_MODULE;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->name, 0, sizeof(e->name));
    
    // We can't easily extract module name from finit_module (it's in the FD).
    // We'll leave the name blank and the user can check the param_values if needed.
    // Let's at least copy the first part of param_values if available.
    if (ctx->param_values) {
        bpf_probe_read_user_str(&e->name, sizeof(e->name), ctx->param_values);
    } else {
        const char *unknown = "<finit_module>";
        __builtin_memcpy(&e->name, unknown, sizeof("<finit_module>"));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct init_module_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    void *umod;
    unsigned long len;
    const char *uargs;
};

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_sys_init_module(struct init_module_args *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct module_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_MODULE;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memset(e->name, 0, sizeof(e->name));
    
    if (ctx->uargs) {
        bpf_probe_read_user_str(&e->name, sizeof(e->name), ctx->uargs);
    } else {
        const char *unknown = "<init_module>";
        __builtin_memcpy(&e->name, unknown, sizeof("<init_module>"));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_MODULE_BPF_H */
