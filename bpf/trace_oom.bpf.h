#ifndef __TRACE_OOM_BPF_H
#define __TRACE_OOM_BPF_H

#include "types.bpf.h"

SEC("tracepoint/oom/mark_victim")
int trace_oom_mark_victim(struct trace_event_raw_mark_victim *ctx) {
    u32 trigger_pid = bpf_get_current_pid_tgid() >> 32;
    u32 victim_pid = ctx->pid;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != trigger_pid && *target_pid != victim_pid) {
        return 0; // only trace if trigger or victim matches filter
    }

    struct oom_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_OOM;
    e->trigger_pid = trigger_pid;
    e->victim_pid = victim_pid;
    e->pages = ctx->total_vm;
    bpf_get_current_comm(&e->trigger_comm, sizeof(e->trigger_comm));
    
    // The victim process name is stored dynamically at the end of the tracepoint struct
    u16 offset = ctx->__data_loc_comm & 0xFFFF;
    bpf_probe_read_kernel_str(&e->victim_comm, sizeof(e->victim_comm), (void *)ctx + offset);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_OOM_BPF_H */
