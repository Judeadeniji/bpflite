#ifndef __TRACE_NET_BPF_H
#define __TRACE_NET_BPF_H

#include "types.bpf.h"

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 key = 0;
    u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    
    if (target_pid && *target_pid != 0 && *target_pid != pid) {
        return 0;
    }

    struct net_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_NET;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    e->family = ctx->family;
    e->protocol = ctx->protocol;
    e->sport = ctx->sport;
    e->dport = ctx->dport;
    e->oldstate = ctx->oldstate;
    e->newstate = ctx->newstate;
    
    // actually, let's use direct pointer casting to force Clang to emit scalar loads
    *(u32 *)e->saddr = *(u32 *)ctx->saddr;
    *(u32 *)e->daddr = *(u32 *)ctx->daddr;
    
    *(u64 *)&e->saddr_v6[0] = *(u64 *)&ctx->saddr_v6[0];
    *(u64 *)&e->saddr_v6[8] = *(u64 *)&ctx->saddr_v6[8];
    *(u64 *)&e->daddr_v6[0] = *(u64 *)&ctx->daddr_v6[0];
    *(u64 *)&e->daddr_v6[8] = *(u64 *)&ctx->daddr_v6[8];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

#endif /* __TRACE_NET_BPF_H */
