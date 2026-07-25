//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifdef __INTELLISENSE__
#undef BPF_CORE_READ_INTO
#define BPF_CORE_READ_INTO(dst, src, ...) ({ *(dst) = 0; 0; })
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

#define TASK_COMM_LEN 16
#define MAX_ARGS 16
#define MAX_ARG_LEN 64
#define MAX_FILENAME_LEN 256

enum event_type {
    EVENT_EXEC = 1,
    EVENT_OPEN = 2,
    EVENT_NET = 3,
};

struct exec_event {
    u32 type; // EVENT_EXEC
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};

struct open_event {
    u32 type; // EVENT_OPEN
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

struct net_event {
    u32 type; // EVENT_NET
    u32 pid;
    char comm[TASK_COMM_LEN];
    u16 family;
    u16 protocol;
    u16 sport;
    u16 dport;
    int oldstate;
    int newstate;
    u8 saddr[4];
    u8 daddr[4];
    u8 saddr_v6[16];
    u8 daddr_v6[16];
};

struct exec_event *unused_exec __attribute__((unused));
struct open_event *unused_open __attribute__((unused));
struct net_event *unused_net __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_pid_map SEC(".maps");

struct execve_args {
    u64 pad;
    int __syscall_nr;
    u32 pad2;
    const char * filename;
    const char *const * argv;
    const char *const * envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_execve(struct execve_args *ctx) {
    struct exec_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);

    e->type = EVENT_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = ppid;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memset(e->argv, 0, sizeof(e->argv));

    const char *const *argv = ctx->argv;
    const char *argp = NULL;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0)
            break;
        if (!argp)
            break;

        bpf_probe_read_user_str(&e->argv[i], MAX_ARG_LEN, argp);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
