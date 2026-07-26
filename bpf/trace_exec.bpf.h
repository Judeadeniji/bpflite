#ifndef __TRACE_EXEC_BPF_H
#define __TRACE_EXEC_BPF_H

#include "types.bpf.h"

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

#endif /* __TRACE_EXEC_BPF_H */
