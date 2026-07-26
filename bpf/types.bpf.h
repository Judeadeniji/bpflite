#ifndef __TYPES_BPF_H
#define __TYPES_BPF_H

#ifdef __INTELLISENSE__
#undef BPF_CORE_READ_INTO
#define BPF_CORE_READ_INTO(dst, src, ...) ({ *(dst) = 0; 0; })
#endif

#define TASK_COMM_LEN 16
#define MAX_ARGS 16
#define MAX_ARG_LEN 64
#define MAX_FILENAME_LEN 256

enum event_type {
    EVENT_EXEC = 1,
    EVENT_OPEN = 2,
    EVENT_NET = 3,
    EVENT_SIGNAL = 4,
    EVENT_OOM = 5,
    EVENT_UNLINK = 6,
    EVENT_MOUNT = 7,
    EVENT_SETUID = 8,
    EVENT_BPF = 9,
    EVENT_MODULE = 10,
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

struct signal_event {
    u32 type; // EVENT_SIGNAL
    u32 pid;
    u32 tpid;
    int sig;
    char comm[TASK_COMM_LEN];
};

struct oom_event {
    u32 type; // EVENT_OOM
    u32 trigger_pid;
    u32 victim_pid;
    char trigger_comm[TASK_COMM_LEN];
    char victim_comm[TASK_COMM_LEN];
    long unsigned int pages;
};

struct unlink_event {
    u32 type; // EVENT_UNLINK
    u32 pid;
    char comm[TASK_COMM_LEN];
    char pathname[MAX_FILENAME_LEN];
};

struct mount_event {
    u32 type; // EVENT_MOUNT
    u32 pid;
    char comm[TASK_COMM_LEN];
    char dev_name[MAX_FILENAME_LEN];
    char dir_name[MAX_FILENAME_LEN];
    char fs_type[16];
    unsigned long flags;
};

struct setuid_event {
    u32 type; // EVENT_SETUID
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 uid;
};

struct bpf_event {
    u32 type; // EVENT_BPF
    u32 pid;
    char comm[TASK_COMM_LEN];
    int cmd;
};

struct module_event {
    u32 type; // EVENT_MODULE
    u32 pid;
    char comm[TASK_COMM_LEN];
    char name[64];
};

struct exec_event *unused_exec __attribute__((unused));
struct open_event *unused_open __attribute__((unused));
struct net_event *unused_net __attribute__((unused));
struct signal_event *unused_signal __attribute__((unused));
struct oom_event *unused_oom __attribute__((unused));
struct unlink_event *unused_unlink __attribute__((unused));
struct mount_event *unused_mount __attribute__((unused));
struct setuid_event *unused_setuid __attribute__((unused));
struct bpf_event *unused_bpf __attribute__((unused));
struct module_event *unused_module __attribute__((unused));

#endif /* __TYPES_BPF_H */
