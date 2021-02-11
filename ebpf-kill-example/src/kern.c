#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <stdlib.h>

#define SIGKILL 9

#define bpfprint(fmt, ...)                                     \
    ({                                                         \
        char __fmt[] = fmt;                                    \
        bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
    })

// Data in this map is accessible in user-space
// The particular syntax with __uint() and __type() and the use of the .maps
// section enable BTF for this map. For an example, "bpftool map dump" will
// show the map structure.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, long);
    __type(value, char);
    __uint(max_entries, 64);
} kill_map SEC(".maps");

// This is the tracepoint arguments of the kill functions
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
struct syscalls_enter_kill_args {
    long long pad;

    long syscall_nr;
    long pid;
    long sig;
};

// 这里定义了BPF_PROG_TYPE_TRACEPOINT类型的BPF Program
SEC("tracepoint/syscalls/sys_enter_kill")
int ebpf_kill_example(struct syscalls_enter_kill_args *ctx) {
    // For this tiny example, we will only listen for "kill -9".
    // Bear in mind that there exist many other signals, and it
    // may be possible to stop or forcefully terminate processes
    // with other signals.
    if (ctx->sig != SIGKILL) return 0;

    bpfprint("[calm]---PID %u is being killed! syscall_nr:%u\n", ctx->pid, ctx->syscall_nr);

    // We can call glibc functions in eBPF program if and only if
    // they are not too large and do not use any of the risky operations
    // disallowed by the eBPF verifier. These include, among others,
    // complex loops and floats.
    long key = labs(ctx->pid);
    int val = 1;

    // Mark the PID as killed in the map.
    // This will create an entry where the killed PID is set to 1.
    bpf_map_update_elem(&kill_map, &key, &val, BPF_NOEXIST);

    return 0;
}

// Some eBPF programs must be GPL licensed. This depends on program types,
// eBPF helpers used and among other things. As this eBPF program is
// integrating with tracepoints, it must be GPL.
char _license[] SEC("license") = "GPL";
