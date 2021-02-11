/*
 * @Author: calmwu
 * @Date: 2021-02-11 17:16:06
 * @Last Modified by: calmwu
 * @Last Modified time: 2021-02-11 20:56:10
 */

#include <linux/types.h>
#include <asm/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <stdlib.h>

#define bpfprint(fmt, ...)                                     \
    ({                                                         \
        bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__); \
    })


SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    char msg[]="Hello, BPF world!";
    bpfprint(msg);
    return 0;
}

char _license[] SEC("license") = "GPL";