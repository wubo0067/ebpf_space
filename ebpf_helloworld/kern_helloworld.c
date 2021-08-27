/*
 * @Author: calmwu
 * @Date: 2021-02-11 17:16:06
 * @Last Modified by: calmwu
 * @Last Modified time: 2021-02-11 20:56:10
 */

//#include <linux/ptrace.h>
//#include <linux/version.h>
//#include <linux/types.h>
//#include <asm/types.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
//#include <linux/bpf.h>
//#include <stdlib.h>
//#include <stdint.h>

#define ARG_MAX         16	/* # chars in a file name */

# define printk(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})

struct syscalls_enter_execve_args {
    u64 pad;

    u64 syscall_nr;
    const char *filename_ptr;
    char *const *argv;
    char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct syscalls_enter_execve_args *ctx) {
    // char msg[] = "Hello, BPF world!";
    // bpfprint(msg);

    // char arg[ARG_MAX] = {};

    //char fmt_1[] = "execve program: %s";
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    printk("execve program: %s",  comm);

    //char fmt_2[] = "execve process running with PID: %d";
    u64 pid = bpf_get_current_pid_tgid();
    printk("execve process running with PID: %d", pid);

    //char fmt[] = "execve syscall_nr{%u} filename_ptr:[%s]\n";
    printk("execve syscall_nr{%u} filename_ptr:[%s]", ctx->syscall_nr, ctx->filename_ptr);

    // 最多三个参数，这个输出和/sys/kernel/debug/tracing/trace_pipe一样
    printk("execve filename: %lx argv: %lx, envp: %lx", (u64)(ctx->filename_ptr), (u64)(ctx->argv), (u64)(ctx->envp));

    //printk("execve argv[0]: %p", (ctx->argv)[0]);

    // char arg0[ARG_MAX] = {};

    // // // bpf_probe_read_user_str(arg0, ARG_MAX, ((char **)(ctx->argv))[0]);
    // // // printk("execve program first args:%s\n", ((char *const
    // // // *)(ctx->argv))[0]);
    // char *const *argv_pp = (char *const *)ctx->argv;
    // bpf_probe_read(arg0, ARG_MAX - 1, (const void*)*argv_pp);
    // printk("execve argv[0]: %s\n", arg0);

    // // char fmtArgv[] = "argc:%d";
    // char *const *argv_pp = (char *const *)(ctx->argv);
    // for (char *argv_p = *argv_pp; argv_p;) {
    //     if (NULL == argv_p) {
    //         break;
    //     }
    //     argv_pp = argv_pp + 1;
    //     argv_p = *argv_pp;
    // }

    //     //bpf_probe_read(&arg, sizeof(arg), (void*)argv[i]);
    //     // else {
    //     //     bpf_trace_printk(fmtArgv, sizeof(fmtArgv), i);
    //     // }
    //     //(void)(fmtArgv);
    //     bpf_trace_printk(fmtArgv, sizeof(fmtArgv), i);
    // }
    printk("-------------------\n");
    return 0;
}

char _license[] SEC("license") = "GPL";