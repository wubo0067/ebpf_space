/*
 * @Author: CALM.WU 
 * @Date: 2021-08-20 10:30:24 
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-23 17:43:29
 */


#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>

#include <linux/stringify.h>
#include <trace_common.h>
#include <linux/sched.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
*/

# define printk(fmt, ...)						            \
		({							                        \
			char ____fmt[] = fmt;				            \
			bpf_trace_printk(____fmt, sizeof(____fmt),	    \
				     ##__VA_ARGS__);			            \
		})



SEC("kprobe/" SYSCALL(sys_execve))
int kprobe_sys_execve(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid();
    __u32 uid = bpf_get_current_uid_gid();

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    const char * filename = "hello";

    int filenamePtr = (int)PT_REGS_PARM1(ctx);

    // 打印输出 /sys/kernel/debug/tracing/trace_pipe
    // (%struct.pt_regs*): too many args to 0x55e14eb7daa8: i64 = Constant<6>
    // 上面错误是 bpf_trace_printk 带的参数太多了 http://kerneltravel.net/blog/2020/ebpf_ljr_no3/
    printk("pid:%d, uid:%d, comm:%s", pid, uid, comm);
    printk("filename:%s", (const char*)filenamePtr);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;