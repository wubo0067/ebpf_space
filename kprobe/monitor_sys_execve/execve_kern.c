/*
 * @Author: CALM.WU
 * @Date: 2021-08-20 10:30:24
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-24 19:26:38
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>
//#include <uapi/linux/bpf_perf_event.h>
//#include <uapi/linux/perf_event.h>

// #include <linux/sched.h>
// #include <linux/stringify.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

#include "execve_data.h"

/*
sys_execve(const char __user *filename,
        const char __user *const __user *argv,
        const char __user *const __user *envp);
*/

#define printk( fmt, ... )                                                                                             \
	( {                                                                                                                \
		char ____fmt[] = fmt;                                                                                          \
		bpf_trace_printk( ____fmt, sizeof( ____fmt ), ##__VA_ARGS__ );                                                 \
	} )

/*
    使用perf event来保存eBPF数据，从user程序读取
*/
struct
{
	__uint( type, BPF_MAP_TYPE_PERF_EVENT_ARRAY );
	__uint( key_size, sizeof( int ) );
	__uint( value_size, sizeof( __u32 ) ); // 这里不是传输数据的sizeof
	__uint( max_entries, 128 );
} execve_map SEC( ".maps" );

SEC( "kprobe/" SYSCALL( sys_execve ) )
int kprobe_sys_execve( struct pt_regs* ctx ) {
	struct data_t data;

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid();

	// 获取当前的进程名
	bpf_get_current_comm( &data.comm, sizeof( data.comm ) );

	// 打印输出 /sys/kernel/debug/tracing/trace_pipe
	// (%struct.pt_regs*): too many args to 0x55e14eb7daa8: i64 = Constant<6>
	// 上面错误是 bpf_trace_printk 带的参数太多了 http://kerneltravel.net/blog/2020/ebpf_ljr_no3/
	// printk( "pid:%d, uid:%d, executing program: %s", pid, uid, comm );

	// struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	// char *file_name = (char *)PT_REGS_PARM1_CORE(real_regs);
	// 读取filename参数内容
	bpf_probe_read_user_str( &data.filename, sizeof( data.filename ), ( char* ) PT_REGS_PARM1( ctx ) );
	// printk( "filenameStr:[%s]", filenameStr );

	// 使用bpf_perf_event_output将data附加到映射上
	// 加上了BPF_F_CURRENT_CPU这个flag后，user测能实时的获得event回调。这是为什么？
	bpf_perf_event_output( ctx, &execve_map, BPF_F_CURRENT_CPU, &data, sizeof( data ) );

	// ebpf无法调用内核的函数
	// struct filename* f = getname( ( const char __user* ) PT_REGS_PARM1( ctx ) );
	// printk( "filename:[%s]", f->name );

	return 0;
}

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;