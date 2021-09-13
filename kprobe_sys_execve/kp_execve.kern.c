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

#define _( P )                                                                                                         \
	( {                                                                                                                \
		typeof( P ) val = 0;                                                                                           \
		bpf_probe_read( &val, sizeof( val ), &P );                                                                     \
		val;                                                                                                           \
	} )

/*
    使用perf event来保存eBPF数据，从user程序读取
*/
struct {
	__uint( type, BPF_MAP_TYPE_PERF_EVENT_ARRAY );
	__uint( key_size, sizeof( __u32 ) );
	__uint( value_size, sizeof( __u32 ) ); // 这里不是传输数据的sizeof
	__uint( max_entries, 128 );
} execve_perf_evt_map SEC( ".maps" );

struct {
	__uint( type, BPF_MAP_TYPE_HASH );
	__uint( max_entries, 128 );
	__type( key, pid_t );
	__type( value, struct data_t );
	__uint( value_size, sizeof( struct data_t ) );
} execve_hash SEC( ".maps" );

SEC( "kprobe/" SYSCALL( sys_execve ) )
//int probe_sys_execve( struct pt_regs* ctx ) {
int BPF_KPROBE(probe_sys_execve, const char __user *filename, 
    const char __user *const __user *argv, 
    const char __user *const __user *envp) {

	struct data_t data = {};

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;

	data.pid       = pid;
	data.tid       = tid;
	data.uid       = bpf_get_current_uid_gid();
	// 获取当前的进程名
	bpf_get_current_comm( &data.comm, sizeof( data.comm ) );

	// 读取filename参数内容
	const char * filename_t = (const char *)PT_REGS_PARM1(ctx);
	bpf_probe_read_user_str( &data.filename, sizeof( data.filename ), filename_t );
	//bpf_probe_read_user_str( &data.filename, sizeof( data.filename ), filename);
	printk( "filenameStr:[%s]", data.filename );

	if ( bpf_map_update_elem( &execve_hash, &tid, &data, BPF_NOEXIST ) ) {
		return 0;
	}

	// 打印输出 /sys/kernel/debug/tracing/trace_pipe
	// (%struct.pt_regs*): too many args to 0x55e14eb7daa8: i64 = Constant<6>
	// 上面错误是 bpf_trace_printk 带的参数太多了 http://kerneltravel.net/blog/2020/ebpf_ljr_no3/
	printk( "pid:%d, tid:%d executing program:%s", pid, data.tid, data.comm );
    printk( "filename:[%s]", data.filename );

	return 0;
}

SEC( "kretprobe/" SYSCALL( sys_execve ) )
int BPF_KRETPROBE( kprobe_sys_execve_exit, int ret ) {
	__u32 tid = bpf_get_current_pid_tgid();

	struct data_t* data;
	data = bpf_map_lookup_elem( &execve_hash, &tid );
	if ( data == NULL ) {
		return 0;
	}

	data->ret = ret;

    printk( "kretprobe sys_execve pid:%d, tid:%d executing program:%s", data->pid, data->tid, data->comm );
	// 使用bpf_perf_event_output将data附加到映射上
	// 加上了BPF_F_CURRENT_CPU这个flag后，user测能实时的获得event回调。这是为什么？
	bpf_perf_event_output( ctx, &execve_perf_evt_map, BPF_F_CURRENT_CPU, data, sizeof( *data ) );
	bpf_map_delete_elem( &execve_hash, &tid );
	return 0;
}

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;