/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 10:49:37
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 19:14:08
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>

//#include <bpf/bpf_core_read.h> 这个需要BTF支持
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

#include "event.h"

#define printk( fmt, ... )                                                                                             \
	( {                                                                                                                \
		char ____fmt[] = fmt;                                                                                          \
		bpf_trace_printk( ____fmt, sizeof( ____fmt ), ##__VA_ARGS__ );                                                 \
	} )

// 缓存event数据，hook tracepoints函数时用于记录数据
struct {
	__uint( type, BPF_MAP_TYPE_HASH );
	__uint( max_entries, 1024 );
	__type( key, pid_t );
	__type( value, struct event_t );
	__uint( value_size, sizeof( struct event_t ) );
} execve_hash SEC( ".maps" );

// 将ebpf数据做为event上报
struct {
	__uint( type, BPF_MAP_TYPE_PERF_EVENT_ARRAY );
	__uint( key_size, sizeof( __s32 ) );
	__uint( value_size, sizeof( __u32 ) ); // 这里不是传输数据的sizeof
	__uint( max_entries, 128 );
} execve_perf_evt_map SEC( ".maps" );

// Based on /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct enter_execve_args {
	// __s16 common_type;
	// char common_flags;
	// char common_preempt_count;
	// __s32 common_pid;
	unsigned long long unused;
	__s32 __syscall_nr;
	char* filename;
	const char* const* argv;
	const char* const* envp;
};

// Based on /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format
struct exit_execve_args {
	__s16 common_type;
	char common_flags;
	char common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__s64 ret;
};

static struct event_t empty_event = {};

// user程序可以设置具体值，volatile保证变量每次都从内存读取，而不是寄存器和cache
// 相当于外部传入的参数，而控制ebpf内核程序
const volatile __s32 max_args     = DEFAULT_MAXARGS;
const volatile uid_t target_uid   = INVALID_UID;
const volatile bool ignore_failed = true;

SEC( "tracepoint/syscalls/sys_enter_execve" )
__s32 tracepoint__syscalls__sys_enter_execve( struct enter_execve_args* ctx ) {
	__u64 id;
	pid_t pid, tgid;
	uid_t uid;
	__u32 ret;
	struct event_t* event;
	// 内核结构task_struct，用于表示进程和线程
	struct task_struct* task;
	// 参数地址
	const char* argp = NULL;

	// 获取用户id
	uid = bpf_get_current_uid_gid();
	id  = bpf_get_current_pid_tgid();
	// 获取进程id
	pid = ( pid_t ) (id & 0xffffffff);
	// 获取线程组id
	tgid = id >> 32;

	// 输出在 /sys/kernel/debug/tracing/trace_pipe
	printk( "pid: %d, tgid: %d, uid: %d\n", pid, tgid, uid );

	if ( target_uid != INVALID_UID && target_uid != uid ) {
		// uid和target_uid不相等，直接返回
		printk( "target_uid:%d != uid:%d, so return", target_uid, uid );
		return 0;
	}

	// 在execve_hash加入成员，key为进程id，value为event_t结构体
	if ( bpf_map_update_elem( &execve_hash, &pid, &empty_event, BPF_NOEXIST ) ) {
		// bpf hash中key不存在，加入失败，直接返回
		return 0;
	}

	// 根据pid查找event数据
	event = bpf_map_lookup_elem( &execve_hash, &pid );
	if ( !event ) {
		return 0;
	}

	// tgid使用主线程的pid
	event->pid = tgid;
	event->uid = uid;

	// 获取当前task_struct
	task = ( struct task_struct* ) bpf_get_current_task();


	// 通过task获取父进程id, 这个需要BTF，如果内核不支持BTF，那么只有直接去读取，根据地址去读
	// event->ppid       = ( pid_t ) BPF_CORE_READ( task, real_parent, tgid );
	struct task_struct* real_parent_task;
	bpf_probe_read( &real_parent_task, sizeof( real_parent_task ), &task->real_parent );
	bpf_probe_read( &event->ppid, sizeof( event->ppid ), &real_parent_task->pid );

	event->args_count = 0;
	event->args_size  = 0;

	// 读取命令名，觉得这个和bpf_get_current_comm应该想用，args[0]
	// 命令行参数都是用户空间分配的，所以用***_user_str
	// https://stackoverflow.com/questions/67188440/ebpf-cannot-read-argv-and-envp-from-tracepoint-sys-enter-execve
	// 先读取第一个参数地址，在读取第一个参数内容
	bpf_probe_read( &argp, sizeof( argp ), &ctx->argv[ 0 ] );
	ret = bpf_probe_read_user_str( event->args, ARGSIZE, argp );

	// ret = bpf_probe_read_user_str( event->args, ARGSIZE, ( const char* ) ctx->argv[ 0 ] );
	if ( ret < ARGSIZE ) {
		event->args_size += ret;
	} else {
		// empty string
		event->args[ 0 ] = '\0';
		event->args_size++;
	}
	// 参数个数递增
	event->args_count++;

	// // 读取第二个参数
	// bpf_probe_read( &argp, sizeof( argp ), &ctx->argv[ 1 ] );
	// if ( !argp ) {
	// 	return 0;
	// }

	// // 这行代码非常重要，如果不加上，下面代码是没法判断空间是否足够读取ARGSIZE这多字节的。而且BPF Verifier会报错
	// if ( event->args_size > LAST_ARG )
	// 	return 0;

	// ret = bpf_probe_read_user_str( event->args + event->args_size, ARGSIZE, argp );
	// if ( ret > ARGSIZE ) {
	// 	return 0;
	// }

	// event->args_size += ret;
	// event->args_count++;

	// 告诉编译器，不做循环展开
	// #pragma unroll
	for ( __s32 i = 1; i < DEFAULT_MAXARGS && i < max_args; i++ ) {
		// 读取后续参数地址
		ret = bpf_probe_read( &argp, sizeof( argp ), &ctx->argv[ i ] );
		if ( !argp ) {
			// 地址为空，说明没有参数
			return 0;
		}

		// 这行代码非常重要，如果不加上，下面代码是没法判断空间是否足够读取ARGSIZE这多字节的。而且BPF Verifier会报错
		if ( event->args_size > LAST_ARG )
			return 0;

		// 读取参数内容
		ret = bpf_probe_read_user_str( &event->args[ event->args_size ], ARGSIZE, argp );
		if ( ret > ARGSIZE ) {
			printk( "argv[%d] size: %d larger than ARGSIZE", i, ret );
			return 0;
		}

		event->args_size += ret;
		event->args_count++;
	}

	return 0;
}

SEC( "tracepoint/syscalls/sys_exit_execve" )
int tracepoint__syscalls__sys_exit_execve( struct exit_execve_args* ctx ) {
	__u64 id;
	pid_t pid;
	__s32 ret;
	struct event_t* evt;

	__u32 uid = bpf_get_current_uid_gid();

	if ( target_uid != INVALID_UID && target_uid != uid ) {
		// uid和target_uid不相等，直接返回
		printk( "target_uid:%d != uid:%d, so return", target_uid, uid );
		return 0;
	}

	id  = bpf_get_current_pid_tgid();
	pid = ( pid_t ) id;
	// 在execve_hash中查找成员，key为进程id
	evt = bpf_map_lookup_elem( &execve_hash, &pid );
	if ( !evt ) {
		return 0;
	}

	// 得到exit_execve的返回值
	ret = ctx->ret;
	if ( ignore_failed && ret < 0 ) {
		// 从execve_hash中删除成员，key为进程id
		bpf_map_delete_elem( &execve_hash, &pid );
		return 0;
	}

	// 更新event中的返回值
	evt->retval = ret;
	// 得到应用程序名字
	bpf_get_current_comm( &evt->comm, sizeof( evt->comm ) );
	// 计算event数据的实际长度
	// size_t event_len = offsetof( struct event_t, args ) + event->args_size;
	// bpf_perf_event_output( ctx, &execve_perf_evt_map, BPF_F_CURRENT_CPU, event, sizeof( *event ) );

	// 下面这种计算长度，会校验报错，R5 unbounded memory access, use 'var &= const' or 'if (var < const)'
    // 原因是size_t对应的format格式不对，就算填写%zu也不对
    // size_t len = offsetof( struct event_t, args ) + evt->args_size;
	__u32 len = offsetof( struct event_t, args ) + evt->args_size;

    // bpf_trace_printk 只支持这些类型，必须对应上，否则verifier报错，%d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx, %p, %s
	printk( "execute:%s, event length: %u", evt->comm, len );

	// size_t len = EVENT_SIZE(evt);
	if ( len <= sizeof( *evt ) ) {
		bpf_perf_event_output( ctx, &execve_perf_evt_map, BPF_F_CURRENT_CPU, evt, len );
	}
	return 0;
}

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;