/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 10:49:37
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-27 13:55:45
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

#include "event.h"

SEC( "tracepoint/syscalls/sys_enter_execve" )
__s32 tracepoint__syscalls__sys_enter_execve( struct trace_event_raw_sys_enter* ctx ) { return 0; }

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;