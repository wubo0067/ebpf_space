/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 11:58:48
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-27 13:57:09
 */

#ifndef __TP_EXECVE_EVENT_H__
#define __TP_EXECVE_EVENT_H__

#include <linux/types.h>

#define TASK_COMM_LEN 16
#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR ( TOTAL_MAX_ARGS * ARGSIZE )
#ifdef INVALID_UID
#	undef INVALID_UID
#	define INVALID_UID ( ( uid_t ) -1 )
#endif

struct event_t {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	__s32 retval;
	__s32 args_count;
	__u32 args_size;
	char comm[ TASK_COMM_LEN ];
	char args[ FULL_MAX_ARGS_ARR ]; // 所有的args都是写入一个数组中
};

#endif // __TP_EXECVE_EVENT_H__