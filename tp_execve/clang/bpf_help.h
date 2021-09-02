/*
 * @Author: CALM.WU
 * @Date: 2021-08-31 11:47:46
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 11:55:31
 */

#ifndef __BPF_HELP_H__
#define __BPF_HELP_H__

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <trace_helpers.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NSEC_PER_SEC
#	undef NSEC_PER_SEC
#endif
#define NSEC_PER_SEC 1000000000ULL

struct env_t {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char* name;
	const char* line;
	bool print_uid;
	bool verbose;
	int32_t max_args;
};

extern struct env_t g_env;

int bump_memlock_rlimit( void );

int bpf_printf( enum libbpf_print_level level, const char* fmt, va_list args );

#ifdef __cplusplus
}
#endif

#endif // __BPF_HELP_H__