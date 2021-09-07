/*
 * @Author: CALM.WU
 * @Date: 2021-08-31 11:48:54
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 12:12:10
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "bpf_help.h"

struct env_t g_env = { .quote = true, .time = true, .print_uid = true, .timestamp = true, .verbose = true };

int bump_memlock_rlimit( void ) {
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit( RLIMIT_MEMLOCK, &rlim_new );
}

int bpf_printf( enum libbpf_print_level level, const char* fmt, va_list args ) {
	// if ( level == LIBBPF_DEBUG && !g_env.verbose ) {
	// 	return 0;
	// }
    char out_fmt[128] = {0};
    sprintf(out_fmt, "level:{%d} %s", level, fmt);
    // vfprintf适合参数可变列表传递
	return vfprintf( stderr, out_fmt, args );
}