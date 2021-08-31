/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 11:57:38
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-08-31 12:04:27
 */

#include <stdio.h>
#include <stdlib.h>

#include <trace_helpers.h>

#include "event.h"
#include "bpf_help.h"
#include "tp_execve.skel.h"

static struct env {
	bool time;
	bool timestamp;
	bool fails;
	uid_t uid;
	bool quote;
	const char* name;
	const char* line;
	bool print_uid;
	bool verbose;
	int max_args;
} env = { .max_args = DEFAULT_MAXARGS, .uid = INVALID_UID };

int32_t libbpf_printf( enum libbpf_print_level level, const char* fmt, va_list args ) {
	if ( level == LIBBPF_DEBUG && !env.verbose ) {
		return 0;
	}
	return vfprintf( stderr, fmt, args );
}

int32_t main( int32_t argc, char** argv ) {
    int32_t err = 0;
    struct tp_execve_kern * bpf_obj = NULL;

	fprintf( stderr, "main: %s\n", argv[ 0 ] );

	libbpf_set_print( libbpf_printf );

    err = bump_memlock_rlimit();
    if ( err ) {
        fprintf( stderr, "failed to increase rlimit: %d\n", err );
        return 1;
    } 

    bpf_obj = tp_execve_kern__open();
    if ( !bpf_obj ) {
        fprintf( stderr, "failed to open BPF execve_kern object\n" );
        return 1;
    }

    /* initialize global data (filtering options)，传递参数控制bpf kern程序的过滤行为 */

cleanup:
    tp_execve_kern__destroy( bpf_obj );

	return err != 0;
}