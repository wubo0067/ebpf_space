/*
 * @Author: CALM.WU
 * @Date: 2021-09-01 10:32:41
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 17:21:31
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <linux/bpf.h>
// #include <linux/ptrace.h>
// #include <trace_helpers.h>

#include "bpf_help.h"
#include "event.h"
#include "event_help.h"

#define PERF_BUFFER_PAGES 64

int32_t main( int32_t argc, char** argv ) {
	int32_t err = 0;
	int32_t map_fd, ret, j = 0;

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer* pb          = NULL;

	struct bpf_object* obj;
	struct bpf_program* prog;
	struct bpf_link* links[ 2 ];

	const char* kern_obj = "tp_execve.kern.o";

	fprintf( stderr, "main: %s\n", argv[ 0 ] );

	libbpf_set_print( bpf_printf );

	err = bump_memlock_rlimit();
	if ( err ) {
		fprintf( stderr, "failed to increase rlimit: %d\n", err );
		return 1;
	}

	obj = bpf_object__open_file( kern_obj, NULL );
	if ( libbpf_get_error( obj ) ) {
		fprintf( stderr, "ERROR: opening BPF object file failed\n" );
		return 0;
	}

	/* load BPF program */
	if ( bpf_object__load( obj ) ) {
		fprintf( stderr, "ERROR: loading BPF object file failed\n" );
		goto cleanup;
	}

	// find map
	map_fd = bpf_object__find_map_fd_by_name( obj, "execve_perf_evt_map" );
	if ( map_fd < 0 ) {
		fprintf( stderr, "ERROR: finding a map in obj file failed\n" );
		goto cleanup;
	}

	bpf_object__for_each_program( prog, obj ) {
		prog->log_level = 1;
		links[ j ]      = bpf_program__attach( prog );
		if ( libbpf_get_error( links[ j ] ) ) {
			fprintf( stderr, "%d: bpf_program__attach failed\n", j );
			links[ j ] = NULL;
			goto cleanup;
		}
		fprintf( stderr, "%d bpf program attach successed\n", j );
		j++;
	}

	printf( "%-9s", "TIME" );
	printf( "%-8s ", "TIME(s)" );
	printf( "%-6s ", "UID" );
	printf( "%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS" );
	// setup perf event callback
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb   = handle_lost_event;
	pb                = perf_buffer__new( map_fd, PERF_BUFFER_PAGES, &pb_opts );
	err               = libbpf_get_error( pb );
	if ( err ) {
		pb = NULL;
		fprintf( stderr, "failed to open perf buffer: %d\n", err );
		goto cleanup;
	}

	// loop perf event
	while ( ( err = perf_buffer__poll( pb, 100 ) ) >= 0 ) { }
	printf( "Error polling perf buffer: %d\n", err );

cleanup:
	for ( j--; j >= 0; j-- )
		bpf_link__destroy( links[ j ] );

	bpf_object__close( obj );

	return 0;
}