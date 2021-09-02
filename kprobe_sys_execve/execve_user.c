/*
 * @Author: CALM.WU
 * @Date: 2021-08-23 15:19:48
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 14:22:49
 */

#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <trace_helpers.h>

#define TASK_COMM_LEN 16

#include "execve_data.h"

static void print_bpf_output( void* ctx, int cpu, void* data, __u32 size ) {
	struct data_t* d = data;
	fprintf( stderr, "pid:%d, uid:%d, cpu:%d executing program:%s filename:[%s]\n", 
        d->pid, d->uid, cpu, d->comm, d->filename );
}

int main( int argc, char** argv ) {

	struct perf_buffer_opts pb_opts = {};
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct perf_buffer *pb;
	struct bpf_object *obj;
	int map_fd, ret = 0;
	char filename[256];

	snprintf( filename, sizeof( filename ), "%s_kern.o", argv[ 0 ] );
	obj = bpf_object__open_file( filename, NULL );
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
	map_fd = bpf_object__find_map_fd_by_name( obj, "execve_map" );
	if ( map_fd < 0 ) {
		fprintf( stderr, "ERROR: finding a map in obj file failed\n" );
		goto cleanup;
	}        

	prog = bpf_object__find_program_by_name( obj, "kprobe_sys_execve" );
	if ( !prog ) {
		fprintf( stderr, "ERROR: finding a prog in obj file failed\n" );
		goto cleanup;
	}

	link = bpf_program__attach( prog );
	if ( libbpf_get_error( link ) ) {
		fprintf( stderr, "ERROR: bpf_program__attach failed\n" );
		link = NULL;
		goto cleanup;
	}

	pb_opts.sample_cb = print_bpf_output;
	pb                = perf_buffer__new( map_fd, 8, &pb_opts );
	ret               = libbpf_get_error( pb );
	if ( ret ) {
		printf( "failed to setup perf_buffer: %d\n", ret );
		return 1;
	}

	// read_trace_pipe();
	while ( ( ret = perf_buffer__poll( pb, 100 ) ) >= 0 ) {
	}

cleanup:
	bpf_link__destroy( link );
	bpf_object__close( obj );
	return 0;
}