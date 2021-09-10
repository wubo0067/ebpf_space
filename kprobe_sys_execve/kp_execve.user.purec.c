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
	fprintf( stderr, "pid:%d, tid:%d uid:%d, ret:%d cpu:%d executing program:%s filename:[%s]\n", 
        d->pid, d->tid, d->uid, d->ret, cpu, d->comm, d->filename );
}

int main( int argc, char** argv ) {

	struct perf_buffer_opts pb_opts = {};
	struct bpf_link *links[2] = {};
	struct bpf_program *prog;
	struct perf_buffer *pb;
	struct bpf_object *obj;
	int map_fd, ret = 0, j = 0;

	const char* kern_obj = "kp_execve.kern.o";

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

	// find perf event map
	map_fd = bpf_object__find_map_fd_by_name( obj, "execve_perf_evt_map" );
	if ( map_fd < 0 ) {
		fprintf( stderr, "ERROR: finding a map in obj file failed\n" );
		goto cleanup;
	}   

	bpf_object__for_each_program( prog, obj ) {
        //prog->log_level = 1;
		links[ j ] = bpf_program__attach( prog );
		if ( libbpf_get_error( links[ j ] ) ) {
			fprintf( stderr, "%d: bpf_program__attach failed\n", j );
			links[ j ] = NULL;
			goto cleanup;
		}
		fprintf( stderr, "%d bpf program attach successed\n", j );
		j++;
	}         

	// prog = bpf_object__find_program_by_name( obj, "kprobe_sys_execve" );
	// if ( !prog ) {
	// 	fprintf( stderr, "ERROR: finding a prog in obj file failed\n" );
	// 	goto cleanup;
	// }

	// link = bpf_program__attach( prog );
	// if ( libbpf_get_error( link ) ) {
	// 	fprintf( stderr, "ERROR: bpf_program__attach failed\n" );
	// 	link = NULL;
	// 	goto cleanup;
	// }

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
	for ( j--; j >= 0; j-- )
		bpf_link__destroy( links[ j ] );

	bpf_object__close( obj );
	return 0;
}