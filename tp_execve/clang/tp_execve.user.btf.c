/*
 * @Author: CALM.WU
 * @Date: 2021-08-27 11:57:38
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 17:19:16
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "bpf_help.h"
#include "event_help.h"
#include "event.h"
#include "tp_execve.skel.h"

#define PERF_BUFFER_PAGES 64

// struct env_t g_env = {
// 	.max_args = DEFAULT_MAXARGS, .uid = INVALID_UID, .quote = true, .time = true, .print_uid = true, .timestamp = true
// };

// static struct timespec start_time;

// static void time_since_start() {
// 	int64_t secs, nsecs;
// 	static struct timespec cur_time;
// 	double time_diff;

// 	clock_gettime( CLOCK_MONOTONIC, &cur_time );
// 	nsecs = cur_time.tv_nsec - start_time.tv_nsec;
// 	secs  = cur_time.tv_sec - start_time.tv_sec;
// 	if ( nsecs < 0 ) {
// 		nsecs += NSEC_PER_SEC;
// 		secs--;
// 	}

// 	time_diff = secs + ( nsecs / NSEC_PER_SEC );
// 	printf( "%-8.3f", time_diff );
// }

// static void inline quoted_symbol( char c ) {
// 	switch ( c ) {
// 		case '"':
// 			putchar( '\\' );
// 			putchar( '"' );
// 			break;
// 		case '\t':
// 			putchar( '\\' );
// 			putchar( 't' );
// 			break;
// 		case '\n':
// 			putchar( '\\' );
// 			putchar( 'n' );
// 			break;
// 		default:
// 			putchar( c );
// 			break;
// 	}
// }

// static void print_args( const struct event_t* e, bool quote ) {
// 	int32_t i, args_counter = 0;

// 	if ( g_env.quote )
// 		putchar( '"' );

// 	for ( i = 0; i < e->args_size && args_counter < e->args_count; i++ ) {
// 		char c = e->args[ i ];

// 		if ( g_env.quote ) {
// 			if ( c == '\0' ) {
// 				args_counter++;
// 				putchar( '"' );
// 				putchar( ' ' );
// 				if ( args_counter < e->args_count ) {
// 					putchar( '"' );
// 				}
// 			} else {
// 				quoted_symbol( c );
// 			}
// 		} else {
// 			if ( c == '\0' ) {
// 				args_counter++;
// 				putchar( ' ' );
// 			} else {
// 				putchar( c );
// 			}
// 		}
// 	}
// 	if ( e->args_count == g_env.max_args + 1 ) {
// 		fputs( " ...", stdout );
// 	}
// }

// perf event call back function
// static void handle_event( void* ctx, int32_t cpu, void* data, uint32_t size ) {
// 	const struct event_t* e = ( const struct event_t* ) data;
// 	time_t t;
// 	struct tm* tm;
// 	char ts[ 32 ];

// 	time( &t );
// 	tm = localtime( &t );
// 	strftime( ts, sizeof( ts ), "%H:%M:%S", tm );

// 	printf( "%-8s ", ts );
// 	time_since_start();
// 	printf( "%-6d", e->uid );
// 	printf( "%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval );
// 	print_args( e, g_env.quote );
// 	putchar( '\n' );
// }

// static void handle_lost_event( void* ctx, int32_t cpu, uint64_t lost_cnt ) {
// 	fprintf( stderr, "Lost %lu events on CPU #%d!\n", lost_cnt, cpu );
// }

int32_t main( int32_t argc, char** argv ) {
	int32_t err                     = 0;
	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer* pb          = NULL;
	struct tp_execve_kern* bpf_obj  = NULL;

	g_env.max_args = DEFAULT_MAXARGS;
	g_env.uid      = INVALID_UID;

	fprintf( stderr, "main: %s\n", argv[ 0 ] );

	libbpf_set_print( bpf_printf );

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
    // 在load之前修改只读代码段的变量
	bpf_obj->rodata->ignore_failed = !g_env.fails;
	bpf_obj->rodata->target_uid    = g_env.uid;
	// 最大的参数个数
	bpf_obj->rodata->max_args = g_env.max_args;

	// 加载bpf kern程序
	err = tp_execve_kern__load( bpf_obj );
	if ( err ) {
		fprintf( stderr, "failed to load BPF object: %d\n", err );
		goto cleanup;
	}

	clock_gettime( CLOCK_MONOTONIC, &start_time );
	err = tp_execve_kern__attach( bpf_obj );
	if ( err ) {
		fprintf( stderr, "failed to attach BPF object: %d\n", err );
		goto cleanup;
	}

	printf( "%-9s", "TIME" );
	printf( "%-8s ", "TIME(s)" );
	printf( "%-6s ", "UID" );
	printf( "%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS" );

	// setup event callback
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb   = handle_lost_event;
	pb  = perf_buffer__new( bpf_map__fd( bpf_obj->maps.execve_perf_evt_map ), PERF_BUFFER_PAGES, &pb_opts );
	err = libbpf_get_error( pb );
	if ( err ) {
		pb = NULL;
		fprintf( stderr, "failed to open perf buffer: %d\n", err );
		goto cleanup;
	}

	// loop perf event
	while ( ( err = perf_buffer__poll( pb, 100 ) ) >= 0 ) {
	}
	printf( "Error polling perf buffer: %d\n", err );

cleanup:
	tp_execve_kern__destroy( bpf_obj );

	return err != 0;
}