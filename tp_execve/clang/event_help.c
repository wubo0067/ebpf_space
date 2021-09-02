/*
 * @Author: CALM.WU
 * @Date: 2021-09-01 14:32:52
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-01 15:01:12
 */

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "bpf_help.h"
#include "event.h"
#include "event_help.h"

struct timespec start_time;

static void time_since_start() {
	int64_t secs, nsecs;
	static struct timespec cur_time;
	double time_diff;

	clock_gettime( CLOCK_MONOTONIC, &cur_time );
	nsecs = cur_time.tv_nsec - start_time.tv_nsec;
	secs  = cur_time.tv_sec - start_time.tv_sec;
	if ( nsecs < 0 ) {
		nsecs += NSEC_PER_SEC;
		secs--;
	}

	time_diff = secs + ( nsecs / NSEC_PER_SEC );
	printf( "%-8.3f", time_diff );
}

static void inline quoted_symbol( char c ) {
	switch ( c ) {
		case '"':
			putchar( '\\' );
			putchar( '"' );
			break;
		case '\t':
			putchar( '\\' );
			putchar( 't' );
			break;
		case '\n':
			putchar( '\\' );
			putchar( 'n' );
			break;
		default:
			putchar( c );
			break;
	}
}

static void print_args( const struct event_t* e, bool quote ) {
	int32_t i, args_counter = 0;

	if ( quote )
		putchar( '"' );

	for ( i = 0; i < e->args_size && args_counter < e->args_count; i++ ) {
		char c = e->args[ i ];

		if ( quote ) {
			if ( c == '\0' ) {
				args_counter++;
				putchar( '"' );
				putchar( ' ' );
				if ( args_counter < e->args_count ) {
					putchar( '"' );
				}
			} else {
				quoted_symbol( c );
			}
		} else {
			if ( c == '\0' ) {
				args_counter++;
				putchar( ' ' );
			} else {
				putchar( c );
			}
		}
	}
	if ( e->args_count == g_env.max_args + 1 ) {
		fputs( " ...", stdout );
	}
}

void handle_event( void* ctx, int32_t cpu, void* data, uint32_t size ) {
	const struct event_t* e = ( const struct event_t* ) data;
	time_t t;
	struct tm* tm;
	char ts[ 32 ];

	time( &t );
	tm = localtime( &t );
	strftime( ts, sizeof( ts ), "%H:%M:%S", tm );

	printf( "%-8s ", ts );
	time_since_start();
	printf( "%-6d", e->uid );
	printf( "%-16s %-6d %-6d %3d ", e->comm, e->pid, e->ppid, e->retval );
	print_args( e, true );
	putchar( '\n' );
}

void handle_lost_event( void* ctx, int32_t cpu, uint64_t lost_cnt ) {
	fprintf( stderr, "Lost %lu events on CPU #%d!\n", lost_cnt, cpu );
}