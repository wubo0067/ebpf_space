/*
 * @Author: CALM.WU
 * @Date: 2021-09-22 17:07:38
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-22 17:08:48
 */

#include <bpf/bpf_endian.h>
#include <linux/socket.h>

#ifndef FORCE_READ
#	define FORCE_READ( X ) ( *( volatile typeof( X )* ) &X )
#endif

#define printk( fmt, ... )                                                                                             \
	( {                                                                                                                \
		char ____fmt[] = fmt;                                                                                          \
		bpf_trace_printk( ____fmt, sizeof( ____fmt ), ##__VA_ARGS__ );                                                 \
	} )

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8 family;
	__u8 pad1;
	__u16 pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects loading
	// of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__( ( packed ) );

struct {
	__uint( type, BPF_MAP_TYPE_SOCKHASH );
	__uint( max_entries, 128 );
	__type( key, struct sock_key );
	__type( value, __s32 );
} sock_ops_map SEC( ".maps" );