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

struct bpf_map_def __section( "maps" ) sock_ops_map = {
	.type        = BPF_MAP_TYPE_SOCKHASH,
	.key_size    = sizeof( struct sock_key ),
	.value_size  = sizeof( __s32 ),
	.max_entries = 65535,
	.map_flags   = 0,
};