/*
 * @Author: CALM.WU
 * @Date: 2021-09-22 10:39:52
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-22 17:13:59
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>

//#include <bpf/bpf_core_read.h> 这个需要BTF支持
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

#include "tcp_accelerate.h"

static inline void sk_extractv4_key( struct bpf_sock_ops* skops, struct sock_key* key ) {
	key->dip4   = skops->remote_ip4;
	key->sip4   = skops->local_ip4;
	key->family = 2;

	key->sport = ( bpf_htonl( skops->local_port ) >> 16 );
	key->dport = FORCE_READ( skops->remote_port ) >> 16;
}

static inline void bpf_sock_ops_ipv4( struct bpf_sock_ops* skops ) {
	struct sock_key key = {};

	sk_extractv4_key( skops, &key );

	__s32 ret = bpf_sock_hash_update( skops, &sock_ops_map, &key, BPF_NOEXIST );
	if ( ret != 0 ) {
		printk( "FAILED: sock_hash_update ret: %d\n", ret );
	} else {
		printk( "remote-ip = %d, local-ip = %d\n", bpf_htonl( skops->remote_ip4 ), bpf_htonl( skops->local_ip4 ) );

		printk( "<<< ipv4 op = %d, local-port %d --> remote-port %d\n", skops->op, skops->local_port,
		    bpf_ntohl( skops->remote_port ) );
	}
}

/*
eBPF program type SOCK_OPS which gets invoked upon TCP events such as connection establishment, tcp retransmit, etc
*/
__section( "sockops" ) __s32 bpf_sockops_v4( struct bpf_sock_ops* skops ) {
	__u32 family, op;

	family = skops->family;
	op     = skops->op;

	switch ( op ) {
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		// 被动建立连接
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			// 主动建立连接
			if ( family == AF_INET ) {
				bpf_sock_ops_ipv4( skops );
			}
			break;
		default:
			break;
	}
	return 0;
}

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;