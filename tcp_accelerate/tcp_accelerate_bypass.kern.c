/*
 * @Author: CALM.WU 
 * @Date: 2021-09-22 17:06:55 
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-22 17:21:15
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>

//#include <bpf/bpf_core_read.h> 这个需要BTF支持
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

#include "tcp_accelerate.h"

static inline void sk_msg_extractv4_key( struct sk_msg_md* msg, struct sock_key* key ) {
	key->sip4   = msg->remote_ip4;
	key->dip4   = msg->local_ip4;
	key->family = 1;

	key->dport = ( bpf_htonl( msg->local_port ) >> 16 );
	key->sport = FORCE_READ( msg->remote_port ) >> 16;
}

/*
The SK_MSG program 在调用sendmsg时被执行
*/
__section( "sk_msg" ) __s32 bpf_tcpip_bypass( struct sk_msg_md* msg ) { 
    struct sock_key key = {};
    sk_msg_extractv4_key( msg, &key );
    bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    return SK_PASS; 
}

char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;

