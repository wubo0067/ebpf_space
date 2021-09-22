/*
 * @Author: CALM.WU 
 * @Date: 2021-09-22 10:39:52 
 * @Last Modified by: CALM.WU
 * @Last Modified time: 2021-09-22 11:17:03
 */

#include <linux/ptrace.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>

//#include <bpf/bpf_core_read.h> 这个需要BTF支持
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <trace_common.h>

struct sock_key {
	__u32 sip4;
	__u32 dip4;
	__u8  family;
	__u8  pad1;
	__u16 pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects loading
	// of the program
	__u32 pad3;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_map_def __section("maps") sock_ops_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(__s32),
    .max_entries = 65535,
    .map_flags = 0,
};

/*
eBPF program type SOCK_OPS which gets invoked upon TCP events such as connection establishment, tcp retransmit, etc
*/
__section("sockops")
__s32 bpf_sockops_v4(struct bpf_sock_ops *skops) {
    return 0;
}

/*
The SK_MSG program 在调用sendmsg时被执行
*/
__section("sk_msg")
__s32 bpf_tcpip_bypass(struct sk_msg_md *msg) {
    return 0;
}


char _license[] SEC( "license" ) = "GPL";
__u32 _version SEC( "version" )  = LINUX_VERSION_CODE;