#!/bin/bash
set -x

bpftool prog detach pinned /sys/fs/bpf/bpf_tcpip_bypass msg_verdict pinned /sys/fs/bpf/sock_ops_map

rm /sys/fs/bpf/bpf_tcpip_bypass

bpftool cgroup detach /sys/fs/cgroup/ sock_ops pinned /sys/fs/bpf/bpf_sockops

rm /sys/fs/bpf/bpf_sockops

rm /sys/fs/bpf/sock_ops_map