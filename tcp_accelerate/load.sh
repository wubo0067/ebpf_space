#!/bin/bash
set -x

mount -t bpf bpf /sys/fs/bpf/

bpftool prog load /home/calmwu/program/ebpf_space/tcp_accelerate/tcp_accelerate_sockops.kern.o "/sys/fs/bpf/bpf_sockops"

# This attaches the loaded SOCK_OPS program to the cgroup
# This is attached to cgroup so that the program applies to all sockets of all tasks placed in the cgroup
bpftool cgroup attach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"

MAP_ID=$(bpftool prog show pinned "/sys/fs/bpf/bpf_sockops" | grep -o -E 'map_ids [0-9]+'|cut -d' ' -f2)
sudo bpftool map pin id $MAP_ID "/sys/fs/bpf/sock_ops_map"

# 将程序加载到内核
# 将程序 pin 到 BPF 文件系统的 /sys/fs/bpf/bpf_tcpip_bypass 位置
# 重用已有的 sockmap，指定了 sockmap 的名字为 sock_ops_map 并且文件路径为 /sys/fs/bpf/sock_ops_map
bpftool prog load /home/calmwu/program/ebpf_space/tcp_accelerate/tcp_accelerate_bypass.kern.o "/sys/fs/bpf/bpf_tcpip_bypass" map name sock_ops_map pinned "/sys/fs/bpf/sock_ops_map"

bpftool prog attach pinned "/sys/fs/bpf/bpf_tcpip_bypass" msg_verdict pinned "/sys/fs/bpf/sock_ops_map"

