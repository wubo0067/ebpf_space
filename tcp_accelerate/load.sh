#!/bin/bash

mount -t bpf bpf /sys/fs/bpf/

bpftool prog load /data/calm/program/ebpf-space/tcp_accelerate/tcp_accelerate_sockops.kern.o "/sys/fs/bpf/bpf_sockops"

# 使用cgroup，这里我不了解原因，说是有这个hook点
bpftool cgroup attach "/sys/fs/cgroup/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"