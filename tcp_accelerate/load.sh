#!/bin/bash

mount -t bpf bpf /sys/fs/bpf/

bpftool prog load tcp_accelerate_sockops.kern.o "/sys/fs/bpf/bpf_sockops"