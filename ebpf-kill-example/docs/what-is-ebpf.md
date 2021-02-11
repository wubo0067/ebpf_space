# What is eBPF?

## Introduction
eBPF or Extended Berkeley Packet Filter is a Linux system allowing developers
to run kernel-space programs from user-space [1]. Programs are compiled to eBPF
byte-code and are run in a VM within the kernel. BPF is a highly advanced VM,
running instructions in a fully isolated environment. It is comparable to the
Java Virtual Machine. eBPF can be used for performance tracing, but also as a
middleware for various different scenarios including security.

After the program is compiled, eBPF verifies that the program is safe to run.
This prevents the kernel from loading programs that that might compromise the
system by crashing the kernel.

eBPF does not require restart when loading modules, but can load and unload
on demand.

## References
[1] Calavera, D., Fontana, L., & Frazelle, J. (2020). Linux observability with
BPF: Advanced programming for performance analysis and networking. Sebastopol,
CA: O'Reilly Media.
