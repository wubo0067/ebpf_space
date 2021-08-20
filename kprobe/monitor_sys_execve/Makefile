ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

# 在定义时扩展。
TARGET := monitor-execve

LLC ?= llc
CLANG ?= clang
OPT ?= opt
LLVM_DIS ?= llvm-dis
KERNEL_SRC = /usr/src/linux-5.12.9

include $(KERNEL_SRC)/scripts/subarch.include

ARCH		?= $(SUBARCH)
SRCARCH 	:= $(ARCH)
ifeq ($(ARCH),i386)
        SRCARCH := x86
endif
ifeq ($(ARCH),x86_64)
        SRCARCH := x86
endif

TRACE_HELPERS := $(KERNEL_SRC)/tools/testing/selftests/bpf/trace_helpers.o
KPROGS_CFLAGS += -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ -D__x86_64__ -D__TARGET_ARCH_$(SRCARCH)
KPROGS_CFLAGS += -Wunused -Wall \
				 -Wno-compare-distinct-pointer-types \
				 -Wno-pointer-sign \
				 -Wno-gnu-variable-sized-type-not-at-end \
				 -Wno-address-of-packed-member \
				 -Wno-tautological-compare \
				 -Wno-unknown-warning-option 

USERINCLUDE    := \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/uapi \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/generated/uapi \
		-I$(KERNEL_SRC)/include/uapi \
		-I$(KERNEL_SRC)/include/generated/uapi


LINUXINCLUDE    := \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/generated \
		$(USERINCLUDE)				

KPROGS_CFLAGS += $(LINUXINCLUDE)
KPROGS_CFLAGS += -I$(KERNEL_SRC)/include
KPROGS_CFLAGS += -I$(KERNEL_SRC)/samples/bpf
#KPROGS_CFLAGS += -I$(KERNEL_SRC)/usr/include
KPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/testing/selftests/bpf/
KPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/lib
#KPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/include


execve_kern.o : execve_kern.c  
	$(Q)$(CLANG) -nostdinc -isystem $(KPROGS_CFLAGS) -O2 -emit-llvm -Xclang -disable-llvm-passes -c $<  -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

