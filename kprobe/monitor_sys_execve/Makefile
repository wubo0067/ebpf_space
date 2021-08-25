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

.PHONY: all clean

all : execve_kern.o execve

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

LIBBPF = $(KERNEL_SRC)/tools/lib/bpf/libbpf.a -lelf -lz

TRACE_HELPERS := $(KERNEL_SRC)/tools/testing/selftests/bpf/trace_helpers.o

KPROGS_CFLAGS = -nostdinc -isystem /usr/lib/gcc/x86_64-redhat-linux/8/include

KPROGS_CFLAGS += -D__KERNEL__ -D__BPF_TRACING__ -D__TARGET_ARCH_$(SRCARCH)
KPROGS_CFLAGS += -Wunused -Wall \
				 -Wno-compare-distinct-pointer-types \
				 -Wno-pointer-sign \
				 -Wno-gnu-variable-sized-type-not-at-end \
				 -Wno-address-of-packed-member \
				 -Wno-tautological-compare \
				 -Wno-unknown-warning-option \
				 -fno-stack-protector -g


LINUXINCLUDE    := \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/generated \
		-I$(KERNEL_SRC)/include \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/uapi \
		-I$(KERNEL_SRC)/arch/$(SRCARCH)/include/generated/uapi \
		-I$(KERNEL_SRC)/include/uapi \
		-I$(KERNEL_SRC)/include/generated/uapi \
		#-include $(KERNEL_SRC)/include/linux/compiler-version.h \
		-include $(KERNEL_SRC)/include/linux/kconfig.h

KPROGS_CFLAGS += $(LINUXINCLUDE)
KPROGS_CFLAGS += -I$(KERNEL_SRC)/samples/bpf
KPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/testing/selftests/bpf/
KPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/lib

UPROGS_CFLAGS = -Wunused -Wall -Wno-unused-variable -Wmissing-prototypes -Wstrict-prototypes
UPROGS_CFLAGS += -I$(KERNEL_SRC)/usr/include
#UPROGS_CFLAGS += -I$(KERNEL_SRC)/include
UPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/lib -I$(KERNEL_SRC)/tools/include -I$(KERNEL_SRC)/tools/perf
UPROGS_CFLAGS += -I$(KERNEL_SRC)/tools/testing/selftests/bpf

execve_kern.o : execve_kern.c  
	$(Q)$(CLANG) $(KPROGS_CFLAGS) -O2 -emit-llvm -Xclang -disable-llvm-passes -c $<  -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@


execve : execve_user.o
	gcc -o $@ execve_user.o $(TRACE_HELPERS) $(LIBBPF)

execve_user.o : execve_user.c
	gcc $(UPROGS_CFLAGS) -c $< -o $@

clean:
	rm *.o execve

