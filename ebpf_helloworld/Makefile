TARGET := ebpf-helloworld

CCINCLUDE += -I/home/calm/Downloads/kernels/linux-5.10.14/tools/testing/selftests/bpf

LOADINCLUDE += -I/home/calm/Downloads/kernels/linux-5.10.14/samples/bpf
LOADINCLUDE += -I/home/calm/Downloads/kernels/linux-5.10.14/tools/lib
LOADINCLUDE += -I/home/calm/Downloads/kernels/linux-5.10.14/tools/perf
LOADINCLUDE += -I/home/calm/Downloads/kernels/linux-5.10.14/tools/include

LIBS = -lbpf -lelf

all: ebpf-helloworld kern_helloworld.o

.PHONY: clean

clean:
	rm -f $(TARGET)
	rm -f *.o

$(TARGET): %: load_helloworld.c
	#gcc $(CFLAGS) $(LDFLAGS) -o $(TARGET) user.c -Wl,-rpath=$(LIBBPF_DIR) $(LIBS)
	#gcc -Wall -Werror -g3 -ggdb3 -o ebpf-kill-example user.c -Wl,-Bstatic -lbpf -Wl,-Bdynamic -lgcc_s -lz -lelf
	clang -Wall -Werror,-Wunused-variable -g3 -ggdb3  -o $(TARGET) \
	/home/calm/Downloads/kernels/linux-5.10.14/samples/bpf/bpf_load.c \
	/home/calm/Downloads/kernels/linux-5.10.14/tools/testing/selftests/bpf/trace_helpers.c \
	load_helloworld.c \
	$(CCINCLUDE) $(LOADINCLUDE) -L/usr/local/lib64 -Wl,-rpath=/usr/local/lib64 $(LIBS)


kern_helloworld.o: kern_helloworld.c
	clang -O2 -target bpf -c kern_helloworld.c $(CCINCLUDE) -o kern_helloworld.o