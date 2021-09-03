### EBPF开发总结

1. 如果在代码中有`#include <bpf/bpf_core_read.h>`，使用了`BPF_CORE_READ`宏，在user程序中`bpf_object__load`就会报如下错误。

    ```
    libbpf: failed to find valid kernel BTF
    libbpf: Error loading vmlinux BTF: -3
    libbpf: failed to load object 'tp_execve_kern'
    libbpf: failed to load BPF skeleton 'tp_execve_kern': -3
    failed to load BPF object: -3
    ```

    

2. BPF Verifier输出unbounded memory access，需要判断args空间是否足够读取ARGSIZE，没有这个判断就校验就会报错。

    ```
    // 这行代码非常重要，如果不加上，下面代码是没法判断空间是否足够读取ARGSIZE这多字节的。而且BPF Verifier会报错
    if ( event->args_size > LAST_ARG )
    	return 0;
    
    // 读取参数内容
    ret = bpf_probe_read_user_str( &event->args[ event->args_size ], ARGSIZE, argp );
    if ( ret > ARGSIZE ) {
    	printk( "argv[%d] size: %d larger than ARGSIZE", i, ret );
    	return 0;
    }
    ```



3. printk( "execute:%s, event length: %u", evt->comm, len );，如果len是size_t类型，没有匹配的format，应为format只支持%d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx, %p, %s，所以会报内存越界。

    

4. user程序如何初始化kern程序中的变量达到控制效果，要使用libbpf中`bpf_object__load_skeleton`这个方法做mmap达到改变变量值的效果。

    LIBBPF_MAP_RODATA

    

5. dump出对应的源码和bpf指令，在verifier报错后可检查指令。

    ```
    llvm-objdump -S --no-show-raw-insn tp_execve.kern.o
    ```

    

6. bfptool工具生成xxx.skel.h文件，解除对xxx.kern.o的依赖。程序中不用`bpf_object__load`。bpftool gen skeleton %.kern.o > %.skel.h。

    ```
    $(patsubst %,%.skel.h,$(APP_TAG)): $(patsubst %,%.kern.o,$(APP_TAG))
    ​	$(call msg,GEN-SKEL,$@)
    ​	$(Q)$(BPFTOOL) gen skeleton $< > $@
    ```



7. 创建struct bpf_object*对象。加载obj文件用`bpf_object__open_file`，在skel.h中创建obj使用`bpf_object__open_mem`