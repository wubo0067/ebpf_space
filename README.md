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



3. size_t的打印。bpf_trace_printk只支持%d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx, %p, %s，size_t类型变量一般用%zu，这里没有，所以使用bpf_trace_printk打印size_t变量，fmt中没有对应，Verifier会报错。建议改为其它整数类型。

   

4. user程序如何初始化kern程序中的变量达到控制效果。