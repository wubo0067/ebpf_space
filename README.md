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

    

4. user程序如何初始化kern程序中的变量达到控制效果。patch有个说明 [[v3,bpf-next,1/3\] bpf: add mmap() support for BPF_MAP_TYPE_ARRAY - Patchwork (ozlabs.org)](https://patchwork.ozlabs.org/project/netdev/patch/20191113031518.155618-2-andriin@fb.com/) 。

    要使用libbpf中`bpf_object__load_skeleton`这个方法做mmap达到改变变量值的效果。

    变量放在名字是rodata，类型是BPF_MAP_TYPE_ARRAY的map中。x

    这是用户态程序调用的参数：

    ```
    bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_ARRAY, key_size=4, value_size=9, max_entries=1, map_flags=BPF_F_RDONLY_PROG|BPF_F_MMAPABLE, inner_map_fd=0, map_name="tp_execv.rodata", map_ifindex=0, btf_fd=3, btf_key_type_id=0, btf_value_type_id=65, btf_vmlinux_value_type_id=0}, 120) = 6
    ```

    内核代码：SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)，kernel_src\kernel\bpf\syscall.c

    首先会找到BPF_MAP_TYPE_ARRAY对应的操作op对象，`BPF_MAP_TYPE(BPF_MAP_TYPE_ARRAY, array_map_ops)`，然后构造map对象，`static struct bpf_map *array_map_alloc(union bpf_attr *attr)`。

    ```
    /* allocate all map elements and zero-initialize them */
    if (attr->map_flags & BPF_F_MMAPABLE) {
    	void *data;
    
    	/* kmalloc'ed memory can't be mmap'ed, use explicit vmalloc */
    	data = bpf_map_area_mmapable_alloc(array_size, numa_node);
    	if (!data)
    		return ERR_PTR(-ENOMEM);
    	array = data + PAGE_ALIGN(sizeof(struct bpf_array))
    		- offsetof(struct bpf_array, value);
    } 
    ```
    这里面很核心的flag是BPF_F_MMAPABLE，它会在最终的空间分配中带上flags = VM_USERMAP这个标志位。

    在函数`static void *__bpf_map_area_alloc(u64 size, int numa_node, bool mmapable)`的代码中

    ```
    /* kmalloc()'ed memory can't be mmap()'ed */
    if (mmapable) {
    	BUG_ON(!PAGE_ALIGNED(size));
    	align = SHMLBA;
    	flags = VM_USERMAP;
    ```
    那么这个map的地址空间分配为何要使用**VM_USERMAP**这个标志呢？看到这标志就对应上这个函数`void *vmalloc_user(unsigned long size)`，看这个函数说明， 它分配一块非连续地址空间，分配的物理地址一般是不连续的，但是虚拟地址是连续的，并且将该地址空间清零，***这样该地址空间就可以被<u>映射到用户空间</u>而不会发生数据泄漏***。** 看来最核心是这个map的地址实际是在用户空间的，所以用户态程序可以进行修改。

    

5. MAP背后的fd。

    每个map会创建一个匿名的inode，这个inode没有绑定到磁盘上某个文件，而仅仅在内存里，一旦fd关闭后，对应的内存空间就会被释放。

    ```
    int bpf_map_new_fd(struct bpf_map *map, int flags)
    {
    	int ret;
    	ret = security_bpf_map(map, OPEN_FMODE(flags));
    	if (ret < 0)
    		return ret;
    	return anon_inode_getfd("bpf-map", &bpf_map_fops, map,
    				flags | O_CLOEXEC);
    }
    ```

    

6. dump出对应的源码和bpf指令，在verifier报错后可检查指令。

    ```
    llvm-objdump -S --no-show-raw-insn tp_execve.kern.o
    ```

    

7. bfptool工具生成xxx.skel.h文件，解除对xxx.kern.o的依赖。程序中不用`bpf_object__load`。bpftool gen skeleton %.kern.o > %.skel.h。

    ```
    $(patsubst %,%.skel.h,$(APP_TAG)): $(patsubst %,%.kern.o,$(APP_TAG))
    ​	$(call msg,GEN-SKEL,$@)
    ​	$(Q)$(BPFTOOL) gen skeleton $< > $@
    ```



8. 创建struct bpf_object*对象。加载obj文件用`bpf_object__open_file`，在skel.h中创建obj使用`bpf_object__open_mem`