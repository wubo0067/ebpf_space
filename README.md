### EBPF开发总结

1. #### 不支持BTF

如果在代码中有`#include <bpf/bpf_core_read.h>`，使用了`BPF_CORE_READ`宏，在user程序中`bpf_object__load`就会报如下错误。

```
libbpf: failed to find valid kernel BTF
libbpf: Error loading vmlinux BTF: -3
libbpf: failed to load object 'tp_execve_kern'
libbpf: failed to load BPF skeleton 'tp_execve_kern': -3
failed to load BPF object: -3
```



2. #### BPF Verifier校验报错

BPF Verifier输出unbounded memory access，需要判断args空间是否足够读取ARGSIZE，没有这个判断就校验就会报错。

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



3. #### printk校验报错

printk( "execute:%s, event length: %u", evt->comm, len );，如果len是size_t类型，没有匹配的format，应为format只支持%d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx, %p, %s，所以会报内存越界。

 

4. #### eBPF用户程序中的全局变量

user程序如何初始化kern程序中的变量达到控制效果。patch有个说明 [[v3,bpf-next,1/3\] bpf: add mmap() support for BPF_MAP_TYPE_ARRAY - Patchwork (ozlabs.org)](https://patchwork.ozlabs.org/project/netdev/patch/20191113031518.155618-2-andriin@fb.com/) 。

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
那么这个map的地址空间分配为何要使用**VM_USERMAP**这个标志呢？

- ###### 就是实现了mmap，vmalloc_user + remap_vmalloc_range

    * vmalloc申请一段不连续的物理地址空间，映射到连续的内核虚拟地址上。
    * vmalloc_user申请一段不连续的物理地址空间，映射到连续的虚拟地址给user space使用。疑问，这个地址是在User Addresses范围内？不在User Addresses范围，而是在Kernel Addresses范围，只是在分配的vma打上VM_USERMAP的标志。相当于在内核连续地址空间范围内标识一块范围，这个是用户空间使用的。
    * vmalloc_user的帮助说明，用于申请一段虚拟地址连续的内存给user space使用，一般情况下这段虚拟内存是当前进程空间的，因此会给它添加一个VM_USERMAP的flag，防止将kernel space的数据泄露到user space。
    * vmalloc_user的实践，https://www.coolcou.com/linux-kernel/linux-kernel-memory-management-api/the-linux-kernel-vmalloc-user.html。看到分配的地址是大于0xffff8000000000的。还是内核地址空间。
    * VM_USERMAP，也是配合函数remap_vmalloc_range使用的，因为这块地址是要用在User Addresses的，所以要重新进行映射，remap_vmalloc_range - map vmalloc pages to userspace。

- 小结

    - 全局变量使用bpf_object__init_global_data_maps

    - 这个map对应类型是BPF_MAP_TYPE_ARRAY，加上了BPF_F_MMAPABLE标志位，支持内存映射。.map_alloc = array_map_alloc, 

        ```
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

        	if (mmapable) {
        		BUG_ON(!PAGE_ALIGNED(size));
        		align = SHMLBA;
        		flags = VM_USERMAP;

    - BPF_F_MMAPABLE的目的是实现内存映射的效果，让用户应用程序可以直接访问内核地址空间。用户空间和内核空间共享数据空间，数据存放在物理内存。在创建带有该标志位的MAP时，使用VM_USERMAP来分配内存

    - 每个bpf map的mmap，首先每个bpf map有个fd。

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

        这里有个bpf_map_fops，上面绑定了fd的对应操作

        ```
        const struct file_operations bpf_map_fops = {
        #ifdef CONFIG_PROC_FS
        	.show_fdinfo	= bpf_map_show_fdinfo,
        #endif
        	.release	= bpf_map_release,
        	.read		= bpf_dummy_read,
        	.write		= bpf_dummy_write,
        	.mmap		= bpf_map_mmap,
        	.poll		= bpf_map_poll,
        };
        ```

        bpf_map_mmap就实现了内存映射功能，调用了err = map->ops->map_mmap(map, vma);针对BPF_MAP_TYPE_ARRAY这种类型的map，.map_mmap = array_map_mmap,最终是调用了remap_vmalloc_range函数。

        ```
        static int array_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
        {
        	struct bpf_array *array = container_of(map, struct bpf_array, map);
        	pgoff_t pgoff = PAGE_ALIGN(sizeof(*array)) >> PAGE_SHIFT;
        
        if (!(map->map_flags & BPF_F_MMAPABLE))
        	return -EINVAL;
        
        if (vma->vm_pgoff * PAGE_SIZE + (vma->vm_end - vma->vm_start) >
            PAGE_ALIGN((u64)array->map.max_entries * array->elem_size))
        	return -EINVAL;
        
        return remap_vmalloc_range(vma, array_map_vmalloc_addr(array),
        			   vma->vm_pgoff + pgoff);
        
        }
        ```

        

5. #### dump出对应的源码和bpf指令，在verifier报错后可检查指令。

```
llvm-objdump -S --no-show-raw-insn tp_execve.kern.o
```



6. #### bfptool工具生成xxx.skel.h文件

解除对xxx.kern.o的依赖。程序中不用`bpf_object__load`。bpftool gen skeleton %.kern.o > %.skel.h。

```
$(patsubst %,%.skel.h,$(APP_TAG)): $(patsubst %,%.kern.o,$(APP_TAG))
​	$(call msg,GEN-SKEL,$@)
​	$(Q)$(BPFTOOL) gen skeleton $< > $@
```



7. #### open bfp kernel object

创建struct bpf_object*对象。加载obj文件用`bpf_object__open_file`，在skel.h中创建obj使用`bpf_object__open_mem`



8. #### 查看正在使用BPF Map

```
[root@Thor-CI ~]# bpftool map
791: hash  name execve_hash  flags 0x0
	key 4B  value 2600B  max_entries 1024  memlock 2670592B
	btf_id 655
792: perf_event_array  name execve_perf_evt  flags 0x0
	key 4B  value 4B  max_entries 128  memlock 4096B
793: array  name tp_execv.rodata  flags 0x480
	key 4B  value 9B  max_entries 1  memlock 4096B
	btf_id 655  frozen
794: array  name tp_execv.bss  flags 0x400
	key 4B  value 2600B  max_entries 1  memlock 4096B
	btf_id 655
```

```
[root@Thor-CI ~]# bpftool map dump name tp_execv.rodata
[{
        "value": {
            ".rodata": [{
                    "max_args": 20
                },{
                    "target_uid": 4294967295
                },{
                    "ignore_failed": true
                }
            ]
        }
    }
]
```



9. #### bpf_trace_prink的限制
   
    - 最大只支持3个参数。
    
    - 程序共享输出共享 `/sys/kernel/debug/tracing/trace_pipe` 文件 。
    
    - 该实现方式在数据量大的时候，性能也存在一定的问题 。
    
      
    
10. #### 创建BPF_MAP_TYPE_SOCKMAP、BPF_MAP_TYPE_SOCKHASH两种类型的map失败。

    ```
    libbpf: Error in bpf_create_map_xattr(sock_ops_map):Invalid argument(-22). Retrying without BTF.
    libbpf: map 'sock_ops_map': failed to create: Invalid argument(-22)
    ```

    原因是内核编译时没有配置 CONFIG_BPF_STREAM_PARSER ，在代码中可以查看到

    ```
    #if defined(CONFIG_BPF_STREAM_PARSER)
    BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKMAP, sock_map_ops)
    BPF_MAP_TYPE(BPF_MAP_TYPE_SOCKHASH, sock_hash_ops)
    #endif
    ```

    只有使用 CONFIG_BPF_STREAM_PARSER=y重新编译内核。

    

11. #### 编译内核支持BTF、BPF_MAP_TYPE_SOCKMAP、BPF_MAP_TYPE_SOCKHASH

      ```
      cd linux-5.12.9/
      cp -v /boot/config-$(uname -r) .config 
      ```

      编辑.config文件，设置以下内容

      ```
      CONFIG_DEBUG_INFO_BTF=y
      CONFIG_BPF_STREAM_PARSER=y
      ```

      内核编译、安装流程

     - 安装工具， yum install rpm-devel;rpmdevtools

     - **rpmdev-setuptree,  在当前用户根目录下生成rpmbuild目录**。
     - 在源码目录执行make -j8 rpm-pkg。 [Step-by-step - Build Kernel CentOS 8 Guide - tutorialforlinux.com](https://tutorialforlinux.com/2020/12/28/step-by-step-build-kernel-centos-linux-8-guide/) 

     -  删除多余的内核， yum remove $(rpm -qa | grep kernel | grep -v $(uname -r)) 


     -  安装内核，dnf in /data/calm/rpmbuild/RPMS/x86_64/kernel*.rpm --allowerasing
    
     安装后查看是否支持BTF、SOCKHASH、SOCKMAP，下面显示配置已经生效。
    
     ```
     [root@Thor-CI ~]# grep BPF /boot/config-`uname -r`
     CONFIG_CGROUP_BPF=y
     CONFIG_BPF=y
     CONFIG_BPF_SYSCALL=y
     CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y
     CONFIG_BPF_JIT_ALWAYS_ON=y
     CONFIG_BPF_JIT_DEFAULT_ON=y
     CONFIG_NETFILTER_XT_MATCH_BPF=m
     CONFIG_NET_CLS_BPF=m
     CONFIG_NET_ACT_BPF=m
     CONFIG_BPF_JIT=y
     CONFIG_BPF_STREAM_PARSER=y
     [root@Thor-CI ~]# cat /boot/config-5.12.9|grep BTF
     CONFIG_DEBUG_INFO_BTF=y
     CONFIG_PAHOLE_HAS_SPLIT_BTF=y
     CONFIG_DEBUG_INFO_BTF_MODULES=y
     ```


​     

12. #### BPF_MAP_TYPE_SOCKHASH定义方式

     ```
     struct bpf_map_def SEC( "maps" ) sock_ops_map = {
     	.type           = BPF_MAP_TYPE_SOCKHASH,
     	.key_size       = sizeof(struct sock_key),
     	.value_size     = sizeof(int),
     	.max_entries    = 65535,
     	.map_flags      = 0,
     };
     ```

     只能用这种定义方式，如果使用下面的方式创建map时会报错：上面会创建失败，Error in bpf_create_map_xattr(sock_ops_map):ERROR: strerror_r(-524)=22(-524)

     ```
     struct {
     	__uint( type, BPF_MAP_TYPE_SOCKHASH );
     	__uint( max_entries, 65535 );
     	__type( key, struct sock_key );
     	__type( value, __s32 );
     	__uint( map_flags, 0 );
     	__uint( key_size, sizeof( struct sock_key ) );
     	__uint( value_size, sizeof( __s32 ) );
     } sock_ops_map_1 SEC( ".maps" );
     ```

     但其它类型的map却没有问题，例如BPF_MAP_TYPE_HASH，这种差异问题需要深入研究代码，查看内核源码是可以按上面的编写方式的。

     ```
     struct {
     	__uint(type, BPF_MAP_TYPE_HASH);
     	__uint(max_entries, 64);
     	__type(key, __u32);
     	__type(value, __u64);
     } sockhash SEC(".maps");
     ```

     加载prog的命令：**bpftool prog load tcp_accelerate_sockops.kern.o "/sys/fs/bpf/bpf_sockops"**

     

13. #### bpftool cgroup attach使用cgroup V2

     当前systemd支持三种cgroup模式，分别是

     1. legacy， 采用 cgroup v1
     2. hybrid，混杂模式，既挂载 cgroup v1 也挂载 cgroup v2， 但是在该模式下，cgroup v2 下不使能任何 controller，不用于资源管理,参考[systemd 模式说明](https://github.com/systemd/systemd/pull/10161/files)
     3. unified, 纯粹使用 cgroup v2

     检查当前系统是否支持cgroup v2

     ```
     [root@Thor-CI sockredir]# grep cgroup /proc/filesystems
     nodev	cgroup
     nodev	cgroup2
     ```

     在内核中开启cgroup v2

     ```
     grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=1"
     reboot
     ```

     检查cgroup v2是否生效

     ```
     [root@Thor-CI sockredir]# mount | grep cgroup
     cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime,nsdelegate)
     tmpfs on /usr/local/aegis/cgroup type tmpfs (rw,relatime,size=51200k)
     ```

    **bpftool cgroup是依赖cgroup v2的**。 

    相关资料

     [centos8使用grubby修改内核启动参数 - TinyChen's Studio](https://tinychen.com/20201118-centos8-use-grubby-modify-kernel/)

     [详解Cgroup V2 | Zorro’s Linux Book (zorrozou.github.io)](https://zorrozou.github.io/docs/详解Cgroup V2.html)
    
     [Cgroup V2 Notes | Lifeng (gitee.io)](https://lifeng2221dd1.gitee.io/2020/11/12/cgroup-v2/)
    
    
    
14. #### SEC("name")和prog _type、attach_type关系

    文件libbpf.c中定义了name和prog_type与attach_type的对应关系。部分如下。

    ```
    static const *struct* bpf_sec_def section_defs[] = {
      BPF_PROG_SEC("socket",     BPF_PROG_TYPE_SOCKET_FILTER),
      BPF_PROG_SEC("sk_reuseport",    BPF_PROG_TYPE_SK_REUSEPORT),
      SEC_DEF("kprobe/", KPROBE,	.attach_fn = attach_kprobe),
      BPF_APROG_SEC("sockops",    BPF_PROG_TYPE_SOCK_OPS,	BPF_CGROUP_SOCK_OPS),
    };
    ```

15. #### ebpf的所有hooks

    查看完成的ebpf hooks列表，文件/uapi/linux/bpf.h中，枚举类型*enum* bpf_attach_type 就是所有的hook点。在libbpf.c代码中通过函数libbpf_prog_type_by_name传入sec name可以获取对应的prog type和attach type。

    ```
    (gdb) p sec_name
    $5 = 0x872f70 "sockops"
    (gdb) n
    1518			bpf_program__set_ifindex(pos, ifindex);
    (gdb) p pos
    $6 = (struct bpf_program *) 0x872e90
    (gdb) p ifindex
    $7 = 0
    (gdb) p expected_attach_type
    $8 = BPF_CGROUP_SOCK_OPS
    (gdb) p prog_type
    $9 = BPF_PROG_TYPE_SOCK_OPS
    ```

    上面的gdb调试结果可清晰的显示这种关系。

    这篇文章对prog type有详细的说明，[BPF: A Tour of Program Types (oracle.com)](https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types)

    

16. #### ebpf对象持久化，文件系统/sys/fs/bpf

    [Persistent BPF objects [LWN.net\]](https://lwn.net/Articles/664688/)

    一般我们会编写一个user space的程序来加载kern的prog，这样ebpf程序的生命周期和用户态程序一致，监控采集显示的程序基本如此。可有些模式下的prog程序是需要类似守护，例如流量控制，转发控制这些，所以在kernel4.4版本提供了持久化能力。会创建一个pin fd在该文件系统下，这个fd就代表一个ebpf object。如果要unpin这个ebpf object，可以直接删除这个文件。

    `mount(type, target, type, 0, "mode=0700"))`

    target是/sys/fs/bpf，type是bpf。

    ```
    err = bpf_obj_pin(bpf_program__fd(prog), pinfile);
    err = bpf_object__pin_maps(obj, pinmaps);
    ```

    使用bpftool命令来持久化ebpf object

    ```
    bpftool prog load tcp_accelerate_sockops.kern.o "/sys/fs/bpf/bpf_sockops"
    ```

    

17. #### kernel_src/samples/bpf，tools/bpf/bpftool 代码编译

    ```
    cp /boot/config-`uname -r` ./.config
    make scripts
    make headers_install
    make M=samples/bpf V=1
    cd tools/bpf/bpftool
    make V=1
    make install
    ```

    



