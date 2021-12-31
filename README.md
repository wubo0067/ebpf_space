### EBPF开发总结

1. #### 编译内核支持BTF

​		如果在代码中有`#include <bpf/bpf_core_read.h>`，使用了`BPF_CORE_READ`宏，在user程序中`bpf_object__load`就会报如下错误。

```
libbpf: failed to find valid kernel BTF
libbpf: Error loading vmlinux BTF: -3
libbpf: failed to load object 'tp_execve_kern'
libbpf: failed to load BPF skeleton 'tp_execve_kern': -3
failed to load BPF object: -3
```

​		BTF，即BPF Type Format，类似于类似于DWARF调试信息，但是没有那么generic和verbose。它是一种空间高效的、紧凑的、有足够表达能力的格式，足以描述C程序的所有类型信息。由于它的简单性和BPF去重算法，对比DWARF，BTF能够缩小100x的尺寸。现在，在运行时总是保留BTF信息是常见做法，它对应内核选项 CONFIG_DEBUG_INFO_BTF=y。

​		BTF能够用来增强BPF verifier的能力，**能够允许BPF代码直接访问内核内存，不需要 bpf_probe_read**()。

​		编译支持BTF的内核。

- .config文件设置CONFIG_DEBUG_INFO_BTF=y，让 Linux 内核在运行时（runtime）一直携带 BTF 信息是可行的

- 安装dwarves。**yum -y install libdwarves1.x86_64 dwarves.x86_64**

- 安装**pahole**。

  ```
  git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
  git checkout v1.19
  cmake -D__LIB="lib" -DCMAKE_INSTALL_PREFIX="/usr/local" -DEXEC_INSTALL_PREFIX="" .
  make
  make install
  ```

- 在内核源码执行make vmlinux，检查/sys/kernel/btf/vmlinux

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

printk( "execute:%s, event length: %u", evt->comm, len );，如果len是size_t类型，没有匹配的format，应为format只支持%d %i %u %x %ld %li %lu %lx %lld %lli %llu %llx %p %pB %pks %pus %s，所以会报内存越界。

bpftrace.c:428。最多只能有三个参数。

```
if (fmt_cnt >= 3)
​      return -EINVAL;
```

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
    * vmalloc_user的实践。看到分配的地址是大于0xffff8000000000的，还是内核地址空间。https://www.coolcou.com/linux-kernel/linux-kernel-memory-management-api/the-linux-kernel-vmalloc-user.html
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
          
          - 安装工具， 
          
            ```
            yum install rpm-devel;  
            yum install rpmdevtools; 
            yum groupinstall "Development tools"
            yum module install llvm-toolset
            ```
          
          - rpmdev-setuptree,  在当前用户根目录下生成rpmbuild目录。
          
          - 在源码目录执行make -j8 rpm-pkg。 [Step-by-step - Build Kernel CentOS 8 Guide - tutorialforlinux.com](https://tutorialforlinux.com/2020/12/28/step-by-step-build-kernel-centos-linux-8-guide/) 
          
            ```
            make mrproper    //会把以前进行过的内核功能文件也删除掉，几乎只有在第一次执行内核编译前才会进行这个操作
            make clean    //仅会删除类似目标文件之类的编译过程产生的中间文件，而不会删除配置文件
            make vmlinux    //未经压缩的内核；常见的/boot下的内核文件都是经过压缩的
            make bzImage    //编译内核，经过压缩的内核
            make modules    //编译内核模块
            make all    //进行上述三个操作
            ```
          
          - 删除多余的内核， yum remove $(rpm -qa | grep kernel | grep -v $(uname -r)) 
          
          - 安装内核，dnf in /data/calm/rpmbuild/RPMS/x86_64/kernel*.rpm --allowerasing，安装后查看是否支持BTF、SOCKHASH、SOCKMAP，下面显示配置已经生效。
          
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
         
         上面的定义方式能**正确运行**，如果使用下面的方式创建map时会报错：Error in bpf_create_map_xattr(sock_ops_map):ERROR: strerror_r(-524)=22(-524)。
         
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

        执行上面命令，可以观察到

        ```
        [root@192 linux]# bpftool prog
        8: sock_ops  name bpf_sockops_v4  tag 532c5c6d79f1461d  gpl
        	loaded_at 2021-10-01T14:26:57+0800  uid 0
        	xlated 936B  jited 533B  memlock 4096B  map_ids 6
        	btf_id 4
        ```

        执行下面命令，prog也会被删除。

        ```
        [root@192 tcp_accelerate]# rm /sys/fs/bpf/bpf_sockops
        rm: remove regular empty file '/sys/fs/bpf/bpf_sockops'? y
        ```

17. #### kernel_src/samples/bpf，tools/bpf/bpftool 代码编译

         在[RPM Search (pbone.net)](http://rpm.pbone.net/)搜索源码rpm包，或[Index of /Linux/cern/centos/7/updates/Source/SPackages (riken.jp)](http://ftp.riken.jp/Linux/cern/centos/7/updates/Source/SPackages/)这个网站。
         ```
         rpm2cpio kernel-4.18.0-305.el8.src.rpm | cpio -idmv
         rpm -ivh kernel-4.18.0-305.el8.src.rpm
         xz -d linux-4.18.0-305.el8.tar.xz
         tar -xvf linux-4.18.0-305.el8.tar -C /usr/src
         cp /boot/config-`uname -r` ./.config
         make scripts
         make headers_install 					# /usr/include/linux
         make M=samples/bpf V=1
         cd tools/bpf/bpftool
         make V=1
         make install
         ```
         
         在编译时报错，遇到
         
         ```
         ./include/linux/page-flags-layout.h:6:10: fatal error: 'generated/bounds.h' file not found
         ./include/linux/jiffies.h:13:10: fatal error: 'generated/timeconst.h' file not found
         ```
         
         先执行下make -j 4，编译下内核源码，这些文件就会生成

     编译参考文档：[How to compile and install Linux Kernel 5.6.9 from source code - nixCraft (cyberciti.biz)](https://www.cyberciti.biz/tips/compiling-linux-kernel-26.html)

     

18. #### ebpf程序的安全性

        - 字节码只能够调用一小部分指定的 eBPF 帮助函数

        - BPF程序不允许包含无法到达的指令，防止加载无效代码，延迟程序的终止。

        - eBPF 程序中循环次数限制且必须在有限时间内结束。

19. #### bpf函数

         内核：uapi/linux/bpf.h、tools/lib/bpf/bpf_helper_defs.h 文件中，*enum* bpf_func_id定义的都是可直接调用的helper functions。
         
         用户：[LIBBPF API — libbpf documentation](https://libbpf.readthedocs.io/en/latest/api.html)
         
         CO-RE：tools/lib/bpf/bpf_core_read.h

20. #### **bpf_map_update_elem**

         BPF_ANY：0，表示如果元素存在，内核将更新元素；如果不存在，则在映射中创建该元素。
         BPF_NOEXIST：1，表示仅在元素不存在时，内核创建元素。
         BPF_EXIST：2，表示仅在元素存在时，内核更新元素。
         内核头文件bpf/bpf_helpers.h，用户空间程序头文件tools/lib/bpf/bpf.h
         用户空间修改映射，区别在于第一个参数改为文件描述符来访问。

21. #### SEC("perf_event")

       ​		Perf事件程序将BPF代码附加到Perf事件上。Perf事件程序类型定义为BPF_PROG_SEC("perf_event",   BPF_PROG_TYPE_PERF_EVENT)，Perf是内核的内部分析器，可以产生硬件和软件的性能数据事件。我们可以用Perf事件程序监控很多系统信息，从计算机的CPU到系统中运行的任何软件。当BPF程序附加到Perf事件上时，每次Perf产生分析数据时，程序代码都将被执行。

       ​		允许perf来加载bfp程序追踪应用程序到内核。

22. #### bpf_get_stackid获取进程用户态、内核态堆栈

        - 应用程序的函数地址转换为symbols name。查看程序elf格式的section，所有symbols信息保存在.symtab 表中。

           ```
           readelf --section-headers ./cachestat_cli
           readelf --syms ./cachestat_cli
           ```

           ebf可以获取用户态堆栈的函数地址，这里需要将地址转换为函数名。

        - 基于软件事件**PERF_TYPE_SOFTWARE**，config描述

           PERF_COUNT_SW_CPU_CLOCK：它报告CPU时钟，即每个CPU的高分辨率计时器，进程堆栈采集使用该事件。

           PERF_COUNT_SW_PAGE_FAULTS：这将报告页面错误数

        - perf_event_open函数参数

           pid == 0 && cpu == -1：这可以测量任何CPU上的调用进程/线程。

           pid == 0 && cpu >= 0：仅当在指定的CPU上运行时，才测量调用进程/线程。

           pid > 0 && cpu == -1：这将测量任何CPU上的指定进程/线程。

           pid > 0 && cpu >= 0：仅当在指定的CPU上运行时，才测量指定的进程/线程。

           pid == -1 && cpu >= 0：这将测量指定CPU上的所有进程/线程。这需要CAP_SYS_ADMIN功能或/ proc / sys / kernel / perf_event_paranoid值小于1。

           pid == -1 && cpu == -1：此设置无效，将返回错误。

        - 用户空间栈帧的内存地址到函数名转换。

          BPF_F_USER_STACK标志可以获取用户空间堆栈列表，栈帧中保存的都是虚拟内存地址，将地址转变为源代码中的函数名（demangle）。

          - /proc/pid/maps文件。虚拟地址在该文件列出的范围里。六列的信息依次为：本段在虚拟内存中的地址范围、本段的权限、偏移地址，即指本段映射地址在文件中的偏移、主设备号与次设备号、文件索引节点号、映射的文件名。kernel会将elf的代码段、数据段映射到虚拟地址空间。
          
          - 函数名在elf文件中，核心是**elf格式和vma之间的关系**，找到这种对应关系才能通过地址找到函数名。
          
          - elf是section，maps是segment，前者是链接视角，后者是运行视角。比如代码在链接时放到了text代码段，这个段就是section，同理还有data、bss等，可当执行文件被加载到进程VM中的不同区域时，这个段就是segment了。
          
          - readelf -l /usr/libexec/netdata/plugins.d/apps.plugin，elf中**只有PT_LOAD段才会被加载到VMA中**。通过这个命令可以看到那些段被加载。
          
          - [Linux ELF文件和VMA间的关系_月出皎兮。 佼人僚兮。 舒窈纠兮。 劳心悄兮。-CSDN博客](https://blog.csdn.net/rockrockwu/article/details/81707909)，[c - relationship between VMA and ELF segments - Stack Overflow](https://stackoverflow.com/questions/33756119/relationship-between-vma-and-elf-segments)
          
          - segment和VMA并不是一一对应的关系，一个segment可能对应多个VMA。这是由segment中的section属性决定的。
          
          - bcc中的实现，bcc_syms.h，bcc_symcache_resolve。
          
          - readelf -s 第一列地址是It's (relative) virtual address。我实验的结果第一列就是虚拟地址
          
            print_stack() 	**0x00000000005414d0**	rrddim_compare	/usr/sbin/netdata   	0x0，这是bpf_get_stackid返回的帧地址
          
            22365: **00000000005414d0**    38 FUNC    GLOBAL DEFAULT   13 rrddim_compare，这是readelf -s /usr/sbin/netdata|grep rrddim_compare返回的结果，地址是匹配的。
          
          - 但是对于动态库中的函数地址，可以通过/proc/pid/maps中module基地址+readelf第一列的相对地址+偏移量得到函数在地址空间的地址。
          
            0x00007f52ff67911b = 0xb + ef110 + 7f52ff58a000
          
            ```
            0x00007f52ff67911b	__GI___readlink	/usr/lib64/libc-2.28.so	0xb
            
            [root@localhost build]# readelf -s /usr/lib64/libc-2.28.so|grep __GI___readlink
             23266: 00000000000ef110    37 FUNC    LOCAL  DEFAULT   14 __GI___readlink
            
            7f52ff58a000-7f52ff746000 r-xp 00000000 fd:00 7445                       /usr/lib64/libc-2.28.so
            7f52ff746000-7f52ff945000 ---p 001bc000 fd:00 7445                       /usr/lib64/libc-2.28.so
            7f52ff945000-7f52ff949000 r--p 001bb000 fd:00 7445                       /usr/lib64/libc-2.28.so
            7f52ff949000-7f52ff94b000 rw-p 001bf000 fd:00 7445                       /usr/lib64/libc-2.28.so
            ```
          

23. #### 解除对内核代码头文件的依赖

        ```
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
        ```

       判断系统是否支持BTF，这个文件可作为标志。

24. #### selinux和bfptool命令冲突

        执行bpftool报错

        ```
        root@localhost pahole]# bpftool prog show
        Error: can't get prog by id (794): Permission denied
        [root@localhost pahole]# bpftool map show
        ```

        解决方式，执行下面的命令

        ```
        ausearch -c 'bpftool' --raw | audit2allow -M my-bpftool
        semodule -X 300 -i my-bpftool.pp
        ```

25. #### profile eEBPF程序

       kernel.bpf_stats_enabled，用来开启收集eBPF程序的状态信息，主要是run_time_ns和run_cnt这两个参数。前者代表内核累计花了多少时间运行这个BPF程序，后者是这个BPF程序累计运行了多少次

       -  使用`bpftool prog show`命令，执行后直接显示结果
       - 使用`cat /proc/<pid>/fdinfo/<bpf_prog_fd>`命令，执行后直接显示结果
       - 使用`BPF_OBJ_GET_INFO_BY_FD`的BPF系统调用方法，编程获取结果

26. #### CO-RE

       一次编译，到处运行，Compile Once – Run Everywhere，将它依赖的软件栈和数据集中在一起.

       - BTF 类型信息：使得我们能获取内核、BPF 程序类型及 BPF 代码的关键信息， 这也是下面其他部分的基础。
       - 编译器（clang）：给 BPF C 代码提供了表达能力和记录重定位（relocation）信息的能力。
       - BPF loader (libbpf)：根据内核的BTF和BPF程序，调整编译后的BPF代码，使其适合在目标内核上运行。
       - 内核：虽然对 BPF CO-RE 完全不感知，但提供了一些 BPF 高级特性，使某些高级场景成为可能。

27. #### cursor_advance宏的作用

      ```
      /* Packet parsing state machine helpers. */
      #define cursor_advance(_cursor, _len) \
        ({ void *_tmp = _cursor; _cursor += _len; _tmp; })
      ```

      调用代码如下：

      ```
      struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
      ```

      代码结果等价于，

      ```
      {
      	void *__tmp = cursor;
      	cursor += sizeof(*ethernet);
      	ethernet = __tmp;
      }
      ```

28. ####  安装内核

     列出仓库中内核：dnf --enablerepo="ol8_baseos_latest" --enablerepo="elrepo-kernel" list available | grep kernel

     查看包信息：yum info kernel-4.18.0

     安装内核：yum install kernel-4.18.0-348.7.1.el8_5

     安装内核源码：在仓库地址[Oracle Linux 8 (x86_64) BaseOS Latest | Oracle, Software. Hardware. Complete.](https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/index_src.html)，找到kernel-4.18.0-348.7.1.el8_5.src.rpm，下载安装

     查看安装的内核：rpm -qa|grep kernel

     解压rpm源码包：cd /usr/src/kernels/，cp linux-4.18.0-348.7.1.el8_5.tar.xz ./，unxz linux-4.18.0-348.7.1.el8_5.tar.xz，tar xf linux-4.18.0-348.7.1.el8_5.tar 