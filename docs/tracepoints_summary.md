# Linux Tracepoints 功能分类统计

## 总览
- **总计**: 2058 个 tracepoints
- **已分类**: 2058 个 (100%)
- **未分类**: 0 个

## 功能分类详情

### 1. 系统调用 (714 个, 34.7%)
用于跟踪所有系统调用的进入和退出
- **syscalls**: 712 个 - 所有系统调用的 enter/exit
- **raw_syscalls**: 2 个 - 原始系统调用包装器

**主要事件类型**:
- 文件操作: open, read, write, close, stat, etc.
- 进程管理: fork, exec, exit, wait, etc.
- 网络操作: socket, bind, connect, accept, etc.
- 内存管理: mmap, mprotect, munmap, mlock, etc.
- 信号处理: kill, signal, etc.
- IPC: shm*, msg*, sem*, etc.

### 2. 文件系统 (209 个, 10.2%)
VFS 和具体文件系统实现的跟踪
- **ext4**: 113 个 - ext4 文件系统操作
- **writeback**: 32 个 - 页面写回机制
- **jbd2**: 21 个 - ext4 的日志层
- **filelock**: 12 个 - 文件锁
- **fs_dax**: 14 个 - 直接访问持久内存
- **iomap**: 13 个 - I/O 映射操作
- **filemap**: 4 个 - 页面缓存文件映射

**典型用途**:
- 文件系统性能分析
- 延迟诊断
- 写回行为观察
- 元数据操作追踪

### 3. 内核功能 (143 个, 6.9%)
通用内核子系统的跟踪
- **xhci-hcd**: 53 个 - USB xHCI 主机控制器
- **workqueue**: 4 个 - 工作队列
- **notifier**: 3 个 - 通知链
- **printk**: 1 个 - 内核日志
- **qdisc**: 5 个 - 网络队列调度
- **regmap**: 17 个 - 寄存器映射
- 其他内核基础设施

### 4. 设备驱动 (142 个, 6.9%)
图形和显示相关的跟踪
- **xe**: 66 个 - Intel GPU 执行单元
- **i915**: 43 个 - Intel GPU 驱动
- **drm**: 3 个 - DRM 子系统
- **gpu_scheduler**: 4 个 - GPU 调度器
- **x86_fpu**: 10 个 - x86 FPU 状态
- **xdp**: 12 个 - eXpress Data Path

### 5. 虚拟化 (140 个, 6.8%)
虚拟化相关的跟踪
- **kvm**: 90 个 - KVM 虚拟机管���
- **kvmmmu**: 17 个 - KVM MMU
- **xen**: 25 个 - Xen 虚拟化
- **hyperv**: 8 个 - Hyper-V 虚拟化

**主要用途**:
- 虚拟机性能分析
- VM 退出原因追踪
- EPT/NPT 违规诊断
- 虚拟化开销测量

### 6. 网络文件系统 (136 个, 6.6%)
NFS/RPC 相关的跟踪
- **sunrpc**: 135 个 - Sun RPC 实现
- **包括**: RPC 客户端、服务器、传输层等

### 7. 内存管理 (88 个, 4.3%)
内核内存管理子系统的跟踪
- **kmem**: 11 个 - 内核内存分配器
- **vmscan**: 18 个 - 内存回收
- **compaction**: 15 个 - 内存碎片整理
- **migrate**: 4 个 - 页面迁移
- **huge_memory**: 6 个 - 大页内存
- **thp**: 6 个 - 透明大页
- **ksm**: 8 个 - 内核同页合并
- **oom**: 8 个 - 内存溢出处理
- **percpu**: 5 个 - per-CPU 变量
- **maple_tree**: 3 个 - Maple 树数据结构
- **page_isolation**: 1 个 - 页面隔离
- **pagemap**: 2 个 - 页面映射

**典型用途**:
- 内存泄漏检测
- 内存分配延迟分析
- 内存回收行为观察
- 大页使用情况统计
- OOM 诊断

### 8. CPU 和调度 (74 个, 3.6%)
CPU 调度和电源管理相关的跟踪
- **sched**: 27 个 - 进程调度器
- **power**: 24 个 - CPU 频率/电源管理
- **cpuhp**: 3 个 - CPU 热插拔
- **ipi**: 4 个 - 处理器间中断
- **irq_vectors**: 33 个 - 中断向量
- **context_tracking**: 2 个 - 上下文切换跟踪

**典型用途**:
- 调度延迟分析
- CPU 使用率统计
- 上下文切换开销
- 迁移模式分析
- 电源管理策略优化

### 9. 网络 (72 个, 3.5%)
网络协议栈的跟踪
- **net**: 16 个 - 网络子系统
- **sock**: 6 个 - Socket 层
- **skb**: 3 个 - Socket buffer
- **tcp**: 8 个 - TCP 协议
- **neigh**: 6 个 - 邻居子系统
- **bridge**: 5 个 - 网桥
- **napi**: 1 个 - 网络轮询
- **mptcp**: 4 个 - 多路径 TCP
- **handshake**: 14 个 - TLS 握手
- **fib**: 1 个 - 路由表查找
- **fib6**: 1 个 - IPv6 路由表
- **icmp**: 1 个 - ICMP 协议

**典型用途**:
- 网络吞吐量分析
- 延迟测量
- 丢包诊断
- TCP 行为分析
- 网络栈性能调优

### 10. 电源管理 (71 个, 3.5%)
系统电源和热管理
- **thermal**: 8 个 - 热管理
- **clk**: 21 个 - 时钟管理
- **regulator**: 10 个 - 电压调节器
- **timer**: 10 个 - 定时器
- **suspend_resume**: 1 个 - 系统挂起/恢复
- **rpm**: 5 个 - 运行时电源管理
- **thermal_power_allocator**: 3 个 - 热功率分配
- **devfreq**: 2 个 - 设备频率管理

### 11. 存储 (65 个, 3.2%)
块设备和存储的跟踪
- **block**: 40 个 - 块设备层
- **libata**: 32 个 - ATA 设备驱动
- **scsi**: 5 个 - SCSI 设备
- **sd**: 2 个 - SCSI 磁盘
- **nvme**: 4 个 - NVMe 设备

**典型用途**:
- I/O 延迟分析
- 吞吐量测量
- 块设备调度器优化
- 存储瓶颈诊断

### 12. 音频 (42 个, 2.0%)
音频子系统的跟踪
- **asoc**: 18 个 - ALSA SoC 音频
- **hda**: 3 个 - HD Audio
- **hda_controller**: 6 个 - HDA 控制器
- **hda_intel**: 4 个 - Intel HDA
- **sof**: 5 个 - Sound Open Firmware
- **sof_intel**: 6 个 - Intel SOF

### 13. 硬件接口 (35 个, 1.7%)
硬件总线和外设接口的跟踪
- **timer**: 10 个 - 定时器
- **rtc**: 12 个 - 实时时钟
- **spi**: 8 个 - SPI 总线
- **i2c**: 4 个 - I2C 总线
- **gpio**: 2 个 - GPIO
- **smbus**: 4 个 - SMBus
- **pwm**: 2 个 - PWM
- **mmc**: 2 个 - MMC/SD 卡

### 14. 中断和锁 (27 个, 1.3%)
中断处理和锁机制
- **irq**: 6 个 - 中断处理
- **irq_matrix**: 13 个 - IRQ 矩阵管理
- **nmi**: 1 个 - 不可屏蔽中断
- **lock**: 2 个 - 锁竞争
- **rcu**: 2 个 - RCU 机制
- **csd**: 3 个 - 函数远程调用

### 15. 容器和资源控制 (23 个, 1.1%)
- **cgroup**: 12 个 - 控制组
- **iocost**: 4 个 - I/O 成本控制
- **resctrl**: 3 个 - 资源控制

### 16. 进程管理 (21 个, 1.0%)
- **task**: 2 个 - 任务管理
- **signal**: 2 个 - 信号处理
- **mmap**: 4 个 - 内存映射
- **mmap_lock**: 3 个 - mmap 锁
- **module**: 5 个 - 内核模块
- **initcall**: 3 个 - 初始化调用
- **exceptions**: 2 个 - 异常处理

### 17. 异步 I/O (17 个, 0.8%)
- **io_uring**: 17 个 - io_uring 异步 I/O 框架

### 18. 内存管理单元 (8 个, 0.4%)
- **iommu**: 5 个 - I/O MMU
- **intel_iommu**: 2 个 - Intel IOMMU

### 19. 性能分析 (5 个, 0.2%)
- **osnoise**: 5 个 - 操作系统噪声测量

### 20. BPF (2 个, 0.1%)
- **bpf_test_run**: 1 个 - BPF 测试运行
- **bpf_trace**: 1 个 - BPF 跟踪

### 21. 安全 (1 个, <0.1%)
- **avc**: 1 个 - SELinux AVC

### 22. TLB (1 个, <0.1%)
- **tlb**: 1 个 - TLB 刷新

### 23. 内存分配 (4 个, 0.2%)
- **vmalloc**: 3 个 - vmalloc 分配器
- **swiotlb**: 1 个 - 软件 I/O TLB

## 使用建议

### 性能分析
1. **CPU 瓶颈**: 使用 `sched:*` 分析调度问题
2. **内存瓶颈**: 使用 `kmem:*`, `vmscan:*` 分析内存压力
3. **I/O 瓶颈**: 使用 `block:*`, `writeback:*` 分析磁盘 I/O
4. **网络瓶颈**: 使用 `net:*`, `tcp:*` 分析网络性能
5. **系统调用开销**: 使用 `syscalls:*` 统计系统调用频率

### 故障诊断
1. **延迟尖峰**: 结合 `irq:*`, `sched:*`, `block:*` 分析
2. **内存泄漏**: 使用 `kmem:*` 跟踪内存分配
3. **进程卡死**: 使用 `sched:*` 和 `signal:*` 分析
4. **文件系统错误**: 使用 `ext4:*`, `jbd2:*` 诊断

### 虚拟化环境
1. **VM 性能**: 使用 `kvm:*`, `kvmmmu:*` 分析虚拟化开销
2. **VM 退出**: 使用 `kvm:*` 统计 VM_EXIT 原因

## 工具支持

这些 tracepoints 可以通过以下工具使用:
- **perf**: `perf record -e 'tracepoint:*'`
- **bpftrace**: `bpftrace -e 'tracepoint:syscalls:sys_enter_* {...}'`
- **eBPF**: 通过 Aya 框架编程访问
- **ftrace**: 通过 tracefs/debugfs 直接访问

## 参考文档

- Linux 内核源码: `Documentation/trace/events.rst`
- Tracepoint 定义: `/sys/kernel/debug/tracing/events/`
- perf-event 文档: `man perf-record`
