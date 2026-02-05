# CPU 的 Tracepoint 跟踪

本文档整理了所有与 CPU 相关的 Linux tracepoints，用于 CPU 性能分析、调度器诊断、电源管理优化等场景。

## 目录
- [1. CPU 调度器 (sched)](#1-cpu-调度器-sched)
- [2. CPU 电源管理 (power)](#2-cpu-电源管理-power)
- [3. CPU 热插拔 (cpuhp)](#3-cpu-热插拔-cpuhp)
- [4. 处理器间中断 (ipi)](#4-处理器间中断-ipi)
- [5. 中断向量 (irq_vectors)](#5-中断向量-irq_vectors)
- [6. 上下文跟踪 (context_tracking)](#6-上下文跟踪-context_tracking)
- [7. AMD CPU (amd_cpu)](#7-amd-cpu-amd_cpu)
- [使用示例](#使用示例)

---

## 1. CPU 调度器 (sched)

调度器 tracepoints 用于分析进程调度行为、调度延迟、CPU 迁移等。

### 调度器事件列表

#### 进程切换和唤醒
- `sched:sched_switch` - 进程切换（核心事件）
- `sched:sched_wakeup` - 唤醒进程
- `sched:sched_wakeup_new` - 唤醒新进程
- `sched:sched_waking` - 进程正在被唤醒
- `sched:sched_wait_task` - 任务等待

#### 进程生命周期
- `sched:sched_process_fork` - 进程创建
- `sched:sched_process_exec` - 进程执行
- `sched:sched_process_exit` - 进程退出
- `sched:sched_process_free` - 进程释放
- `sched:sched_process_wait` - 进程等待

#### CPU 迁移和 NUMA
- `sched:sched_migrate_task` - 任务迁移到其他 CPU
- `sched:sched_move_numa` - NUMA 节点间迁移
- `sched:sched_stick_numa` - 任务固定到 NUMA 节点
- `sched:sched_swap_numa` - NUMA 节点间交换
- `sched:sched_skip_vma_numa` - 跳过 VMA NUMA

#### 调度统计
- `sched:sched_stat_runtime` - 运行时统计
- `sched:sched_stat_wait` - 等待时间统计
- `sched:sched_stat_sleep` - 休眠时间统计
- `sched:sched_stat_blocked` - 阻塞时间统计
- `sched:sched_stat_iowait` - I/O 等待统计

#### 优先级和策略
- `sched:sched_pi_setprio` - 设置优先级
- `sched:sched_wake_idle_without_ipi` - 唤醒 idle CPU 不发送 IPI

#### 内核线程
- `sched:sched_kthread_stop` - 停止内核线程
- `sched:sched_kthread_stop_ret` - 内核线程停止返回
- `sched:sched_kthread_work_queue_work` - 队列化内核工作
- `sched:sched_kthread_work_execute_start` - 开始执行内核工作
- `sched:sched_kthread_work_execute_end` - 完成执行内核工作

#### 异常情况
- `sched:sched_process_hang` - 进程挂起

### 典型使用场景

**1. 分析调度延迟**
```bash
# 查看 sched_switch 延迟
bpftrace -e '
tracepoint:sched:sched_switch {
    @ns[comm] = hist(timestamp - args->prev_timestamp);
}
'
```

**2. 统计进程迁移**
```bash
# 统计 CPU 间迁移频率
bpftrace -e '
tracepoint:sched:sched_migrate_task {
    @migr[args->pid, args->comm] = count();
}
'
```

**3. 监控 runnable 延迟**
```bash
bpftrace -e '
tracepoint:sched:sched_wakeup {
    @start[args->pid] = nsecs;
}

tracepoint:sched:sched_switch {
    if (@start[args->next_pid]) {
        @latency = hist(nsecs() - @start[args->next_pid]);
        delete(@start[args->next_pid]);
    }
}
'
```

---

## 2. CPU 电源管理 (power)

CPU 频率调节、空闲状态管理和电源策略相关的 tracepoints。

### 电源管理事件列表

#### CPU 频率
- `power:cpu_frequency` - CPU 频率变化
- `power:cpu_frequency_limits` - CPU 频率限制
- `power:pstate_sample` - P-state 采样

#### CPU 空闲状态
- `power:cpu_idle` - CPU 进入/退出空闲状态
- `power:cpu_idle_miss` - CPU 空闲状态未命中

#### 时钟管理
- `power:clock_enable` - 时钟使能
- `power:clock_disable` - 时钟禁用
- `power:clock_set_rate` - 设置时钟频率

#### 设备电源管理
- `power:device_pm_callback_start` - 设备 PM 回调开始
- `power:device_pm_callback_end` - 设备 PM 回调结束
- `power:suspend_resume` - 系统挂起/恢复
- `power:wakeup_source_activate` - 唤醒源激活
- `power:wakeup_source_deactivate` - 唤醒源停用

#### 电源服务质量 (QoS)
- `power:pm_qos_add_request` - 添加 QoS 请求
- `power:pm_qos_remove_request` - 移除 QoS 请求
- `power:pm_qos_update_request` - 更新 QoS 请求
- `power:pm_qos_update_flags` - 更新 QoS 标志
- `power:pm_qos_update_target` - 更新 QoS 目标

#### 设备 QoS
- `power:dev_pm_qos_add_request` - 添加设备 QoS 请求
- `power:dev_pm_qos_remove_request` - 移除设备 QoS 请求
- `power:dev_pm_qos_update_request` - 更新设备 QoS 请求

#### 其他
- `power:guest_halt_poll_ns` - Guest halt 轮询时间
- `power:power_domain_target` - 电源域目标
- `power:powernv_throttle` - PowerNV 节流

### 典型使用场景

**1. 监控 CPU 频率变化**
```bash
bpftrace -e '
tracepoint:power:cpu_frequency {
    printf("CPU%d: %d -> %d kHz\n", args->cpu_id, args->old_state, args->new_state);
}
'
```

**2. 统计 CPU 空闲时间**
```bash
bpftrace -e '
tracepoint:power:cpu_idle {
    if (args->state == 4294967295) { // 退出 idle
        @idle_ns[args->cpu_id] = nsecs() - @idle_start[args->cpu_id];
    } else { // 进入 idle
        @idle_start[args->cpu_id] = nsecs();
    }
}
'
```

**3. 分析 DVFS 策略**
```bash
perf record -e 'power:cpu_frequency' -a
perf report
```

---

## 3. CPU 热插拔 (cpuhp)

CPU 热插拔机制的跟踪，用于动态添加/移除 CPU。

### CPU 热插拔事件列表

- `cpuhp:cpuhp_enter` - 进入 CPU 热插拔操作
- `cpuhp:cpuhp_exit` - 退出 CPU 热插拔操作
- `cpuhp:cpuhp_multi_enter` - 进入多 CPU 热插拔操作

### 使用示例

```bash
# 监控 CPU 热插拔事件
bpftrace -e '
tracepoint:cpuhp:cpuhp_enter {
    printf("CPU%d: hotplug operation started (cpu=%d, target=%d)\n",
           args->cpu, args->cpu, args->target);
}
'
```

---

## 4. 处理器间中断 (IPI)

IPI 用于多核 CPU 之间的通信和协调。

### IPI 事件列表

- `ipi:ipi_entry` - IPI 处理入口
- `ipi:ipi_exit` - IPI 处理退出
- `ipi:ipi_raise` - 发起 IPI
- `ipi:ipi_send_cpu` - 向指定 CPU 发送 IPI
- `ipi:ipi_send_cpumask` - 向 CPU 集合发送 IPI

### 使用示例

```bash
# 统计 IPI 发送情况
bpftrace -e '
tracepoint:ipi:ipi_raise {
    @[args->cpumask] = count();
}

tracepoint:ipi:ipi_send_cpu {
    @ipi_to_cpu[args->cpu] = count();
}
'
```

---

## 5. 中断向量 (irq_vectors)

x86 中断向量相关的 tracepoints，用于分析中断处理性能。

### 中断向量事件列表

#### 中断处理入口/出口
- `irq_vectors:reschedule_entry` - 重新调度中断入口
- `irq_vectors:reschedule_exit` - 重新调度中断出口
- `irq_vectors:call_function_entry` - 调用函数中断入口
- `irq_vectors:call_function_exit` - 调用函数中断出口
- `irq_vectors:call_function_single_entry` - 单 CPU 函数调用入口
- `irq_vectors:call_function_single_exit` - 单 CPU 函数调用退出

#### 定时器相关
- `irq_vectors:local_timer_entry` - 本地定时器中断入口
- `irq_vectors:local_timer_exit` - 本地定时器中断退出

#### 错误处理
- `irq_vectors:error_apic_entry` - APIC 错误中断入口
- `irq_vectors:error_apic_exit` - APIC 错误中断退出
- `irq_vectors:spurious_apic_entry` - 伪 APIC 中断入口
- `irq_vectors:spurious_apic_exit` - 伪 APIC 中断退出

#### 热管理
- `irq_vectors:thermal_apic_entry` - 热管理 APIC 中断入口
- `irq_vectors:thermal_apic_exit` - 热管理 APIC 中断退出

#### 阈值处理
- `irq_vectors:threshold_apic_entry` - 阈值 APIC 中断入口
- `irq_vectors:threshold_apic_exit` - 阈值 APIC 中断退出

#### 向量管理
- `irq_vectors:irq_work_entry` - IRQ 工作入口
- `irq_vectors:irq_work_exit` - IRQ 工作退出
- `irq_vectors:vector_activate` - 激活中断向量
- `irq_vectors:vector_alloc` - 分配中断向量
- `irq_vectors:vector_alloc_managed` - 分配托管中断向量
- `irq_vectors:vector_free_moved` - 释放已移动的向量
- `irq_vectors:vector_reserve` - 保留中断向量
- `irq_vectors:vector_reserve_managed` - 保留托管中断向量
- `irq_vectors:vector_setup` - 设置中断向量
- `irq_vectors:vector_teardown` - 拆除中断向量
- `irq_vectors:vector_update` - 更新中断向量
- `irq_vectors:vector_config` - 配置中断向量
- `irq_vectors:vector_deactivate` - 停用中断向量
- `irq_vectors:vector_clear` - 清除中断向量

#### 平台特定
- `irq_vectors:x86_platform_ipi_entry` - x86 平台 IPI 入口
- `irq_vectors:x86_platform_ipi_exit` - x86 平台 IPI 退出
- `irq_vectors:deferred_error_apic_entry` - 延迟错误 APIC 入口
- `irq_vectors:deferred_error_apic_exit` - 延迟错误 APIC 退出

### 使用示例

```bash
# 统计各类中断向量频率
bpftrace -e '
tracepoint:irq_vectors:*_entry {
    @[probe] = count();
}
'
```

---

## 6. 上下文跟踪 (context_tracking)

跟踪用户态和内核态的上下文切换。

### 上下文跟踪事件列表

- `context_tracking:user_enter` - 进入用户态
- `context_tracking:user_exit` - 退出用户态（进入内核态）

### 使用示例

```bash
# 统计用户态/内核态时间分布
bpftrace -e '
tracepoint:context_tracking:user_exit {
    @kernel_start[cpu] = nsecs();
}

tracepoint:context_tracking:user_enter {
    if (@kernel_start[cpu]) {
        @kernel_ns = sum(nsecs() - @kernel_start[cpu]);
        delete(@kernel_start[cpu]);
    }
}
'
```

---

## 7. AMD CPU (amd_cpu)

AMD CPU 特定的性能事件。

### AMD CPU 事件列表

- `amd_cpu:amd_pstate_perf` - AMD P-state 性能状态

---

## 使用示例

### 示例 1: CPU 调度延迟分析

完整的调度延迟分析脚本：

```bpftrace
#!/usr/bin/env bpftrace
// sched_latency.bt - 分析进程调度延迟

tracepoint:sched:sched_wakeup {
    @wakeup_time[args->pid] = nsecs();
}

tracepoint:sched:sched_switch {
    // 被切换出去的进程
    if (@wakeup_time[args->prev_pid]) {
        $latency = nsecs() - @wakeup_time[args->prev_pid];
        @wakeup_latency[args->prev_comm] = hist($latency);
        delete(@wakeup_time[args->prev_pid]);
    }

    // 切换到的新进程
    if (@wakeup_time[args->next_pid]) {
        $latency = nsecs() - @wakeup_time[args->next_pid];
        @switch_latency[args->next_comm] = hist($latency);
        delete(@wakeup_time[args->next_pid]);
    }
}
```

### 示例 2: CPU 使用率监控

```bpftrace
#!/usr/bin/env bpftrace
// cpu_usage.bt - 监控各 CPU 的使用模式

tracepoint:sched:sched_switch {
    @cpu_state[args->cpu] = args->next_state == 0 ? "RUNNING" : "IDLE";
}

interval:s:1 {
    printf("\n=== CPU State Summary ===\n");
    print(@cpu_state);
    clear(@cpu_state);
}
```

### 示例 3: CPU 频率调节监控

```bpftrace
#!/usr/bin/env bpftrace
// cpu_frequency.bt - 监控 CPU 频率变化

tracepoint:power:cpu_frequency {
    @freq[args->cpu_id] = args->new_state;
    printf("CPU%d: %d kHz -> %d kHz\n",
           args->cpu_id, args->old_state, args->new_state);
}

interval:s:5 {
    printf("\n=== Current CPU Frequencies ===\n");
    print(@freq);
}
```

### 示例 4: 进程迁移热图

```bpftrace
#!/usr/bin/env bpftrace
// process_migration.bt - 分析进程在 CPU 间的迁移

tracepoint:sched:sched_migrate_task {
    @migrate[args->orig_cpu, args->dest_cpu] = count();
}

interval:s:10 {
    printf("\n=== CPU Migration Heatmap ===\n");
    printf("From\\To: ");
    print(@migrate);
}
```

### 示例 5: 中断延迟分析

```bpftrace
#!/usr/bin/env bpftrace
// irq_latency.bt - 分析中断处理延迟

tracepoint:irq:irq_handler_entry {
    @irq_start[args->irq, args->name] = nsecs();
}

tracepoint:irq:irq_handler_exit {
    if (@irq_start[args->irq, args->name]) {
        $latency = nsecs() - @irq_start[args->irq, args->name];
        @irq_latency[args->name] = hist($latency);
        delete(@irq_start[args->irq, args->name]);
    }
}
```

---

## 性能分析工具集成

### 使用 perf 工具

```bash
# 记录所有 CPU 相关的调度事件
perf record -e 'sched:*' -a sleep 10

# 记录 CPU 频率变化
perf record -e 'power:cpu_frequency' -a

# 查看调度详情
perf script

# 生成火焰图
perf script | ./FlameGraph/stackcollapse-perf.pl | \
    ./FlameGraph/flamegraph.pl > cpu_flamegraph.svg
```

### 使用 bpftrace 快速查询

```bash
# 列出所有 CPU 调度相关事件
bpftrace -l 'tracepoint:sched:*'

# 查看特定事件的字段
bpftrace -e 'tracepoint:sched:sched_switch { print(args); }'

# 统计进程切换频率
bpftrace -e 'tracepoint:sched:sched_switch { @[comm] = count(); }'
```

---

## 注意事项

1. **性能开销**: tracepoints 本身有性能开销，生产环境谨慎使用
2. **buffer 大小**: 高频事件可能需要增加 perf buffer 大小
3. **权限**: 需要 root 权限或 CAP_PERFMON 能力
4. **内核版本**: 某些 tracepoints 在旧内核中可能不存在
5. **数据过滤**: 建议使用过滤器减少数据量

---

## 参考资源

- Linux 内核文档: `Documentation/trace/events.rst`
- Tracepoints 定义: `/sys/kernel/debug/tracing/events/`
- BPFtrace 参考指南: https://github.com/iovisor/bpftrace
- Perf 工具文档: https://perf.wiki.kernel.org/
