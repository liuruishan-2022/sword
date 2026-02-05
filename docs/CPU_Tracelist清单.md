# CPU Tracepoint 完整清单

本文档列出了从 `tp.data` 中提取的所有 CPU 相关 tracepoints，共 97 个。

## 1. sched (28 个)

### 进程切换和唤醒
- tracepoint:sched:sched_switch
- tracepoint:sched:sched_wakeup
- tracepoint:sched:sched_wakeup_new
- tracepoint:sched:sched_waking
- tracepoint:sched:sched_wait_task

### 进程生命周期
- tracepoint:sched:sched_process_fork
- tracepoint:sched:sched_process_exec
- tracepoint:sched:sched_process_exit
- tracepoint:sched:sched_process_free
- tracepoint:sched:sched_process_wait

### CPU 迁移和 NUMA
- tracepoint:sched:sched_migrate_task
- tracepoint:sched:sched_move_numa
- tracepoint:sched:sched_stick_numa
- tracepoint:sched:sched_swap_numa
- tracepoint:sched:sched_skip_vma_numa

### 调度统计
- tracepoint:sched:sched_stat_runtime
- tracepoint:sched:sched_stat_wait
- tracepoint:sched:sched_stat_sleep
- tracepoint:sched:sched_stat_blocked
- tracepoint:sched:sched_stat_iowait

### 优先级和策略
- tracepoint:sched:sched_pi_setprio
- tracepoint:sched:sched_wake_idle_without_ipi

### 内核线程
- tracepoint:sched:sched_kthread_stop
- tracepoint:sched:sched_kthread_stop_ret
- tracepoint:sched:sched_kthread_work_queue_work
- tracepoint:sched:sched_kthread_work_execute_start
- tracepoint:sched:sched_kthread_work_execute_end

### 异常情况
- tracepoint:sched:sched_process_hang

---

## 2. power (24 个)

### CPU 频率
- tracepoint:power:cpu_frequency
- tracepoint:power:cpu_frequency_limits
- tracepoint:power:pstate_sample

### CPU 空闲状态
- tracepoint:power:cpu_idle
- tracepoint:power:cpu_idle_miss

### 时钟管理
- tracepoint:power:clock_enable
- tracepoint:power:clock_disable
- tracepoint:power:clock_set_rate

### 设备电源管理
- tracepoint:power:device_pm_callback_start
- tracepoint:power:device_pm_callback_end
- tracepoint:power:suspend_resume
- tracepoint:power:wakeup_source_activate
- tracepoint:power:wakeup_source_deactivate

### 电源服务质量 (QoS)
- tracepoint:power:pm_qos_add_request
- tracepoint:power:pm_qos_remove_request
- tracepoint:power:pm_qos_update_request
- tracepoint:power:pm_qos_update_flags
- tracepoint:power:pm_qos_update_target

### 设备 QoS
- tracepoint:power:dev_pm_qos_add_request
- tracepoint:power:dev_pm_qos_remove_request
- tracepoint:power:dev_pm_qos_update_request

### 其他
- tracepoint:power:guest_halt_poll_ns
- tracepoint:power:power_domain_target
- tracepoint:power:powernv_throttle

---

## 3. irq_vectors (34 个)

### 调度相关
- tracepoint:irq_vectors:reschedule_entry
- tracepoint:irq_vectors:reschedule_exit

### 函数调用
- tracepoint:irq_vectors:call_function_entry
- tracepoint:irq_vectors:call_function_exit
- tracepoint:irq_vectors:call_function_single_entry
- tracepoint:irq_vectors:call_function_single_exit

### 定时器
- tracepoint:irq_vectors:local_timer_entry
- tracepoint:irq_vectors:local_timer_exit

### 错误处理
- tracepoint:irq_vectors:error_apic_entry
- tracepoint:irq_vectors:error_apic_exit
- tracepoint:irq_vectors:spurious_apic_entry
- tracepoint:irq_vectors:spurious_apic_exit
- tracepoint:irq_vectors:deferred_error_apic_entry
- tracepoint:irq_vectors:deferred_error_apic_exit

### 热管理
- tracepoint:irq_vectors:thermal_apic_entry
- tracepoint:irq_vectors:thermal_apic_exit
- tracepoint:irq_vectors:threshold_apic_entry
- tracepoint:irq_vectors:threshold_apic_exit

### 工作队列
- tracepoint:irq_vectors:irq_work_entry
- tracepoint:irq_vectors:irq_work_exit

### 向量管理
- tracepoint:irq_vectors:vector_activate
- tracepoint:irq_vectors:vector_alloc
- tracepoint:irq_vectors:vector_alloc_managed
- tracepoint:irq_vectors:vector_clear
- tracepoint:irq_vectors:vector_config
- tracepoint:irq_vectors:vector_deactivate
- tracepoint:irq_vectors:vector_free_moved
- tracepoint:irq_vectors:vector_reserve
- tracepoint:irq_vectors:vector_reserve_managed
- tracepoint:irq_vectors:vector_setup
- tracepoint:irq_vectors:vector_teardown
- tracepoint:irq_vectors:vector_update

### 平台特定
- tracepoint:irq_vectors:x86_platform_ipi_entry
- tracepoint:irq_vectors:x86_platform_ipi_exit

---

## 4. ipi (5 个)

- tracepoint:ipi:ipi_entry
- tracepoint:ipi:ipi_exit
- tracepoint:ipi:ipi_raise
- tracepoint:ipi:ipi_send_cpu
- tracepoint:ipi:ipi_send_cpumask

---

## 5. cpuhp (3 个)

- tracepoint:cpuhp:cpuhp_enter
- tracepoint:cpuhp:cpuhp_exit
- tracepoint:cpuhp:cpuhp_multi_enter

---

## 6. context_tracking (2 个)

- tracepoint:context_tracking:user_enter
- tracepoint:context_tracking:user_exit

---

## 7. amd_cpu (1 个)

- tracepoint:amd_cpu:amd_pstate_perf

---

## 统计总结

| 类别 | 数量 |
|------|------|
| irq_vectors | 34 |
| sched | 28 |
| power | 24 |
| ipi | 5 |
| cpuhp | 3 |
| context_tracking | 2 |
| amd_cpu | 1 |
| **总计** | **97** |

---

## 快速查询

### 查看所有可用的 CPU tracepoints
```bash
# 在系统上查看
ls /sys/kernel/debug/tracing/events/sched/
ls /sys/kernel/debug/tracing/events/power/
ls /sys/kernel/debug/tracing/events/irq_vectors/
```

### 使用 bpftrace 列出
```bash
bpftrace -l 'tracepoint:sched:*'
bpftrace -l 'tracepoint:power:*'
bpftrace -l 'tracepoint:irq_vectors:*'
```

### 使用 perf 列出
```bash
perf list 'sched:*'
perf list 'power:*'
perf list 'irq_vectors:*'
```

---

## 相关文档

- [CPU的Tracepoint跟踪.md](./CPU的Tracepoint跟踪.md) - 详细的使用指南和示例
- [tracepoints_classified.md](./tracepoints_classified.md) - 所有 tracepoints 的完整分类
- [tp.data](./tp.data) - 原始的 tracepoint 数据
