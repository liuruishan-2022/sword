#!/usr/bin/env python3
"""
Tracepoint 分类脚本
将 Linux tracepoints 按照功能模块进行分类
"""

import re
from collections import defaultdict
from pathlib import Path


def get_category_mapping():
    """
    返回 tracepoint category 到功能分类的映射
    """
    return {
        # 内存管理
        "kmem": "内存管理",
        "compaction": "内存管理",
        "migrate": "内存管理",
        "vmscan": "内存管理",
        "huge_memory": "内存管理",
        "thp": "内存管理",
        "ksm": "内存管理",
        "page_isolation": "内存管理",
        "pagemap": "内存管理",
        "oom": "内存管理",
        "percpu": "内存管理",
        "maple_tree": "内存管理",

        # CPU 和调度
        "sched": "CPU和调度",
        "cpuhp": "CPU和调度",
        "ipi": "CPU和调度",
        "irq_vectors": "CPU和调度",
        "power": "CPU和调度",
        "cpu_idle": "CPU和调度",
        "context_tracking": "CPU和调度",
        "cros_ec": "CPU和调度",

        # 中断和锁
        "irq": "中断和锁",
        "irq_matrix": "中断和锁",
        "nmi": "中断和锁",
        "lock": "中断和锁",
        "rcu": "中断和锁",
        "csd": "中断和锁",

        # 文件系统和 VFS
        "ext4": "文件系统",
        "jbd2": "文件系统",
        "filemap": "文件系统",
        "filelock": "文件系统",
        "writeback": "文件系统",
        "fs_dax": "文件系统",
        "iomap": "文件系统",

        # 系统调用
        "syscalls": "系统调用",
        "raw_syscalls": "系统调用",

        # 网络协议栈
        "net": "网络",
        "tcp": "网络",
        "udp": "网络",
        "sock": "网络",
        "skb": "网络",
        "neigh": "网络",
        "bridge": "网络",
        "icmp": "网络",
        "fib": "网络",
        "fib6": "网络",
        "napi": "网络",
        "mptcp": "网络",
        "handshake": "网络",

        # 存储和块设备
        "block": "存储",
        "libata": "存储",
        "scsi": "存储",
        "sd": "存储",
        "nvme": "存储",
        "mmc": "存储",

        # I/O 和异步
        "io_uring": "异步I/O",

        # 进程和任务
        "task": "进程管理",
        "signal": "进程管理",
        "mmap": "进程管理",
        "mmap_lock": "进程管理",
        "module": "进程管理",
        "initcall": "进程管理",
        "exceptions": "进程管理",

        # 虚拟化
        "kvm": "虚拟化",
        "kvmmmu": "虚拟化",
        "xen": "虚拟化",
        "hyperv": "虚拟化",

        # 设备驱动
        "i915": "设备驱动",
        "drm": "设备驱动",
        "gpu_scheduler": "设备驱动",
        "xe": "设备驱动",
        "x86_fpu": "设备驱动",
        "xdp": "设备驱动",
        "dma_fence": "设备驱动",

        # 硬件接口
        "gpio": "硬件接口",
        "i2c": "硬件接口",
        "spi": "硬件接口",
        "smbus": "硬件接口",
        "mmc": "硬件接口",
        "rtc": "硬件接口",
        "pwm": "硬件接口",
        "timer": "硬件接口",
        "hrtimer": "硬件接口",

        # 音频
        "asoc": "音频",
        "hda": "音频",
        "hda_controller": "音频",
        "hda_intel": "音频",
        "sof": "音频",
        "sof_intel": "音频",

        # 电源管理
        "power": "电源管理",
        "thermal": "电源管理",
        "thermal_power_allocator": "电源管理",
        "suspend_resume": "电源管理",
        "cpuidle": "电源管理",
        "rpm": "电源管理",
        "clk": "电源管理",
        "regulator": "电源管理",
        "devfreq": "电源管理",

        # 内存管理单元
        "iommu": "内存管理单元",
        "intel_iommu": "内存管理单元",

        # BPF
        "bpf_test_run": "BPF",
        "bpf_trace": "BPF",

        # 容器和资源控制
        "cgroup": "容器和资源控制",
        "iocost": "容器和资源控制",
        "resctrl": "容器和资源控制",

        # 安全
        "avc": "安全",

        # 性能工具
        "osnoise": "性能分析",

        # 定时器
        "timer": "定时器",
        "alarmtimer": "定时器",
        "itimer": "定时器",

        # 网络文件系统
        "sunrpc": "网络文件系统",
        "nfs": "网络文件系统",

        # 内存分配
        "vmalloc": "内存分配",
        "swiotlb": "内存分配",

        # TLB
        "tlb": "TLB",

        # 其他内核功能
        "notifier": "内核功能",
        "workqueue": "内核功能",
        "printk": "内核功能",
        "qdisc": "内核功能",
        "regmap": "内核功能",
        "interconnect": "内核功能",
        "wbt": "内核功能",
        "page_pool": "内核功能",
        "msr": "内核功能",
        "rseq": "内核功能",
        "mce": "内核功能",
        "ras": "内核功能",
        "sync_trace": "内核功能",
        "vsyscall": "内核功能",
        "watchdog": "内核功能",
        "error_report": "内核功能",
        "amd_cpu": "内核功能",
        "hwmon": "内核功能",
        "mdio": "内核功能",
        "mei": "内核功能",
        "mctp": "内核功能",
        "devlink": "内核功能",
        "qrtr": "内核功能",
        "netlink": "内核功能",
        "dma_fence": "内核功能",
        "dev": "内核功能",
        "rv": "内核功能",
        "xhci-hcd": "内核功能",
    }


def classify_tracepoints(input_file, output_file):
    """
    分类 tracepoints 并生成分类报告

    Args:
        input_file: 输入的 tp.data 文件路径
        output_file: 输出的分类文件路径
    """
    # 读取 tracepoint 数据
    with open(input_file, 'r') as f:
        lines = f.readlines()

    # 获取分类映射
    category_mapping = get_category_mapping()

    # 按功能分类统计
    classified = defaultdict(lambda: defaultdict(list))
    unclassified = defaultdict(list)

    total_count = 0
    for line in lines:
        line = line.strip()
        if not line or not line.startswith('tracepoint:'):
            continue

        # 解析 tracepoint 格式: tracepoint:category:event_name
        parts = line.split(':')
        if len(parts) >= 3:
            category = parts[1]
            event_name = parts[2]

            total_count += 1

            # 查找分类
            if category in category_mapping:
                functional_category = category_mapping[category]
                classified[functional_category][category].append(event_name)
            else:
                unclassified[category].append(event_name)

    # 生成输出
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Linux Tracepoints 功能分类\n\n")
        f.write(f"总计: {total_count} 个 tracepoints\n")
        f.write(f"已分类: {total_count - sum(len(v) for v in unclassified.values())} 个\n")
        f.write(f"未分类: {sum(len(v) for v in unclassified.values())} 个\n\n")

        # 按功能分类输出
        f.write("## 功能分类统计\n\n")
        sorted_categories = sorted(classified.items(),
                                  key=lambda x: sum(len(v) for v in x[1].values()),
                                  reverse=True)

        for functional_cat, categories in sorted_categories:
            count = sum(len(events) for events in categories.values())
            f.write(f"### {functional_cat}: {count} 个 tracepoints\n\n")

            # 输出该功能下的各个 category
            for cat in sorted(categories.keys()):
                events = sorted(categories[cat])
                f.write(f"#### {cat} ({len(events)} 个)\n\n")
                for event in events[:20]:  # 只显示前20个
                    f.write(f"- {cat}:{event}\n")
                if len(events) > 20:
                    f.write(f"- ... 还有 {len(events) - 20} 个\n")
                f.write("\n")

        # 输出未分类的
        if unclassified:
            f.write("## 未分类的 Tracepoints\n\n")
            for cat in sorted(unclassified.keys()):
                events = sorted(unclassified[cat])
                f.write(f"### {cat} ({len(events)} 个)\n\n")
                for event in events[:10]:
                    f.write(f"- {cat}:{event}\n")
                if len(events) > 10:
                    f.write(f"- ... 还有 {len(events) - 10} 个\n")
                f.write("\n")

        # 生成详细分类清单（用于程序使用）
        f.write("\n## 详细分类清单\n\n")
        f.write("```python\n")
        f.write("# 格式: 功能分类 -> [category:event_name]\n")
        f.write("tracepoint_classification = {\n")
        for functional_cat in sorted(classified.keys()):
            f.write(f"    '{functional_cat}': [\n")
            for cat in sorted(classified[functional_cat].keys()):
                for event in sorted(classified[functional_cat][cat])[:5]:
                    f.write(f"        '{cat}:{event}',\n")
                if len(classified[functional_cat][cat]) > 5:
                    f.write(f"        # ... 还有 {len(classified[functional_cat][cat]) - 5} 个\n")
            f.write(f"    ],\n")
        f.write("}\n")
        f.write("```\n")

    print(f"\n分类完成！")
    print(f"总计: {total_count} 个 tracepoints")
    print(f"已分类: {total_count - sum(len(v) for v in unclassified.values())} 个")
    print(f"未分类: {sum(len(v) for v in unclassified.values())} 个")
    print(f"输出文件: {output_file}")


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    input_file = script_dir / "tp.data"
    output_file = script_dir / "tracepoints_classified.md"

    if not input_file.exists():
        print(f"错误: 找不到输入文件 {input_file}")
        exit(1)

    classify_tracepoints(input_file, output_file)
