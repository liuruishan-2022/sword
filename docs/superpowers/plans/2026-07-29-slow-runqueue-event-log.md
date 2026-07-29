# Slow Runqueue Event Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为达到慢阈值的目标线程调度事件输出可与 TCP 慢事件对齐的逐事件日志。

**Architecture:** eBPF 在现有 `sched_switch` 路径确认 runqueue latency 达到阈值后，将固定长度的 `SlowSchedEvent` 写入独立 RingBuf。用户态异步读取、校验事件长度并输出 WARN 日志；现有 Prometheus 聚合指标保持不变。

**Tech Stack:** Rust、Aya/Aya eBPF、Tokio、Prometheus client。

## Global Constraints

- 只上报达到 `SWORD_SLOW_THRESHOLD_MS` 的事件。
- 日志包含 `tid`、`comm`、`wakeup_ns`、`switch_in_ns`、`latency_ms`。
- 不给 Prometheus 增加 TID 标签。
- 不修改现有 TCP 慢事件格式。
- 保留当前未提交的 `deployment.yaml`。

---

### Task 1: 慢调度事件契约及日志格式

**Files:**
- Modify: `sword-common/src/lib.rs`
- Modify: `sword/src/metrics/cpu.rs`

**Interfaces:**
- Produces: `SlowSchedEvent`
- Produces: `decode_slow_sched_event(&[u8]) -> Option<SlowSchedEvent>`
- Produces: `format_slow_sched_event(&SlowSchedEvent) -> String`

- [ ] **Step 1: Write the failing test**

新增测试，构造 `SlowSchedEvent` 字节并断言解码成功，同时断言格式化结果包含：

```text
tid=3770977 comm=XNIO-1 I/O-3 wakeup_ns=1000000 switch_in_ns=151000000 latency_ms=150.000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sword metrics::cpu::tests::decodes_and_formats_slow_sched_event`

Expected: FAIL，因为 `SlowSchedEvent` 和格式化函数尚不存在。

- [ ] **Step 3: Write minimal implementation**

在公共 crate 增加固定布局事件结构和 `aya::Pod` 实现；在用户态增加严格长度校验、线程名解码和日志格式化。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sword metrics::cpu::tests::decodes_and_formats_slow_sched_event`

Expected: PASS。

### Task 2: eBPF 上报与用户态消费

**Files:**
- Modify: `sword-ebpf/src/cpu/sched.rs`
- Modify: `sword/src/metrics/mod.rs`

**Interfaces:**
- Consumes: `SlowSchedEvent`
- Produces: eBPF map `SLOW_SCHED_EVENTS`

- [ ] **Step 1: Write the failing test**

新增用户态事件读取器接线后运行 workspace 检查，以未定义 eBPF Map 验证接线尚未完成。

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo check -p sword`

Expected: FAIL，因为 `SLOW_SCHED_EVENTS` 尚未由 eBPF 对象提供。

- [ ] **Step 3: Write minimal implementation**

在超过慢阈值的分支写入 `SlowSchedEvent`；用户态从 eBPF 对象取出独立 RingBuf，并异步输出格式化 WARN 日志。

- [ ] **Step 4: Run tests and build**

Run:

```bash
cargo test -p sword
cargo test -p sword-common
bash build.sh sword
```

Expected: 全部成功，生成新的 Sword 镜像。
