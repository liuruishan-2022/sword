# Risk ReadTimeout eBPF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 sword 增加低开销的 Risk ReadTimeout 两阶段诊断：目标线程运行队列延迟、TCP 重传/RST，以及目标服务从成功读取 TCP 数据到开始写响应的慢事件。

**Architecture:** 用户态通过一个统一的目标配置 Map 下发 TGID、服务端口和 100ms 默认慢阈值。eBPF 侧在探针入口最先过滤目标，只在 Map 中累计正常事件，只有超过阈值的 TCP read-to-write 事件才进入 RingBuf；用户态读取 Map 暴露低基数 Prometheus 指标并打印慢事件。

**Tech Stack:** Rust 2024、Aya/Aya eBPF、Linux 5.14 tracepoint/kprobe、Tokio、prometheus-client。

## Global Constraints

- 不读取 HTTP Header、Body、requestId、手机号或短信内容。
- 不实现 `tcp_rcv_established`、抓包、Cilium采集和Kubernetes Pod自动发现。
- 所有高频探针必须首先按目标 TGID/TID 或服务端口过滤。
- 默认慢阈值为 `100ms`，正常 TCP 读写不进入 RingBuf。
- 不修改现有 `deployment.yaml`。

---

### Task 1: 统一目标配置和共享数据结构

**Files:**
- Modify: `sword-common/src/lib.rs`
- Modify: `sword/src/loader/mod.rs`
- Test: `sword/src/loader/mod.rs`

**Interfaces:**
- Produces: `RiskTargetConfig { tgid, server_port, slow_threshold_ns }`
- Produces: `SlowTcpEvent { timestamp_ns, latency_ns, tgid, tid, addresses, ports }`
- Produces: `LoaderOptions { target_pid, server_port, slow_threshold_ms }`

- [ ] **Step 1: 写参数解析失败测试**

覆盖缺少值、非法 PID、非法端口和非法慢阈值：

```rust
assert!(LoaderOptions::parse(["--target-pid", "abc"]).is_err());
assert!(LoaderOptions::parse(["--server-port", "70000"]).is_err());
assert!(LoaderOptions::parse(["--slow-threshold-ms", "0"]).is_err());
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `cargo test -p sword loader::tests --no-default-features`

Expected: FAIL，现有 `LoaderOptions` 不支持 `parse`、端口和慢阈值。

- [ ] **Step 3: 实现最小参数模型**

保留 `parse_args()` 作为进程参数入口，新增可测试的迭代器解析函数。默认值：

```rust
const DEFAULT_SERVER_PORT: u16 = 8080;
const DEFAULT_SLOW_THRESHOLD_MS: u64 = 100;
```

只有设置 `--target-pid` 时才启用专项探针。

- [ ] **Step 4: 增加共享 POD 类型**

所有跨用户态/eBPF类型使用 `#[repr(C)]`、`Copy`，并在 `user` feature 下实现
`aya::Pod`。地址字段保持纯整数，不包含动态内存。

- [ ] **Step 5: 运行测试**

Run: `cargo test -p sword loader::tests --no-default-features`

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add sword-common/src/lib.rs sword/src/loader/mod.rs
git commit -m "feat: add risk tracing target configuration"
```

### Task 2: 第一阶段目标线程运行队列延迟

**Files:**
- Modify: `sword-ebpf/src/cpu/sched.rs`
- Modify: `sword/src/loader/cpu.rs`
- Modify: `sword/src/metrics/cpu.rs`
- Modify: `sword/src/metrics/mod.rs`
- Test: `sword/src/metrics/cpu.rs`

**Interfaces:**
- Consumes: `RiskTargetConfig.slow_threshold_ns`
- Produces Maps: `THREAD_WAKEUP_NS`, `RUNQUEUE_TOTAL`, `RUNQUEUE_TOTAL_NS`, `RUNQUEUE_SLOW_TOTAL`
- Produces metrics: target runqueue event、总纳秒和慢事件计数

- [ ] **Step 1: 写指标标签和累计值测试**

将 Map 原始值转换为无 PID/TID 标签的指标，验证输出包含：

```text
sword_target_thread_runqueue_total
sword_target_thread_runqueue_latency_ns_total
sword_target_thread_runqueue_slow_total
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `cargo test -p sword metrics::cpu::tests --no-default-features`

Expected: FAIL，指标尚不存在。

- [ ] **Step 3: 实现 `sched_wakeup` 和 `sched_wakeup_new`**

从 tracepoint 读取目标 TID；若 TID 不在现有 `SCHED_SWITCH_TARGET_TIDS` Map 中立即返回，
否则在 `THREAD_WAKEUP_NS` 保存 `bpf_ktime_get_ns()`。

- [ ] **Step 4: 扩展 `sched_switch`**

目标线程切入时读取并删除 wakeup 时间，累计事件数、延迟纳秒；超过配置阈值时累计慢
调度次数。使用 PerCpuArray，避免高频原子争用。

- [ ] **Step 5: 加载探针和接入指标**

用户态加载两个新增 tracepoint，取出四个 Map 并追加到现有 OpenMetrics 输出。

- [ ] **Step 6: 运行格式化和测试**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p sword metrics::cpu::tests --no-default-features`

Expected: PASS。

- [ ] **Step 7: 提交**

```bash
git add sword-ebpf/src/cpu/sched.rs sword/src/loader/cpu.rs sword/src/metrics/cpu.rs sword/src/metrics/mod.rs
git commit -m "feat: measure target thread runqueue latency"
```

### Task 3: 第一阶段 TCP 重传和 RST 计数

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/network.rs`
- Modify: `sword/src/metrics/network.rs`
- Modify: `sword/src/metrics/mod.rs`
- Test: `sword/src/metrics/network.rs`

**Interfaces:**
- Consumes: `RiskTargetConfig.server_port`
- Produces Map: `RISK_TCP_COUNTERS`
- Produces metrics: retransmit、receive reset、send reset

- [ ] **Step 1: 写TCP计数到指标输出测试**

验证指标名称和数值：

```text
sword_target_tcp_retransmit_total 3
sword_target_tcp_receive_reset_total 2
sword_target_tcp_send_reset_total 1
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `cargo test -p sword metrics::network::tests --no-default-features`

Expected: FAIL，专项TCP指标尚不存在。

- [ ] **Step 3: 实现三个tracepoint计数**

实现 `tcp_retransmit_skb`、`tcp_receive_reset`，并把现有 `tcp_send_reset` 从逐事件日志
改为目标端口计数。按目标本地服务端口过滤后增加对应 PerCpuArray 下标。

- [ ] **Step 4: 加载探针和接入指标**

为三个tracepoint建立显式加载项，用户态读取 `RISK_TCP_COUNTERS` 并输出低基数Counter。

- [ ] **Step 5: 运行格式化和测试**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p sword metrics::network::tests --no-default-features`

Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add sword-ebpf/src/network/tcp.rs sword/src/loader/network.rs sword/src/metrics/network.rs sword/src/metrics/mod.rs
git commit -m "feat: count target tcp retransmits and resets"
```

### Task 4: 第二阶段 TCP read-to-write 慢事件

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/network.rs`
- Modify: `sword/src/metrics/network.rs`
- Modify: `sword/src/metrics/mod.rs`
- Test: `sword/src/metrics/network.rs`

**Interfaces:**
- Consumes: `RiskTargetConfig`
- Produces Maps: `TCP_RECV_INFLIGHT`, `TCP_REQUEST_START`, `SLOW_TCP_EVENTS`
- Produces metrics: TCP读取、写入、慢read-to-write和RingBuf丢弃计数

- [ ] **Step 1: 写慢事件解码和日志字段测试**

给定一个 `SlowTcpEvent` 字节切片，验证用户态仅输出耗时、进程线程和地址元数据，不
包含任何payload字段。

- [ ] **Step 2: 运行测试并确认失败**

Run: `cargo test -p sword metrics::network::tests --no-default-features`

Expected: FAIL，慢事件解码函数尚不存在。

- [ ] **Step 3: 完成 `tcp_recvmsg` 入口和返回探针**

入口按目标 TGID、本地服务端口过滤，以 TID 保存 socket；返回点读取实际返回值，
只有返回字节数大于0时才按socket保存成功读取时间并增加读取计数。

- [ ] **Step 4: 完成 `tcp_sendmsg` 慢阈值计算**

按目标 TGID和端口过滤，增加写入计数；若同一socket存在读取时间，则计算
read-to-write耗时并删除状态。只有耗时大于等于阈值时写RingBuf，否则不产生事件。
RingBuf满时增加丢弃计数。

- [ ] **Step 5: 用户态异步读取慢事件**

通过 `aya::maps::RingBuf` 和 `tokio::io::unix::AsyncFd` 消费事件，以一条WARN日志输出
元数据；同时从计数Map暴露读取、写入、慢事件和丢弃指标。

- [ ] **Step 6: 运行格式化、测试和完整构建**

Run: `cargo fmt --all -- --check`

Run: `cargo test -p sword --no-default-features`

Run: `cargo build -p sword --release`

Expected: 全部PASS，release构建成功生成 `target/release/sword`。

- [ ] **Step 7: 提交**

```bash
git add sword-common/src/lib.rs sword-ebpf/src/network/tcp.rs sword/src/loader/network.rs sword/src/metrics/network.rs sword/src/metrics/mod.rs
git commit -m "feat: report slow target tcp read to write latency"
```

### Task 5: 兼容性和性能验证

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `sword --target-pid PID --server-port 8080 --slow-threshold-ms 100`
- Produces: 可重复的短时诊断运行说明

- [ ] **Step 1: 在README记录运行命令和输出边界**

明确目标PID必须是宿主机TGID、默认端口8080、默认慢阈值100ms，以及不采集报文内容。

- [ ] **Step 2: 在5.14节点检查探针存在**

Run:

```bash
grep -E 'sched_wakeup|sched_switch|tcp_retransmit_skb|tcp_receive_reset|tcp_send_reset' \
  /sys/kernel/tracing/available_events
```

Expected: 五类事件均存在；缺失项在验收记录中明确标记。

- [ ] **Step 3: 执行短时功能验证**

正常请求不产生慢事件；人工增加超过100ms处理延迟后产生慢事件；指标端点可读取。

- [ ] **Step 4: 执行性能A/B**

同一压测脚本依次运行未启用和启用采集场景，记录TPS、p99和Node CPU。若调度探针
造成不可接受影响，关闭调度探针后重测TCP诊断。

- [ ] **Step 5: 提交文档**

```bash
git add README.md
git commit -m "docs: add risk read timeout tracing guide"
```

### Task 6: DaemonSet CMDLINE 自动发现

**Files:**
- Modify: `sword-common/src/lib.rs`
- Modify: `sword-ebpf/src/common/mod.rs`
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/mod.rs`
- Modify: `sword/src/loader/cpu.rs`
- Modify: `sword/src/loader/network.rs`
- Modify: `deployment.yaml`
- Modify: `README.md`
- Test: `sword/src/loader/mod.rs`
- Test: `sword/src/loader/cpu.rs`

**Interfaces:**
- Consumes env: `SWORD_TARGET_CMDLINE`, `SWORD_TARGET_PORT`,
  `SWORD_SLOW_THRESHOLD_MS`
- Produces map: `RISK_TARGET_TGIDS: HashMap<u32, u8>`
- Produces discovery: `SchedSwitchTarget::Cmdline(String)`
- Preserves CLI: `--target-pid`, `--server-port`, `--slow-threshold-ms`

- [ ] **Step 1: 写环境变量解析失败和覆盖测试**

验证 CMDLINE、端口和阈值进入 `LoaderOptions`，非法端口和阈值返回错误，CLI值覆盖环境
变量值。

- [ ] **Step 2: 运行参数测试并确认失败**

Run:

```bash
cargo test -p sword loader::tests --no-default-features \
  --config 'target."cfg(all())".runner="env"'
```

Expected: FAIL，`LoaderOptions` 尚无 `target_cmdline` 和环境变量解析入口。

- [ ] **Step 3: 实现最小环境变量解析**

`LoaderOptions::parse_with_env` 先读取以下默认配置，再用CLI覆盖：

```text
SWORD_TARGET_CMDLINE
SWORD_TARGET_PORT=8080
SWORD_SLOW_THRESHOLD_MS=100
```

空CMDLINE视为未配置；端口和阈值必须是大于0的整数。

- [ ] **Step 4: 写CMDLINE进程发现测试**

把NUL分隔的命令行解析为参数，验证
`java\0-jar\0content-risk-control-service.jar\0`命中，其他Jar不命中；验证一次刷新同时
产生TGID集合和TID集合。

- [ ] **Step 5: 运行发现测试并确认失败**

Run:

```bash
cargo test -p sword loader::cpu::tests --no-default-features \
  --config 'target."cfg(all())".runner="env"'
```

Expected: FAIL，`SchedSwitchTarget::Cmdline` 尚不存在。

- [ ] **Step 6: 实现动态TGID/TID刷新**

扩展现有5秒刷新器，使其同时维护：

```text
RISK_TARGET_TGIDS: tgid -> 1
SCHED_SWITCH_TARGET_TIDS: tid -> 1
```

扫描错误只记录WARN并保留或清理可确认的旧集合；零匹配不是启动失败。

- [ ] **Step 7: 调整eBPF目标过滤**

TCP读写首先使用当前TGID查询 `RISK_TARGET_TGIDS`，命中后再读取socket并检查本地端口。
全局配置Map始终写入端口和慢阈值，避免未配置时使用零值阈值。

- [ ] **Step 8: 更新DaemonSet配置**

将示例目标改为：

```yaml
- name: SWORD_TARGET_CMDLINE
  value: "content-risk-control-service.jar"
- name: SWORD_TARGET_PORT
  value: "8080"
- name: SWORD_SLOW_THRESHOLD_MS
  value: "100"
```

- [ ] **Step 9: 运行完整验证**

Run:

```bash
cargo fmt --all -- --check
cargo test -p sword --no-default-features \
  --config 'target."cfg(all())".runner="env"'
cargo build -p sword --release
```

Expected: 全部测试PASS，release构建成功。

- [ ] **Step 10: 提交**

```bash
git add sword-common sword-ebpf/src/common/mod.rs sword-ebpf/src/network/tcp.rs \
  sword/src/loader deployment.yaml README.md
git commit -m "feat: discover daemonset targets by cmdline"
```
