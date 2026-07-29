# Risk Socket-to-XNIO Latency Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将现有 `arrival-to-read` 拆成 TCP payload 到 epoll 返回、epoll 返回到 `tcp_recvmsg` 入口、`tcp_recvmsg` 执行三个阶段，并在慢调度日志中标识 XNIO I/O/worker 线程。

**Architecture:** 使用目标内核已有的 epoll syscall tracepoint 按 TID 记录最近一次有效事件返回时间；`tcp_recvmsg` 入口通过当前 TID 取走该时间并与 socket 对应的 payload 到达时间关联。首次成功读取把四个时间点固化到 socket 请求上下文，`tcp_sendmsg` 输出组合慢请求；聚合指标不使用 PID、TID、端口或 socket 标签。

**Tech Stack:** Rust 2024、Aya/Aya eBPF、Linux tracepoint/kprobe、Prometheus client、Cargo workspace。

## Global Constraints

- 仅采集 `RISK_TARGET_CONFIG` 和目标 TID Map 命中的 Risk 进程。
- 只处理本地服务端口 `SWORD_TARGET_PORT`，默认 `8080`。
- 慢阶段阈值沿用 `SWORD_SLOW_THRESHOLD_MS`，默认 `100ms`。
- 组合慢请求阈值保持 `500ms`。
- 不解析 epoll ready-list，不采集报文正文、手机号或 Header。
- `requestId` 提取失败时仍保留和输出阶段耗时。
- 保留工作树中既有的 `deployment.yaml` 修改。

---

### Task 1: 公共时间模型与日志格式

**Files:**
- Modify: `sword-common/src/lib.rs`
- Modify: `sword/src/metrics/network.rs`
- Modify: `sword/src/metrics/cpu.rs`

**Interfaces:**
- Produces: `RequestTimings::from_phase_timestamps(arrival_ns, epoll_exit_ns, recv_enter_ns, read_ns, write_ns)`
- Produces: `SlowTcpEvent` 的 `arrival_to_epoll_ns`、`epoll_to_recv_ns`、`recv_duration_ns`
- Produces: `thread_role(comm: &[u8]) -> &'static str`

- [ ] **Step 1: 写失败测试**

在 `sword-common/src/lib.rs` 增加测试，要求五个时间点计算：

```rust
let timings = RequestTimings::from_phase_timestamps(1_000, 11_000, 31_000, 51_000, 651_000);
assert_eq!(timings.arrival_to_epoll_ns, 10_000);
assert_eq!(timings.epoll_to_recv_ns, 20_000);
assert_eq!(timings.recv_duration_ns, 20_000);
assert_eq!(timings.read_to_write_ns, 600_000);
assert_eq!(timings.arrival_to_write_ns, 650_000);
```

在用户态日志测试中要求组合日志包含
`arrival_to_epoll_ms`、`epoll_to_recv_ms`、`recv_duration_ms`，调度日志包含
`thread_role=xnio-io` 或 `thread_role=xnio-worker`。

- [ ] **Step 2: 运行测试确认 RED**

Run: `cargo test -p sword-common -p sword`

Expected: FAIL，缺少新字段、构造函数和线程角色。

- [ ] **Step 3: 最小实现公共 ABI 与格式化**

扩展 `RequestTimings` 和 `SlowTcpEvent`，保留 `#[repr(C)]`；使用
`saturating_sub`，无有效 epoll 时间时三个新增 epoll 阶段保持 `0`。格式化函数输出：

```text
target http slow requestId=... arrival_to_epoll_ms=... epoll_to_recv_ms=...
recv_duration_ms=... read_to_write_ms=... arrival_to_write_ms=...
```

调度日志按线程名前缀分类：

```rust
fn thread_role(comm: &str) -> &'static str {
    if comm.starts_with("XNIO-1 I/O-") { "xnio-io" }
    else if comm.starts_with("XNIO-1 task-") { "xnio-worker" }
    else { "other" }
}
```

- [ ] **Step 4: 运行测试确认 GREEN**

Run: `cargo test -p sword-common -p sword`

Expected: PASS。

### Task 2: epoll Tracepoint 和 recvmsg 分段关联

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/network.rs`

**Interfaces:**
- Consumes: Task 1 的 `RequestTimings` 和 `SlowTcpEvent`
- Produces: eBPF 程序 `sys_enter_epoll_wait`、`sys_exit_epoll_wait`、`sys_enter_epoll_pwait`、`sys_exit_epoll_pwait`
- Produces: `EPOLL_WAIT_ENTER_NS`、`EPOLL_EVENT_EXIT_NS` 两个按 TID Map

- [ ] **Step 1: 写失败测试**

在 `sword/src/loader/network.rs` 增加测试，要求 tracepoint 配置同时包含四个 epoll
事件，并验证 category 为 `syscalls`。

- [ ] **Step 2: 运行测试确认 RED**

Run: `cargo test -p sword loader::network`

Expected: FAIL，tracepoint 列表中缺少 epoll 程序。

- [ ] **Step 3: 实现 epoll 探针**

`sys_enter_epoll_*` 只对目标 TID记录当前单调时钟；`sys_exit_epoll_*` 读取 offset 16
的 `ret`，仅在 `ret > 0` 时保存 `EPOLL_EVENT_EXIT_NS[tid]`。入口状态在退出时删除。

扩展：

```rust
struct TcpRecvInflight {
    socket_key: u64,
    user_buffer: u64,
    buffer_len: u64,
    recv_enter_ns: u64,
    epoll_exit_ns: u64,
}

struct TcpRequestContext {
    arrival_ns: u64,
    epoll_exit_ns: u64,
    recv_enter_ns: u64,
    read_ns: u64,
}
```

`tcp_recvmsg` 入口读取并移除当前 TID 最近一次 epoll 返回；首次成功返回时固化时间，
分别按阈值输出新增阶段事件，后续读取不覆盖首次时间。

- [ ] **Step 4: 运行 Loader 测试和 eBPF 编译**

Run: `cargo test -p sword loader::network`

Expected: PASS。

Run: `cargo build -p sword-ebpf --release`

Expected: exit 0，无 verifier/编译错误。

### Task 3: Prometheus 指标、完整回归与镜像

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/metrics/network.rs`
- Verify: `deployment.yaml`

**Interfaces:**
- Consumes: Task 2 新增的 eBPF counter 索引
- Produces: 三个阶段的累计耗时和慢事件累计指标

- [ ] **Step 1: 写失败测试**

扩展 `exports_target_tcp_transport_metrics`，要求输出：

```text
sword_target_tcp_arrival_to_epoll_latency_ns_total
sword_target_tcp_arrival_to_epoll_slow_total
sword_target_tcp_epoll_to_recv_latency_ns_total
sword_target_tcp_epoll_to_recv_slow_total
sword_target_tcp_recv_duration_ns_total
sword_target_tcp_recv_duration_slow_total
```

- [ ] **Step 2: 运行测试确认 RED**

Run: `cargo test -p sword metrics::network`

Expected: FAIL，指标尚未注册。

- [ ] **Step 3: 实现无高基数指标**

扩展 `RISK_TCP_COUNTERS` 固定索引、用户态 `NetworkMetrics` 注册和
`NetworkCollector::collect()` 读取；只输出全局累计值。

- [ ] **Step 4: 完整验证**

Run: `cargo fmt --all -- --check`

Run: `cargo test --workspace`

Run: `cargo build -p sword --release`

Expected: 所有命令 exit 0，测试无失败。

- [ ] **Step 5: 检查变更范围并提交**

Run: `git diff --check`

Run: `git status --short`

确认只包含本计划代码、文档，以及用户原有的 `deployment.yaml` 修改。代码提交时不把
原有 `deployment.yaml` 加入提交。

- [ ] **Step 6: 构建推送镜像**

Run: `bash build.sh sword`

Expected: Cargo release 构建、Docker build、push 均成功；最终输出
`xwharbor.wxchina.com/cpaas/component/sword:v0.1.0-<commit前10位>`。
