# Sword HTTP Request Latency Correlation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 Sword 在 HTTP/1.1 Keep-Alive 下只输出真实慢请求，并把请求级耗时关联到正确的 `requestId`。

**Architecture:** eBPF 继续在第一次成功 `tcp_recvmsg` 与第一次 `tcp_sendmsg` 之间维护单请求上下文，但 HTTP 慢请求判断只使用 `read_to_write_ns`。用户态继续利用同一 ring buffer 中“请求片段先于慢事件”的顺序提取并关联 `requestId`。

**Tech Stack:** Rust、Aya eBPF、Linux kprobe/tracepoint、Cargo test。

## Global Constraints

- 不解析完整 HTTP 协议，不支持 HTTP/2 多路复用。
- 默认只输出请求读取完成到响应开始写出超过 500 ms 的请求。
- 不修改用户已有的 `deployment.yaml`。
- 真实验证必须先在 26 机器完成，之后才能构建镜像。

---

### Task 1: 固化请求级耗时语义

**Files:**
- Modify: `sword-common/src/lib.rs`
- Test: `sword-common/src/lib.rs`

**Interfaces:**
- Consumes: `RequestTimings.read_to_write_ns`
- Produces: `RequestTimings::http_request_latency_ns(&self) -> u64`

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn http_request_latency_ignores_stale_socket_arrival() {
    let timings =
        RequestTimings::from_phase_timestamps(1_000, 11_000, 31_000, 2_051_000, 2_651_000);

    assert_eq!(timings.http_request_latency_ns(), 600_000);
    assert_eq!(timings.arrival_to_write_ns, 2_650_000);
}
```

- [ ] **Step 2: 确认测试失败**

Run: `cargo test -p sword-common http_request_latency_ignores_stale_socket_arrival -- --exact`

Expected: FAIL，提示 `RequestTimings` 不存在 `http_request_latency_ns`。

- [ ] **Step 3: 最小实现**

```rust
impl RequestTimings {
    pub const fn http_request_latency_ns(&self) -> u64 {
        self.read_to_write_ns
    }
}
```

- [ ] **Step 4: 确认测试通过**

Run: `cargo test -p sword-common http_request_latency_ignores_stale_socket_arrival`

Expected: PASS。

### Task 2: HTTP 慢请求使用请求级阈值

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/metrics/network.rs`
- Test: `sword/src/metrics/network.rs`

**Interfaces:**
- Consumes: `RequestTimings::http_request_latency_ns()`
- Produces: `target http slow ... request_read_to_write_ms=...`

- [ ] **Step 1: 写 Keep-Alive 失败测试**

在同一 `socket_key` 上依次记录请求 A、事件 A、请求 B、事件 B；断言第二个事件
使用 B 的 `requestId`，且格式化日志包含
`request_read_to_write_ms=600.000`、不包含 `arrival_to_write_ms=`。

- [ ] **Step 2: 确认测试失败**

Run: `cargo test -p sword correlates_keep_alive_requests_with_request_latency`

Expected: FAIL，因为当前日志仍输出 `arrival_to_write_ms`。

- [ ] **Step 3: 修改 eBPF 慢请求判断**

```rust
let http_request_latency_ns = timings.http_request_latency_ns();
let slow_http = http_request_latency_ns >= HTTP_REQUEST_SLOW_THRESHOLD_NS;
let trace_http = should_trace_http(
    config.flags,
    http_request_latency_ns,
    HTTP_REQUEST_SLOW_THRESHOLD_NS,
);
```

慢事件的 `latency_ns` 写入 `http_request_latency_ns`，保留其余阶段字段作为附加诊断。

- [ ] **Step 4: 修改日志语义**

HTTP 慢日志仅把 `event.latency_ns` 格式化为：

```text
request_read_to_write_ms={:.3}
```

不再输出具有请求总耗时含义的 `arrival_to_write_ms`。

- [ ] **Step 5: 运行单元测试**

Run: `cargo test -p sword-common && cargo test -p sword`

Expected: 全部 PASS。

### Task 3: 26 机器真实 Keep-Alive 验证

**Files:**
- Create: `/tmp/sword-keepalive-validation/` 下的一次性服务端和客户端文件
- Modify: none

**Interfaces:**
- Consumes: 本次构建的 Sword 二进制/eBPF 对象
- Produces: 同一连接上 requestId 与慢耗时对应的验证日志

- [ ] **Step 1: 编译调试产物**

Run: `cargo build -p sword`

Expected: PASS。

- [ ] **Step 2: 启动可控延迟 HTTP 服务**

服务在同一 Keep-Alive 连接上按请求内容执行 20 ms 或 650 ms 延迟，并原样返回
`requestId`。

- [ ] **Step 3: 启动 Sword 全量抓取并发送四个请求**

客户端必须复用一个连接，依次发送 A(20 ms)、B(650 ms)、C(20 ms)、D(650 ms)。

- [ ] **Step 4: 核对日志**

Expected:

```text
target http slow requestId=<B> request_read_to_write_ms≈650
target http slow requestId=<D> request_read_to_write_ms≈650
```

A、C 不得出现慢日志，B、D 不得为空或串号。

### Task 4: 完整验证

**Files:**
- Modify: none

**Interfaces:**
- Consumes: Tasks 1-3 的实现
- Produces: 可构建的 Sword 工作树

- [ ] **Step 1: 格式检查**

Run: `cargo fmt --all -- --check`

Expected: PASS。

- [ ] **Step 2: 工作区测试**

Run: `cargo test --workspace`

Expected: PASS。

- [ ] **Step 3: 检查变更范围**

Run: `git diff --check && git status --short`

Expected: 只包含本次源码/测试/文档，以及用户原有的 `deployment.yaml` 修改。

