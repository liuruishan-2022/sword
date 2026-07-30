# Sword Socket Lifecycle Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 防止关闭连接遗留的 eBPF socket 状态污染复用该内核地址的新连接。

**Architecture:** 保持现有以 `sock *` 为键的请求关联方式，在 TCP 状态切换到
`TCP_CLOSE` 时统一清除全部 socket 级请求状态。通过源码约束测试和 26 机器上的
真实 socket 生命周期验证确认修复有效。

**Tech Stack:** Rust、Aya eBPF、Linux `sock:inet_sock_set_state` tracepoint、Cargo。

## Global Constraints

- 只修改 Sword 工程。
- 不修改或提交 `deployment.yaml`。
- 不改变 500ms 慢请求阈值。
- 不改变 Keep-Alive 正常请求的首报文计时语义。

---

### Task 1: Socket 关闭清理回归测试

**Files:**
- Create: `sword/tests/socket_lifecycle_source.rs`
- Test: `sword/tests/socket_lifecycle_source.rs`

**Interfaces:**
- Consumes: `sword-ebpf/src/network/tcp.rs` 中的 socket 状态 Map 名称。
- Produces: 回归约束 `cleanup_socket_request_state` 必须清理四类状态。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tcp_close_cleans_all_socket_request_state() {
    let source = include_str!("../../sword-ebpf/src/network/tcp.rs");
    let cleanup = source.split("fn cleanup_socket_request_state").nth(1)
        .expect("socket cleanup helper must exist");
    for map in ["TCP_REQUEST_START", "TCP_PAYLOAD_ARRIVAL",
                "TCP_ACTIVE_FLOWS", "HTTP_REQUEST_HEADS"] {
        assert!(cleanup.contains(&format!("{map}.remove(&socket_key)")));
    }
    assert!(source.contains("cleanup_socket_request_state(skaddr);"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sword --test socket_lifecycle_source`

Expected: FAIL，提示 `socket cleanup helper must exist`。

### Task 2: TCP_CLOSE 完整清理

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Test: `sword/tests/socket_lifecycle_source.rs`

**Interfaces:**
- Consumes: `socket_key: u64`。
- Produces: `cleanup_socket_request_state(socket_key: u64)`。

- [ ] **Step 1: Add the minimal cleanup helper**

```rust
fn cleanup_socket_request_state(socket_key: u64) {
    let _ = TCP_REQUEST_START.remove(&socket_key);
    let _ = TCP_PAYLOAD_ARRIVAL.remove(&socket_key);
    let _ = TCP_ACTIVE_FLOWS.remove(&socket_key);
    let _ = HTTP_REQUEST_HEADS.remove(&socket_key);
}
```

- [ ] **Step 2: Use the helper on TCP_CLOSE**

```rust
if new_state == BPF_TCP_CLOSE {
    cleanup_socket_request_state(skaddr);
}
```

- [ ] **Step 3: Run focused and workspace tests**

Run: `cargo test -p sword --test socket_lifecycle_source && cargo test --workspace`

Expected: PASS。

### Task 3: 26 机器运行验证

**Files:** none

- [ ] **Step 1:** Run `bash build.sh sword`，确认镜像构建成功。
- [ ] **Step 2:** 执行短连接、Keep-Alive、请求未读即关闭后的新连接测试。
- [ ] **Step 3:** 检查新请求不继承旧时间戳，`requestId` 与耗时对应。
- [ ] **Step 4:** 确认 `deployment.yaml` 未进入本次提交。
