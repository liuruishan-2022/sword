# Sword TCP Arrival-to-Read Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure and report the delay from the first TCP payload reaching the Risk server socket to the target process completing its first successful TCP read.

**Architecture:** Attach the existing Sword eBPF object to `tracepoint/tcp/tcp_probe`, retain the first non-empty payload timestamp by normalized flow key, and consume it at `tcp_recvmsg` return. Keep the current socket-keyed read-to-write measurement intact, distinguish the two latency phases in the shared RingBuf event, and export phase-specific counters.

**Tech Stack:** Rust 2024, Aya/Aya eBPF, Linux 5.14 `tcp:tcp_probe`, Tokio, prometheus-client.

## Global Constraints

- Target kernel is `5.14.0-479.el9.x86_64`.
- No fallback is required for kernels without `tcp:tcp_probe`.
- Do not read or emit HTTP payload, headers, request IDs, phone numbers, or message content.
- Filter `tcp_probe` events with `data_len > 0` and local server port equal to `SWORD_TARGET_PORT`.
- Reuse `SWORD_SLOW_THRESHOLD_MS` for both latency phases.
- Keep existing read-to-write metric names and log format semantics.

---

### Task 1: Shared Flow and Event Phase Types

**Files:**
- Modify: `sword-common/src/lib.rs`

**Interfaces:**
- Produces: `TcpFlowKey`, `SLOW_TCP_PHASE_READ_TO_WRITE`, `SLOW_TCP_PHASE_ARRIVAL_TO_READ`.
- Produces: `TcpFlowKey::ipv4(...)` and `TcpFlowKey::ipv6(...)`.
- Changes: `SlowTcpEvent` replaces its two-byte padding with `phase: u8` and one-byte padding while retaining its total layout size.

- [ ] **Step 1: Write failing tests for flow normalization and event layout**

Add tests to `sword-common/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        SLOW_TCP_PHASE_ARRIVAL_TO_READ, SLOW_TCP_PHASE_READ_TO_WRITE, SlowTcpEvent, TcpFlowKey,
    };

    #[test]
    fn builds_ipv4_flow_key_with_zeroed_ipv6_words() {
        let key = TcpFlowKey::ipv4(0x0a000001, 0x0a000002, 8080, 32000);
        assert_eq!(key.family, 2);
        assert_eq!(key.local_addr, [0x0a000001, 0, 0, 0]);
        assert_eq!(key.remote_addr, [0x0a000002, 0, 0, 0]);
        assert_eq!(key.local_port, 8080);
        assert_eq!(key.remote_port, 32000);
    }

    #[test]
    fn builds_ipv6_flow_key_without_reordering_words() {
        let local = [1, 2, 3, 4];
        let remote = [5, 6, 7, 8];
        let key = TcpFlowKey::ipv6(local, remote, 8080, 32000);
        assert_eq!(key.family, 10);
        assert_eq!(key.local_addr, local);
        assert_eq!(key.remote_addr, remote);
    }

    #[test]
    fn slow_event_phases_are_distinct_without_changing_event_size() {
        assert_ne!(
            SLOW_TCP_PHASE_READ_TO_WRITE,
            SLOW_TCP_PHASE_ARRIVAL_TO_READ
        );
        assert_eq!(size_of::<SlowTcpEvent>(), 40);
    }
}
```

- [ ] **Step 2: Run the shared crate tests and verify RED**

Run:

```bash
cargo test -p sword-common
```

Expected: compilation fails because `TcpFlowKey`, constructors, phase constants, and the `phase` field do not exist.

- [ ] **Step 3: Add the minimum shared types**

Add:

```rust
pub const SLOW_TCP_PHASE_READ_TO_WRITE: u8 = 1;
pub const SLOW_TCP_PHASE_ARRIVAL_TO_READ: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub struct TcpFlowKey {
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub family: u16,
    pub _pad: u16,
}

impl TcpFlowKey {
    pub const fn ipv4(local_addr: u32, remote_addr: u32, local_port: u16, remote_port: u16) -> Self {
        Self {
            local_addr: [local_addr, 0, 0, 0],
            remote_addr: [remote_addr, 0, 0, 0],
            local_port,
            remote_port,
            family: 2,
            _pad: 0,
        }
    }

    pub const fn ipv6(
        local_addr: [u32; 4],
        remote_addr: [u32; 4],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            family: 10,
            _pad: 0,
        }
    }
}
```

Change the tail of `SlowTcpEvent` to:

```rust
pub family: u16,
pub phase: u8,
pub _pad: u8,
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
cargo test -p sword-common
```

Expected: all `sword-common` tests pass.

- [ ] **Step 5: Commit**

```bash
git add sword-common/src/lib.rs
git commit -m "feat: add tcp flow and latency phase types"
```

### Task 2: User-Space Phase Logs and Prometheus Counters

**Files:**
- Modify: `sword/src/metrics/network.rs`

**Interfaces:**
- Consumes: `SlowTcpEvent.phase` and phase constants from Task 1.
- Produces metrics:
  - `sword_target_tcp_payload_arrival_total`
  - `sword_target_tcp_arrival_to_read_total`
  - `sword_target_tcp_arrival_to_read_slow_total`
- Produces phase-specific slow log text from `format_slow_tcp_event`.

- [ ] **Step 1: Extend existing tests first**

Change `exports_target_tcp_transport_metrics` to pass ten counters and assert:

```rust
metrics.set_target_tcp_events(10, 9, 8, 7, 6, 5, 4, 3, 2, 1);
assert!(output.contains("sword_target_tcp_payload_arrival_total 3"));
assert!(output.contains("sword_target_tcp_arrival_to_read_total 2"));
assert!(output.contains("sword_target_tcp_arrival_to_read_slow_total 1"));
```

Change the existing event fixture to use `phase: SLOW_TCP_PHASE_READ_TO_WRITE` and assert:

```rust
assert!(line.contains("target tcp read-to-write slow"));
```

Add:

```rust
#[test]
fn formats_arrival_to_read_slow_event() {
    let event = SlowTcpEvent {
        timestamp_ns: 1,
        latency_ns: 250_000_000,
        tgid: 42,
        tid: 43,
        source_addr_v4: u32::from_be_bytes([172, 16, 15, 139]),
        destination_addr_v4: u32::from_be_bytes([172, 16, 1, 30]),
        source_port: 8080,
        destination_port: 54321,
        family: 2,
        phase: SLOW_TCP_PHASE_ARRIVAL_TO_READ,
        _pad: 0,
    };
    let line = format_slow_tcp_event(&event);
    assert!(line.contains("target tcp arrival-to-read slow"));
    assert!(line.contains("latency_ms=250.000"));
}
```

- [ ] **Step 2: Run the Sword tests and verify RED**

Run:

```bash
cargo test -p sword metrics::network
```

Expected: compilation or assertions fail because the exporter still accepts seven counters and always formats `read-to-write`.

- [ ] **Step 3: Implement the minimum exporter changes**

Add three gauges to `NetworkMetrics`, register them with the exact metric names above, add three arguments to `set_target_tcp_events`, and read counter indexes `7`, `8`, and `9` from `NetworkCollector::collect`.

Select the phase text with:

```rust
let phase = match event.phase {
    SLOW_TCP_PHASE_ARRIVAL_TO_READ => "arrival-to-read",
    SLOW_TCP_PHASE_READ_TO_WRITE => "read-to-write",
    _ => "unknown",
};
```

Format:

```rust
"target tcp {phase} slow latency_ms={:.3} ..."
```

- [ ] **Step 4: Run tests and verify GREEN**

Run:

```bash
cargo test -p sword metrics::network
```

Expected: all network metric tests pass.

- [ ] **Step 5: Commit**

```bash
git add sword/src/metrics/network.rs
git commit -m "feat: export tcp arrival to read metrics"
```

### Task 3: Attach `tcp_probe` and Correlate Payload Arrival

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/network.rs`

**Interfaces:**
- Consumes: `TcpFlowKey` and phase constants from Task 1.
- Consumes: `tcp:tcp_probe` offsets verified on kernel 5.14:
  - local port `68`
  - remote port `70`
  - family `72`
  - payload length `80`
  - IPv4 local/remote address `16`/`44`
  - IPv6 local/remote address `20`/`48`
- Produces: `TCP_PAYLOAD_ARRIVAL` and `TCP_ACTIVE_FLOWS` LRU maps.
- Produces: arrival-to-read events and counter indexes `7`, `8`, and `9`.

- [ ] **Step 1: Add a failing loader test**

Extract the tracepoint list in `sword/src/loader/network.rs`:

```rust
fn network_tracepoints() -> Vec<TracePointConfig>
```

Add a test that collects `(category, program, tracepoint)` values and asserts the list contains:

```rust
("tcp", "tcp_probe", "tcp_probe")
```

Run:

```bash
cargo test -p sword loader::network
```

Expected: the assertion fails because `tcp_probe` is not in the loader list.

- [ ] **Step 2: Attach the tracepoint and verify the loader test passes**

Add:

```rust
TracePointConfig::create_tcp("tcp_probe", "tcp_probe"),
```

Run:

```bash
cargo test -p sword loader::network
```

Expected: loader test passes.

- [ ] **Step 3: Implement bounded eBPF flow state**

Increase `RISK_TCP_COUNTERS` entries from `7` to `10`. Add:

```rust
const RISK_TCP_PAYLOAD_ARRIVAL_INDEX: u32 = 7;
const RISK_TCP_ARRIVAL_TO_READ_INDEX: u32 = 8;
const RISK_TCP_ARRIVAL_TO_READ_SLOW_INDEX: u32 = 9;

#[map]
pub static TCP_PAYLOAD_ARRIVAL: LruHashMap<TcpFlowKey, u64> =
    LruHashMap::with_max_entries(32768, 0);

#[map]
pub static TCP_ACTIVE_FLOWS: LruHashMap<TcpFlowKey, u8> =
    LruHashMap::with_max_entries(32768, 0);
```

Add `tcp_probe` tracepoint handling that:

1. reads and validates family, ports, and `data_len`;
2. builds `TcpFlowKey`;
3. increments payload-arrival counter;
4. ignores active flows and existing first-arrival entries;
5. inserts `bpf_ktime_get_ns()` for a new idle flow.

- [ ] **Step 4: Calculate arrival-to-read at successful read**

At `tcp_recvmsg_ret`:

1. rebuild the flow key from the retained socket pointer;
2. insert the active-flow marker;
3. remove the first-arrival timestamp;
4. increment the arrival-to-read sample counter;
5. calculate latency and emit phase `SLOW_TCP_PHASE_ARRIVAL_TO_READ` only when it exceeds the configured threshold;
6. continue the existing read-to-write start logic unchanged.

At `tcp_sendmsg`, clear the flow's active marker before applying the existing socket-keyed read-to-write logic. Emit the existing event with phase `SLOW_TCP_PHASE_READ_TO_WRITE`.

- [ ] **Step 5: Compile the eBPF and workspace**

Run:

```bash
cargo fmt --all -- --check
cargo check -p sword-common
cargo check -p sword
cargo build -p sword --release
```

Expected: all commands succeed without warnings introduced by this change.

- [ ] **Step 6: Commit**

```bash
git add sword-ebpf/src/network/tcp.rs sword/src/loader/network.rs
git commit -m "feat: trace tcp payload arrival to process read"
```

### Task 4: Documentation and Full Verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Documents the two latency phases and three new metrics.

- [ ] **Step 1: Update the tracing documentation**

Document:

```text
arrival-to-read: first non-empty TCP payload observed by tcp_probe until the
target process completes its first successful tcp_recvmsg.

read-to-write: first successful tcp_recvmsg until the target process starts its
first tcp_sendmsg.
```

State that the current build requires the `tcp:tcp_probe` tracepoint and targets
the verified Linux 5.14 test kernel.

- [ ] **Step 2: Run full local verification**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo build -p sword --release
git diff --check
```

Expected: all commands succeed.

- [ ] **Step 3: Verify on the test node**

Deploy the image built from the implementation commit to node
`172.16.15.139`, then verify:

```bash
curl -s http://127.0.0.1:9898/metrics | grep 'sword_target_tcp_.*arrival'
```

Expected: all three new metrics are present.

Generate controlled Risk HTTP traffic and verify logs contain
`target tcp arrival-to-read slow` only when the configured threshold is
exceeded, with no payload content.

- [ ] **Step 4: Commit documentation**

```bash
git add README.md
git commit -m "docs: explain tcp latency phases"
```

