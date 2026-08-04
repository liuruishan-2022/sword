# Remove Risk Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all Risk-specific monitoring code, configuration, metrics, tests, and historical documents while preserving Sword's generic observability behavior and the user's in-progress generic TCP Reset changes.

**Architecture:** Use commit `4ff99b80be1265ce0eb109538e2f7602703c590f` as the read-only pre-Risk baseline for files touched by the Risk feature. Apply baseline-guided edits to the current tree instead of resetting or reverting commits, then retain the current image tag and the uncommitted `tcp_send_active_reset` loader work.

**Tech Stack:** Rust workspace, Aya/Aya eBPF, Linux tracepoints and kprobes, Tokio, Prometheus client, Kubernetes DaemonSet YAML.

## Global Constraints

- Do not reset, revert, or overwrite unrelated working-tree changes.
- Preserve `sword-ebpf/src/network/tcp.rs` and `sword/src/loader/network.rs` user intent; the Risk deletions are superseded by full removal, while `tcp_send_active_reset` remains generic work in progress.
- Preserve generic `SWORD_SCHED_SWITCH_PID` and `SWORD_SCHED_SWITCH_COMM` targeting.
- Preserve generic CPU, I/O, connect, socket, accept, TCP state, and `tcp_send_reset` monitoring.
- Preserve the current deployment image tag `xwharbor.wxchina.com/cpaas/component/sword:v0.1.0-7f7a0d6561`.
- Do not restore the removed `rust-mouse` example Deployment.
- Remove all historical Risk plans and specifications, but keep the approved removal design and this implementation plan.

---

### Task 1: Remove Risk shared models and target discovery

**Files:**
- Modify: `sword-common/src/lib.rs`
- Modify: `sword-ebpf/src/common/mod.rs`
- Modify: `sword-ebpf/src/cpu/sched.rs`
- Modify: `sword/src/loader/cpu.rs`
- Modify: `sword/src/loader/mod.rs`
- Modify: `sword/src/metrics/cpu.rs`

**Interfaces:**
- Consumes: pre-Risk implementations from commit `4ff99b80be1265ce0eb109538e2f7602703c590f`.
- Produces: generic scheduling and loader APIs with no `RiskTargetConfig`, `RISK_TARGET_TGIDS`, `SLOW_SCHED_EVENTS`, or Risk threshold dependency.

- [ ] **Step 1: Capture the failing removal assertions**

Run:

```bash
rg -n 'RiskTarget|RISK_TARGET|risk_target|content-risk-control-service|SWORD_TARGET_|SWORD_SLOW_THRESHOLD|SWORD_HTTP_TRACE_ALL' \
  sword-common sword-ebpf sword/src
```

Expected: matches are present, proving Risk-specific shared and loader code still exists.

- [ ] **Step 2: Restore the shared and CPU boundaries from the pre-Risk baseline**

For each file, compare the current content with the authoritative baseline:

```bash
git diff 4ff99b80be1265ce0eb109538e2f7602703c590f -- \
  sword-common/src/lib.rs \
  sword-ebpf/src/common/mod.rs \
  sword-ebpf/src/cpu/sched.rs \
  sword/src/loader/cpu.rs \
  sword/src/loader/mod.rs \
  sword/src/metrics/cpu.rs
```

Apply baseline-guided patches so the resulting responsibilities are:

```text
sword-common/src/lib.rs
  Retain generic scheduler/network structures only.
  Remove RiskTargetConfig, HTTP payload/request ID types, slow TCP events,
  Risk constants, and their tests.

sword-ebpf/src/common/mod.rs
  Retain thread_id(), byte_to_str(), and cgroup_id().
  Remove RISK_TARGET_CONFIG, RISK_TARGET_TGIDS, and Risk lookup helpers.

sword-ebpf/src/cpu/sched.rs
  Retain generic sched_switch accounting and SCHED_SWITCH_TARGET_TIDS.
  Remove Risk threshold lookup, sched_wakeup Risk latency events,
  RUNQUEUE_METRICS, and SLOW_SCHED_EVENTS added for Risk.

sword/src/loader/cpu.rs
  Retain PID/COMM target discovery and SCHED_SWITCH_TARGET_TIDS refresh.
  Remove command-line marker discovery and RISK_TARGET_TGIDS synchronization.

sword/src/loader/mod.rs
  LoaderOptions contains only tcp_sendmsg_pid.
  Remove Risk environment parsing and configure_risk_target().

sword/src/metrics/cpu.rs
  Retain pre-Risk CPU metrics; remove Risk runqueue latency/event consumption.
```

- [ ] **Step 3: Verify shared and CPU code compiles and tests pass**

Run:

```bash
cargo fmt --all -- --check
cargo test -p sword-common
cargo test -p sword --lib loader::cpu
```

Expected: all commands exit successfully; generic PID/COMM parser tests remain green.

- [ ] **Step 4: Commit the shared/CPU removal**

```bash
git add sword-common/src/lib.rs sword-ebpf/src/common/mod.rs \
  sword-ebpf/src/cpu/sched.rs sword/src/loader/cpu.rs \
  sword/src/loader/mod.rs sword/src/metrics/cpu.rs
git commit -m "refactor: remove risk target monitoring"
```

---

### Task 2: Remove Risk network probes, events, and metrics

**Files:**
- Modify: `sword-ebpf/src/network/tcp.rs`
- Modify: `sword/src/loader/network.rs`
- Modify: `sword/src/metrics/network.rs`
- Modify: `sword/src/metrics/mod.rs`
- Delete: `sword/tests/socket_lifecycle_source.rs`

**Interfaces:**
- Consumes: generic `LoaderOptions { tcp_sendmsg_pid: Option<u32> }` from Task 1.
- Produces: generic TCP/socket monitoring with the user-added `KProberConfig::new("tcp_send_active_reset", "tcp_send_active_reset")` entry preserved independently of Risk maps.

- [ ] **Step 1: Record the current user changes before editing**

Run:

```bash
git diff -- sword-ebpf/src/network/tcp.rs sword/src/loader/network.rs
```

Expected: the existing Risk cleanup in `tcp.rs` and the `tcp_send_active_reset` loader addition are visible. Save this output for the final diff comparison; do not stage or revert it separately.

- [ ] **Step 2: Remove Risk-only eBPF network state**

Use the pre-Risk file as the generic reference:

```bash
git diff 4ff99b80be1265ce0eb109538e2f7602703c590f -- sword-ebpf/src/network/tcp.rs
```

Apply a patch that removes all of the following Risk-only groups:

```text
RISK_TCP_* indices and RISK_TCP_COUNTERS
TCP_RECV_INFLIGHT and HTTP_* inflight/payload maps
EPOLL_* maps and epoll tracepoints
TCP_REQUEST_START, TCP_PAYLOAD_ARRIVAL, TCP_ACTIVE_FLOWS
SLOW_TCP_EVENTS and SlowTcpEvent emission
tcp_data_queue, tcp_recvmsg, tcp_recvmsg_ret Risk correlation paths
read/readv/recvfrom/recvmsg/write/writev/sendto/sendmsg Risk syscall paths
HTTP request ID extraction and socket lifecycle cleanup added for Risk
Risk-target counting inside tcp_send_reset/tcp_receive_reset/tcp_retransmit_skb
```

Retain the baseline generic programs:

```text
sys_enter_connect/sys_exit_connect
sys_enter_socket/sys_exit_socket
tcp_v4_connect
inet_sock_set_state
accept/accept4 handling that existed in the baseline
tcp_send_reset
generic SYS_ENTER_CONNECT and SYS_ENTER_STATISTICS maps
```

- [ ] **Step 3: Restore generic loader and metrics behavior while retaining Reset work**

Use these baseline comparisons:

```bash
git diff 4ff99b80be1265ce0eb109538e2f7602703c590f -- \
  sword/src/loader/network.rs sword/src/metrics/network.rs sword/src/metrics/mod.rs
```

The final `network_kprobes()` must retain the baseline connect probe and the user's generic
addition:

```rust
fn network_kprobes() -> Vec<KProberConfig> {
    vec![
        KProberConfig::new("tcp_v4_connect", "tcp_v4_connect"),
        KProberConfig::new("tcp_send_active_reset", "tcp_send_active_reset"),
    ]
}
```

Keep the existing pre-Risk `tcp_sendmsg_pid` gate for these in-progress kprobes; do not introduce
a new default runtime attachment while the eBPF-side `tcp_send_active_reset` program is not yet
implemented. The loader must not consult Risk target maps. Restore `metrics/network.rs` and
`metrics/mod.rs` to generic metrics collection, removing `RISK_TCP_COUNTERS`, `sword_target_*`
metrics, HTTP payload decoding, correlators, and Risk ring-buffer consumers.

- [ ] **Step 4: Delete the Risk-only source-structure test**

Delete:

```text
sword/tests/socket_lifecycle_source.rs
```

Expected: no remaining test reads Risk HTTP/socket lifecycle source text.

- [ ] **Step 5: Run network and workspace tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p sword-common
cargo test -p sword
cargo check --workspace
```

Expected: all commands exit successfully. If the in-progress `tcp_send_active_reset` loader references a not-yet-created eBPF program only at runtime, document that existing limitation without removing the loader entry.

- [ ] **Step 6: Commit the network removal**

```bash
git add sword-ebpf/src/network/tcp.rs sword/src/loader/network.rs \
  sword/src/metrics/network.rs sword/src/metrics/mod.rs \
  sword/tests/socket_lifecycle_source.rs
git commit -m "refactor: remove risk network tracing"
```

---

### Task 3: Remove Risk deployment configuration and historical documents

**Files:**
- Modify: `README.md`
- Modify: `deployment.yaml`
- Delete: `docs/superpowers/plans/2026-07-28-risk-read-timeout-ebpf.md`
- Delete: `docs/superpowers/plans/2026-07-28-tcp-arrival-to-read.md`
- Delete: `docs/superpowers/plans/2026-07-29-risk-socket-xnio-latency-split.md`
- Delete: `docs/superpowers/plans/2026-07-29-slow-runqueue-event-log.md`
- Delete: `docs/superpowers/plans/2026-07-30-http-request-latency-correlation.md`
- Delete: `docs/superpowers/plans/2026-07-30-socket-lifecycle-cleanup.md`
- Delete: `docs/superpowers/specs/2026-07-28-risk-read-timeout-ebpf-design.md`
- Delete: `docs/superpowers/specs/2026-07-28-tcp-arrival-to-read-design.md`
- Delete: `docs/superpowers/specs/2026-07-30-http-request-latency-correlation-design.md`
- Delete: `docs/superpowers/specs/2026-07-30-socket-lifecycle-cleanup-design.md`

**Interfaces:**
- Consumes: Risk-free runtime from Tasks 1 and 2.
- Produces: deployment and operator documentation containing no Risk configuration, while retaining the removal design and this plan as audit records.

- [ ] **Step 1: Remove the README Risk section**

Delete the complete section beginning with:

```markdown
## Risk ReadTimeout short-term tracing
```

and ending immediately before:

```markdown
## Cross-compiling on macOS
```

Retain all other README sections unchanged.

- [ ] **Step 2: Remove Risk environment variables from the DaemonSet**

The resulting environment block must be exactly:

```yaml
env:
- name: RUST_LOG
  value: "info"
```

Keep the current image tag and do not restore the old `rust-mouse` Deployment.

- [ ] **Step 3: Delete the listed historical Risk documents**

Delete exactly the ten files listed in this task. Keep:

```text
docs/superpowers/specs/2026-08-04-remove-risk-monitoring-design.md
docs/superpowers/plans/2026-08-04-remove-risk-monitoring.md
```

- [ ] **Step 4: Verify repository-facing Risk content is gone**

Run:

```bash
rg -n -i 'content-risk-control-service|RISK_TARGET|risk_target|sword_target_tcp|Risk ReadTimeout' \
  README.md deployment.yaml sword-common sword-ebpf sword/src sword/tests \
  docs/superpowers/plans/2026-07-* docs/superpowers/specs/2026-07-*
```

Expected: no matches and exit code `1` from `rg`.

- [ ] **Step 5: Commit documentation and deployment cleanup**

```bash
git add README.md deployment.yaml docs/superpowers
git commit -m "docs: remove risk monitoring configuration"
```

---

### Task 4: Full verification and final diff audit

**Files:**
- Verify only; no planned source changes.

**Interfaces:**
- Consumes: the Risk-free workspace from Tasks 1 through 3.
- Produces: evidence that the workspace builds and only approved behavior changed.

- [ ] **Step 1: Scan for forbidden runtime symbols**

Run:

```bash
if rg -n -i 'content-risk-control-service|RISK_TARGET|risk_target|sword_target_tcp|SWORD_TARGET_|SWORD_SLOW_THRESHOLD|SWORD_HTTP_TRACE_ALL' \
  README.md deployment.yaml sword-common sword-ebpf sword/src sword/tests; then
  exit 1
fi
```

Expected: command exits successfully because `rg` finds no forbidden runtime reference.

- [ ] **Step 2: Format and test the Rust workspace**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo check --workspace
```

Expected: all commands exit successfully.

- [ ] **Step 3: Build the userspace and eBPF artifacts**

Run the repository workflow:

```bash
./build.sh
```

Expected: userspace and eBPF builds complete successfully. Do not build or push a container image unless separately requested.

- [ ] **Step 4: Audit preservation requirements**

Run:

```bash
git diff 4ff99b80be1265ce0eb109538e2f7602703c590f -- deployment.yaml
rg -n 'tcp_send_active_reset' sword/src/loader/network.rs
if ! rg -n 'tcp_send_active_reset' sword-ebpf/src/network/tcp.rs; then
  echo 'existing limitation: eBPF tcp_send_active_reset program is not implemented yet'
fi
git status --short --branch
git log --oneline -5
```

Expected:

```text
deployment.yaml retains image v0.1.0-7f7a0d6561
deployment.yaml contains no Risk environment variable
tcp_send_active_reset loader work remains visible
only approved removal and audit documents differ from the pre-Risk source baseline
```

- [ ] **Step 5: Record final verification without broad staging**

If verification requires no further changes, do not create an empty commit. Report the exact test/build results and any pre-existing TCP Reset runtime limitation separately.
