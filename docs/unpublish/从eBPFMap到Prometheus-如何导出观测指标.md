# 从 eBPF Map 到 Prometheus：如何导出观测指标

做 eBPF 观测时，很多人第一版都会从日志开始。

比如在 `tcp_sendmsg` 里打印一次发送字节数，在 `sched_switch` 里打印一次线程切换，在 `inet_sock_set_state` 里打印一次连接状态变化。这样验证功能很方便：事件来了，日志就出来了。

但日志不是长期观测的好形态。

日志适合看细节，不适合看趋势。我们很难从刷屏日志里回答这些问题：

- 最近 5 分钟某个进程发起了多少次 TCP 连接？
- 每个 CPU 上调度切换次数是否异常？
- 某个线程 off-cpu 时间是否持续增长？
- 这些数据能不能接入 Grafana 做图？

所以当 eBPF 程序从“实验验证”进入“持续观测”，就需要把日志变成指标。

一种常见做法是采用 Prometheus 导出方式：eBPF 侧把数据写入 map，用户态定期读取 map，再通过 HTTP `/metrics` 输出 OpenMetrics 文本。

本文就沿着这个链路展开。

## 第一步：为什么不能只靠 eBPF 日志

在 Aya 里，eBPF 程序可以通过 `aya_log_ebpf::info!` 打印日志。

例如网络发送方向可以输出：

```text
tcp_sendmsg pid=12345 tid=12345 family=ipv4 src=10.0.0.1:50000 dst=1.2.3.4:443 size=1280
```

连接耗时可以输出：

```text
Socket:123456 旧状态:2 新状态:1 耗时为:23ms
```

这些日志对于开发阶段很有用，因为它能直接证明 hook 点生效了，也能看到字段解析是否正确。

但日志有几个天然问题：

- 高频事件会刷屏，人工很难读。
- 事件粒度太细，不方便直接看总量和趋势。
- 日志格式不稳定，不适合给监控系统消费。
- 长期保留日志成本高，还可能带来隐私和合规风险。

所以日志应该作为调试手段，而不是最终观测产品形态。

更好的方式是让 eBPF 侧只做轻量聚合，用户态负责把聚合结果导出成指标。

## 第二步：先在 eBPF 侧用 Map 聚合

eBPF 程序不能随便分配内存，也不适合做复杂业务逻辑。它最适合做的事情是：

```text
事件发生 -> 读取少量字段 -> 更新 map -> 返回
```

以文件打开次数为例，可以使用 `PerCpuArray` 统计：

```rust
#[map]
pub static SYS_ENTER_OPEN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
```

每次触发 `sys_enter_open`、`sys_enter_openat`、`sys_enter_openat2` 时，计数器加一：

```rust
fn inc_sys_enter_open_counter() {
    unsafe {
        if let Some(count) = SYS_ENTER_OPEN_COUNTER.get_ptr_mut(0) {
            *count += 1;
        }
    }
}
```

CPU 调度事件也是类似思路：

```rust
#[map]
pub static SCHED_SWITCH_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
```

每次 `sched_switch` 事件进来，当前 CPU 上的计数加一：

```rust
if let Some(total) = SCHED_SWITCH_TOTAL.get_ptr_mut(0) {
    *total = (*total).wrapping_add(1);
}
```

这里用 `PerCpuArray` 的好处是减少多 CPU 并发更新同一个计数器带来的竞争。用户态读取时，再把每个 CPU 的值汇总或按 CPU 分标签输出。

对于按线程维度的指标，可以使用 `HashMap`：

```rust
#[map]
pub static THREAD_OFFCPU_TOTAL_NS: HashMap<SchedSwitchStateKey, u64> =
    HashMap::with_max_entries(SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES, 0);
```

key 是线程 ID 和状态，value 是累计 off-cpu 时间。

到这里，eBPF 侧只负责把“瞬时事件”变成“可读取的聚合数据”。

## 第三步：用户态接管 Map

eBPF map 里的数据不能直接被 Prometheus 抓取。Prometheus 抓的是 HTTP 文本接口，所以需要用户态程序做中间层。

用户态入口通常会先加载 eBPF object，再启动指标导出服务：

```rust
let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
    env!("OUT_DIR"),
    "/ebpf-observer"
)))?;

loader::load_ebpf(&mut ebpf, &options)?;
metrics::spawn_prometheus_exporter(&mut ebpf).await?;
```

这里的顺序是：

```text
加载 eBPF object
    -> attach tracepoint/kprobe
    -> 启动 Prometheus exporter
```

指标导出入口可以这样设计：

```rust
pub async fn spawn_prometheus_exporter(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .take_map(SCHED_SWITCH_TOTAL_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TOTAL_MAP} not found"))?;
    let sched_switch_total_map: PerCpuArray<MapData, u64> = PerCpuArray::try_from(map)?;

    // 继续 take 其他 map...
}
```

注意这里用的是 `take_map`，不是只借用 map。用户态把 map 从 `Ebpf` 对象里取出来，交给 collector 持有。

然后分别创建 CPU 和 Network collector：

```rust
let cpu_state = CpuCollector::new(
    sched_switch_total_map,
    sys_enter_open_counter_map,
    thread_switch_out_total_map,
    thread_offcpu_total_ns_map,
    thread_comm_map,
);
let network_state = NetworkCollector::new(sys_enter_connect_map);
```

这样每个 collector 都只关心自己的 map 和指标转换逻辑。

## 第四步：用 prometheus-client 定义指标

Prometheus 指标不是随便拼字符串。可以使用 `prometheus-client` 这个 crate 定义 Registry、Family、Gauge 和 Label。

以 CPU 指标为例，先定义标签：

```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SchedSwitchLabels {
    cpu: u32,
}
```

这个结构体表示指标标签：

```text
cpu="<cpu_id>"
```

指标定义：

```rust
pub struct CpuMetrics {
    sched_switch_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
    sys_enter_open_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
    thread_sched_switch_out_total: Family<ThreadStateLabels, Gauge<u64, AtomicU64>>,
    thread_offcpu_ns_total: Family<ThreadStateLabels, Gauge<u64, AtomicU64>>,
}
```

初始化时注册到 `Registry`：

```rust
registry.register(
    "sched_switch_total",
    "Total number of sched_switch events per CPU",
    sched_switch_total.clone(),
);
```

这一步完成了从“Rust 变量”到“Prometheus 指标定义”的转换。

网络指标同理：

```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TcpLabels {
    pid: u32,
}
```

指标名是：

```text
network_tcp_pid_total
```

它的目标是按 PID 暴露 TCP connect 总量。

## 第五步：Collector 把 Map 数据刷新到指标

指标对象创建之后，还需要把 eBPF map 里的值读出来。

CPU collector 的核心逻辑是 `collect`：

```rust
pub async fn collect(&self) -> Result<(), MapError> {
    let sched_switch_cpus = self.sched_switch.get(&0, 0)?;
    sched_switch_cpus
        .iter()
        .enumerate()
        .for_each(|(index, count)| {
            self.cpu.inc_sched_switch_total(index as u32, *count);
        });

    let sys_enter_open_cpus = self.sys_enter_open.get(&0, 0)?;
    sys_enter_open_cpus
        .iter()
        .enumerate()
        .for_each(|(index, count)| {
            self.cpu.inc_sys_enter_open_total(index as u32, *count);
        });

    Ok(())
}
```

这里做了两件事：

1. 从 eBPF map 读取当前值。
2. 写入 prometheus-client 的 Gauge。

对 `PerCpuArray` 来说，读取出来的是每个 CPU 一份值，所以这里按 CPU 下标输出标签。

线程级指标则从 `HashMap` 遍历：

```rust
for item in self.thread_offcpu.iter() {
    let (key, ns) = item?;
    let comm = self.thread_comm(key.tid);
    let state = sched_switch_state_label(key.state);
    self.cpu
        .set_thread_offcpu_ns_total(key.tid, comm, state, ns);
}
```

这一步会把 eBPF 侧的数字翻译成更适合人读的标签，例如线程名和任务状态。

网络 collector 也是类似模式：

```rust
for item in self.sys_enter_connect.iter() {
    let (pid, counts) = item?;
    if !pid_exists(pid) {
        stale_pids.push(pid);
        continue;
    }

    let total = counts.iter().copied().sum();
    self.network.pid_tcp_total(pid, total);
}
```

这里还有一个细节：如果 PID 已经不存在，就把对应 map 和指标清理掉，避免 `/metrics` 长期保留过期进程。

## 第六步：用 Axum 暴露 /metrics

有了 Registry 和 Collector，还需要一个 HTTP 接口。

用户态可以启动一个 Axum 服务：

```rust
let app = Router::new()
    .route("/metrics", get(metrics_handler))
    .route("/health", get(health_handler))
    .with_state(exporter_state);
let listener = TcpListener::bind("0.0.0.0:9898").await?;
```

`/health` 用来做健康检查：

```rust
async fn health_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("ok"))
        .unwrap()
}
```

`/metrics` 每次被请求时，都会触发一次采集：

```rust
async fn metrics_handler(
    State(metrics_state): State<Arc<Mutex<MetricsState>>>,
) -> impl IntoResponse {
    match metrics_state.lock().await.metrics().await {
        Ok(metrics) => Response::builder()
            .header(
                CONTENT_TYPE,
                "application/openmetrics-text;version=1.0.0; charset=utf-8",
            )
            .body(Body::from(metrics))
            .unwrap(),
        Err(err) => {
            error!("failed to collect metrics: {err}");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to collect metrics"))
                .unwrap()
        }
    }
}
```

这里的设计是“按请求采集”，不是后台定时采集。

也就是说：

```text
Prometheus scrape /metrics
    -> handler 读取 eBPF map
    -> collector 更新 Registry
    -> encode 成 OpenMetrics 文本
    -> 返回 HTTP 响应
```

这种方式实现简单，也符合 Prometheus 的 pull 模型。

## 第七步：多个 Registry 如何合并

一种拆分方式是让 CPU collector 和 Network collector 各自持有一个 `Registry`。

最终 `/metrics` 需要把它们合并输出：

```rust
impl MetricsState {
    async fn metrics(&mut self) -> anyhow::Result<String> {
        let mut metrics = trim_openmetrics_eof(self.cpu.metrics().await?);
        metrics.push_str(&trim_openmetrics_eof(self.network.metrics().await?));
        metrics.push_str("# EOF\n");
        Ok(metrics)
    }
}
```

这里有一个小处理：`prometheus-client` 编码出来的 OpenMetrics 文本末尾会带 `# EOF`。多个 Registry 拼接时，不能每段都保留 EOF，所以先去掉每段末尾的 EOF，最后统一补一个。

处理函数是：

```rust
fn trim_openmetrics_eof(mut metrics: String) -> String {
    const EOF_MARKER: &str = "# EOF\n";
    if metrics.ends_with(EOF_MARKER) {
        metrics.truncate(metrics.len() - EOF_MARKER.len());
    }
    metrics
}
```

这个细节很实用。否则 `/metrics` 里出现多个 EOF，Prometheus 解析可能会出问题。

## 当前可以看到哪些指标

启动后可以访问：

```bash
curl -s http://127.0.0.1:9898/metrics
```

当前代码中，比较明确的指标包括：

```text
sched_switch_total{cpu="0"} ...
sys_enter_open_total{cpu="0"} ...
thread_sched_switch_out_total{tid="...",comm="...",state="..."} ...
thread_offcpu_ns_total{tid="...",comm="...",state="..."} ...
network_tcp_pid_total{pid="..."} ...
```

需要注意，`network_tcp_pid_total` 的数据来源是 `SYS_ENTER_CONNECT` map。

如果 `sys_enter_connect` tracepoint 加载还处于注释状态：

```rust
// TracePointConfig::create_syscalls("sys_enter_connect", "sys_enter_connect"),
```

所以这个网络指标的链路设计已经在，但要让它真实增长，需要恢复这个 tracepoint 的 attach。

## 运行和验证

构建并运行：

```bash
sudo RUST_LOG=info cargo run --release -- --target-pid <PID>
```

检查 exporter 是否正常：

```bash
curl -s http://127.0.0.1:9898/health
```

查看指标：

```bash
curl -s http://127.0.0.1:9898/metrics
```

如果要接入 Prometheus，可以增加 scrape 配置：

```yaml
scrape_configs:
  - job_name: ebpf-observer
    static_configs:
      - targets: ["127.0.0.1:9898"]
```

然后在 Grafana 中按指标名查询。

## 这套设计的关键点

把 Prometheus 导出链路压缩成一句话：

```text
eBPF 程序更新 map，用户态读取 map，prometheus-client 编码，Axum 暴露 /metrics。
```

这个架构有几个好处：

- eBPF 侧足够轻，只负责计数和聚合。
- 用户态负责复杂逻辑，比如标签、清理过期 PID、编码文本。
- Prometheus 用标准 pull 模型抓取，不需要 eBPF 程序主动推送数据。
- 后续新增指标时，只要增加 map、collector 和 registry 注册即可。

后续优化可以从三个方向做：

1. 把网络 connect、established、失败次数和耗时分桶补齐。
2. 把 `tcp_sendmsg` 的发送字节数从日志沉淀为 `*_bytes_total` 指标。
3. 统一各模块 Registry，减少手工拼接 OpenMetrics 文本的复杂度。

日志适合回答“刚刚发生了什么”，指标适合回答“这段时间整体怎么样”。当 eBPF 工具从调试脚本走向长期观测系统时，Prometheus 导出就是非常自然的一步。
