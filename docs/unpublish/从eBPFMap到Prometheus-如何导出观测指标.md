# 用 eBPF 统计打开文件次数，并导出给 Prometheus

线上排查问题时，文件打开这件事经常会被忽略。

服务变慢了，我们会先看 CPU、内存、GC、接口耗时；怀疑文件句柄问题时，再临时上去敲 `lsof`。但 `lsof` 看到的是某一刻的状态，它回答不了另一个问题：这段时间里，程序到底有没有频繁打开文件？

如果只是想验证 eBPF 程序有没有抓到事件，最直接的办法是在 `open` 相关 hook 里打日志。这个办法开发时很方便，但跑一会儿就会发现日志太吵。文件打开事件本身可能非常高频，全部打印出来，既看不出趋势，也不适合长期放在线上。

所以这里换一种方式：不打印每次事件，只维护一个计数器，再把这个计数器暴露成 Prometheus 指标。

这篇文章只看一个指标：

```text
sys_enter_open_total
```

它表示系统进入打开文件相关系统调用的累计次数。因为底层用的是 per-CPU 计数，所以导出时会带上 CPU 维度：

```text
sys_enter_open_total{cpu="0"} 123
sys_enter_open_total{cpu="1"} 98
```

这不是“当前打开了多少个 fd”，而是“发生过多少次打开文件动作”。两者含义不同，后者更适合用 tracepoint 做低成本计数。

## 先抓哪些事件

打开文件通常会经过这些系统调用：

```text
open
openat
openat2
```

对应到 tracepoint，就是：

```text
syscalls:sys_enter_open
syscalls:sys_enter_openat
syscalls:sys_enter_openat2
```

这里挂在 `sys_enter_*` 上，只统计“尝试打开文件”的次数，不关心这次打开最终成功还是失败。

如果要区分成功失败，就需要再看退出点和返回值。本文先不做这一步，避免把问题扩大。先把一个计数指标跑通，比一开始就设计一堆维度更稳。

## eBPF 侧只做计数

内核态逻辑越简单越好。这个需求里，eBPF 程序只需要在事件触发时把计数器加一。

Map 定义如下：

```rust
#[map]
pub static SYS_ENTER_OPEN_COUNTER: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
```

这里用 `PerCpuArray`，不是普通数组。原因很直接：打开文件事件可能在多个 CPU 上同时发生，如果大家都更新同一个计数器，会有不必要的竞争。per-CPU 计数让每个 CPU 写自己的那份，用户态读取时再按 CPU 拿出来。

计数函数也很短：

```rust
fn inc_sys_enter_open_counter() {
    unsafe {
        if let Some(count) = SYS_ENTER_OPEN_COUNTER.get_ptr_mut(0) {
            *count += 1;
        }
    }
}
```

三个 tracepoint 程序都调用它：

```rust
#[tracepoint]
pub fn sys_enter_open(_ctx: TracePointContext) -> u32 {
    inc_sys_enter_open_counter();
    0
}

#[tracepoint]
pub fn sys_enter_openat(_ctx: TracePointContext) -> u32 {
    inc_sys_enter_open_counter();
    0
}

#[tracepoint]
pub fn sys_enter_openat2(_ctx: TracePointContext) -> u32 {
    inc_sys_enter_open_counter();
    0
}
```

到这里，内核态已经结束了。它不拼字符串，不做 HTTP，不关心 Prometheus，只负责把事件数记下来。

## 用户态把 Map 拿出来

Prometheus 不认识 eBPF Map。它能抓的是 HTTP 接口，通常就是：

```text
GET /metrics
```

所以用户态需要做一层转换：从 eBPF Map 里读数，再写成 Prometheus 能理解的文本。

启动时先从 `Ebpf` 对象里取出 `SYS_ENTER_OPEN_COUNTER`：

```rust
let map = ebpf
    .take_map(SYS_ENTER_OPEN_COUNTER_MAP)
    .ok_or_else(|| anyhow::anyhow!("map {SYS_ENTER_OPEN_COUNTER_MAP} not found"))?;

let sys_enter_open: PerCpuArray<MapData, u64> =
    PerCpuArray::try_from(map)?;
```

取出来之后，这个 `PerCpuArray` 就交给 collector 持有。Prometheus 每次来抓 `/metrics`，collector 就读一次最新值。

## 指标怎么定义

指标名用：

```text
sys_enter_open_total
```

标签先只放一个 `cpu`：

```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OpenFileLabels {
    cpu: String,
}
```

注册指标：

```rust
registry.register(
    "sys_enter_open_total",
    "Total number of sys_enter_open events per CPU",
    sys_enter_open_total.clone(),
);
```

这里实现上可以用 `Gauge`，虽然名字带 `_total`。

原因是 eBPF Map 里已经是累计值。每次抓取时，用户态只是把 Map 当前值设置到指标里：

```text
Map 当前累计值是多少，/metrics 就暴露多少
```

如果这里用 Counter 再 `inc`，反而容易在每次 scrape 时重复累加同一份数据。这个地方用 Gauge 承载累计值，查询时照样可以用 `rate()` 看增长速度。

## 每次抓取时读一次 Map

collector 读取 key `0`，拿到每个 CPU 的计数：

```rust
let sys_enter_open_cpus = self.sys_enter_open.get(&0, 0)?;

for (index, count) in sys_enter_open_cpus.iter().enumerate() {
    self.inc_sys_enter_open_total(index as u32, *count);
}
```

写入 Prometheus 指标：

```rust
fn inc_sys_enter_open_total(&self, cpu: u32, total: u64) {
    self.sys_enter_open_total
        .get_or_create(&OpenFileLabels {
            cpu: cpu.to_string(),
        })
        .set(total);
}
```

最后导出的效果大概是：

```text
sys_enter_open_total{cpu="0"} 123
sys_enter_open_total{cpu="1"} 98
sys_enter_open_total{cpu="2"} 76
sys_enter_open_total{cpu="3"} 81
```

如果想看整机总量，PromQL 里再聚合：

```promql
sum(sys_enter_open_total)
```

如果想看最近 5 分钟的增长速度：

```promql
sum(rate(sys_enter_open_total[5m]))
```

## 暴露 /metrics

HTTP 部分不用复杂，提供 `/metrics` 和 `/health` 就够了：

```rust
Router::new()
    .route("/metrics", get(metrics_handler))
    .route("/health", get(health_handler))
```

`/metrics` 处理时，先采集，再编码：

```rust
async fn metrics_handler(State(state): State<MetricsState>) -> impl IntoResponse {
    state.collect();

    let mut buffer = String::new();
    encode(&mut buffer, &state.registry)?;

    (
        [(CONTENT_TYPE, "application/openmetrics-text; version=1.0.0; charset=utf-8")],
        buffer,
    )
}
```

这个顺序不要反过来。先 `collect()`，才能把 eBPF Map 里的最新值刷到 registry；再 `encode()`，Prometheus 看到的才是这次抓取时的结果。

## 本地怎么确认

服务启动后，先看健康检查：

```bash
curl -s http://127.0.0.1:9898/health
```

再看指标：

```bash
curl -s http://127.0.0.1:9898/metrics | grep sys_enter_open_total
```

能看到类似结果就说明指标已经暴露出来：

```text
# HELP sys_enter_open_total Total number of sys_enter_open events per CPU.
# TYPE sys_enter_open_total gauge
sys_enter_open_total{cpu="0"} 123
sys_enter_open_total{cpu="1"} 98
# EOF
```

可以手动制造一些打开文件动作：

```bash
ls /tmp >/dev/null
cat /etc/hosts >/dev/null
find /etc -maxdepth 1 -type f >/dev/null
```

再查一次：

```bash
curl -s http://127.0.0.1:9898/metrics | grep sys_enter_open_total
```

如果计数上涨，说明从 syscall tracepoint 到 Prometheus 文本输出这段已经通了。

后面看数据时，可以先查原始值：

```promql
sys_enter_open_total
```

再看增长速度：

```promql
sum(rate(sys_enter_open_total[5m]))
```

如果某段时间这个值突然上升，就可以继续往下排查：是否有配置频繁 reload、是否有目录扫描、是否有异常临时文件读写。

## 收一下

这次只做了一件事：统计打开文件次数。

实现上没有把每次 `open` 都打印出来，而是在 eBPF 侧用 `PerCpuArray` 维护累计值，用户态定期读取，再通过 `/metrics` 给 Prometheus 抓取。

这种方式的好处是运行时足够安静。平时只是一条时间序列，需要排查时再用 PromQL 看趋势：

```promql
sum(rate(sys_enter_open_total[5m]))
```

从这个指标开始，已经可以回答一个很具体的问题：服务运行过程中，打开文件动作有没有异常变多。
