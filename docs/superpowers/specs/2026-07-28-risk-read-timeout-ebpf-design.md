# Risk ReadTimeout eBPF 诊断设计

## 目标

定位 `content-risk-control-service` 压测期间偶发 ReadTimeout 是否与以下因素相关：

- Risk 进程线程被唤醒后长时间得不到 CPU；
- Risk 连接出现 TCP 重传或 RST；
- Risk 进程读取请求后，超过 100ms 才开始写响应。

在原有传输阶段观测上，额外只提取 HTTP JSON 中的 `requestId`。当报文到达 Socket
到首次响应写入达到 500ms 时，输出同一请求的三段耗时，供 MTR 和 Risk 日志关联。
不实现完整 HTTP 解析、数据包抓取或 Cilium 流量采集。

## 运行边界

- 采集器运行在 Risk Pod 所在 Node 上，通过明确的目标 TGID/PID 过滤。
- DaemonSet 通过 `SWORD_TARGET_CMDLINE=content-risk-control-service.jar` 在宿主机
  `/proc` 中自动发现目标 TGID；不在 YAML 中配置易失效的静态 PID。
- TCP 读写额外按服务端本地端口过滤。
- 默认慢阈值为 100ms，可通过启动参数配置。
- 采集用于 5～15 分钟的短时诊断，不默认作为全节点永久全量采集。
- 不保存请求体、响应体、手机号、短信内容或 HTTP Header。只限量扫描
  `tcp_recvmsg` 用户缓冲区的前 512 字节并保留 `requestId`，其他内容立即丢弃。

## DaemonSet 目标发现

DaemonSet 使用 `hostPID: true` 读取宿主机 `/proc/<tgid>/cmdline`。进程的任一启动参数
包含 `SWORD_TARGET_CMDLINE` 时，将该 TGID 和它的全部 TID 加入目标 Map。139 Node
已确认 Risk 进程为：

```text
java -jar content-risk-control-service.jar
```

运行配置为：

```yaml
SWORD_TARGET_CMDLINE: content-risk-control-service.jar
SWORD_TARGET_PORT: "8080"
SWORD_SLOW_THRESHOLD_MS: "100"
```

用户态每 5 秒重新扫描一次：新增 Risk 进程时加入 TGID/TID，Pod 退出或重启后删除旧
TGID/TID。同一 Node 上的多个 Risk Pod 使用同一个端口和阈值，可以同时进入目标集合。
若暂时没有匹配进程，Map 保持为空并等待下一次扫描，不使用 PID 或阈值零值执行采集。

兼容现有手工诊断参数 `--target-pid`，其优先级高于 CMDLINE；原有
`SWORD_SCHED_SWITCH_PID` 和 `SWORD_SCHED_SWITCH_COMM` 继续保留，但不用于生产 Risk
定位。

## 第一阶段：调度和 TCP 异常

### 调度

新增 `sched:sched_wakeup` 和 `sched:sched_wakeup_new`，复用现有
`sched:sched_switch`。

当目标线程被唤醒时记录单调时钟时间；目标线程真正被调度运行时计算：

```text
runqueue latency = sched_switch 时间 - sched_wakeup 时间
```

只在目标 TID Map 中保存状态。Prometheus 输出累计次数、累计时间和慢调度次数。
当单次 runqueue latency 达到慢阈值时，通过独立的 `SLOW_SCHED_EVENTS` RingBuf
上报并打印以下信息：

```text
target thread runqueue slow tid=<tid> comm=<comm>
wakeup_ns=<monotonic-ns> switch_in_ns=<monotonic-ns> latency_ms=<ms>
```

`wakeup_ns` 与 `switch_in_ns` 均为内核单调时钟，用于和 Sword TCP 事件精确对齐；
日志自身时间戳用于和 MTR、Risk 应用日志按墙上时钟关联。正常调度事件不进入
RingBuf，也不为 Prometheus 增加 TID 标签。

### TCP 异常

新增或启用：

- `tcp:tcp_retransmit_skb`
- `tcp:tcp_receive_reset`
- `tcp:tcp_send_reset`

按 Risk 服务端口过滤并输出计数器。若目标内核不存在某个可选 tracepoint，用户态
记录警告并继续加载其他探针。

## 第二阶段：Risk 进程内部 TCP 读写耗时

### 探针

- `kprobe/kretprobe:tcp_recvmsg`
- `kprobe:tcp_sendmsg`

`tcp_recvmsg` 入口保存当前线程、socket 指针和开始时间；返回点只在返回字节数大于
0 时，将 socket 标记为已经读取请求。

`tcp_sendmsg` 仅处理目标进程且本地端口匹配的服务端 socket。若该 socket 已记录
读取时间，则计算：

```text
read-to-write latency = tcp_sendmsg 时间 - tcp_recvmsg 成功返回时间
```

只有 read-to-write latency 大于等于慢阈值时才通过 RingBuf 上报用户态。正常请求
只更新聚合计数，不产生逐请求日志。

### 连接关联

eBPF Map 使用 socket 指针值作为短生命周期关联键，连接关闭或完成首次响应写入后
删除对应状态。

### 慢请求关联

`tcp_recvmsg` 入口根据压测节点 `5.14.0-479.el9.x86_64` 的 BTF 布局读取
`msghdr.msg_iter`，保存首个用户缓冲区地址；返回点读取成功数据并通过跨分片状态机
提取 `"requestId":"..."`。支持 `ITER_IOVEC` 和 `ITER_UBUF`。

首次 `tcp_sendmsg` 计算：

```text
arrival_to_read = tcp_recvmsg完成 - 首个TCP payload到达
read_to_write = 首次tcp_sendmsg - tcp_recvmsg完成
arrival_to_write = 首次tcp_sendmsg - 首个TCP payload到达
```

仅当 `arrival_to_write >= 500ms` 且已提取到 requestId 时输出：

```text
target http slow requestId=... arrival_to_read_ms=... read_to_write_ms=...
arrival_to_write_ms=... pid=... tid=... src=... dst=... family=...
```

扫描缓冲区使用单元素 Per-CPU Map，不占用 BPF 512 字节栈，也不会在 CPU 之间共享。

## 指标

新增指标不使用 IP、端口、PID、TID 或 socket 作为标签，避免高基数：

- `sword_target_thread_runqueue_latency_ns_total`
- `sword_target_thread_runqueue_slow_total`
- `sword_target_tcp_retransmit_total`
- `sword_target_tcp_receive_reset_total`
- `sword_target_tcp_send_reset_total`
- `sword_target_tcp_read_total`
- `sword_target_tcp_write_total`
- `sword_target_tcp_read_to_write_slow_total`
- `sword_target_event_dropped_total`

普通慢事件日志只包含耗时、PID/TID、连接地址和端口；500ms 慢请求额外包含
requestId，不包含短信内容或其他报文内容。

## 性能控制

- 所有探针首先执行目标 PID/TID 或端口过滤。
- TCP 探针先查询目标 TGID Map，再读取 socket 元数据。
- 调度事件只操作 BPF Map，不逐事件进入 RingBuf。
- TCP 正常读写不逐事件进入 RingBuf，仅慢事件上报。
- requestId 只扫描目标 TGID、目标服务端口的成功读取，每次最多 512 字节。
- Map 使用固定容量，插入失败或 RingBuf 满时只增加丢弃计数。
- 通过相同压测场景对比未开启和开启采集时的 TPS、p99、Node CPU。

## 验证

- 用户态单元测试：参数解析、指标更新、慢阈值边界。
- eBPF 构建验证：现有 Aya 构建链能够生成目标程序。
- 功能验证：
  - 正常请求不输出慢事件；
  - 人工延迟超过阈值时输出慢事件；
  - CPU 竞争时调度慢计数增加；
  - 制造重传或 RST 时对应计数增加。
- 性能验证：相同压测基线下确认采集开销是否可接受；若调度探针影响明显，可独立关闭
  调度阶段，仅保留 TCP 读写诊断。
