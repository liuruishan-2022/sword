# Sword HTTP 请求级耗时关联设计

## 背景

Sword 当前在 `tcp_data_queue` 记录 socket 首包时间，在 `tcp_sendmsg` 计算
`arrival_to_write`，并把同一 socket 上缓存的 HTTP 请求体用于提取
`requestId`。该模型把 socket 当作一次请求；HTTP/1.1 Keep-Alive 会在同一
socket 上连续承载多个请求，socket 级首包时间可能与当前 `requestId` 不属于
同一次请求。

已有压测样本中，同一 `requestId` 的 Sword `arrival_to_write_ms` 与 MTR
`costMs` 大量相差 500 ms 以上，且出现 Sword 耗时显著大于客户端完整调用耗时
的情况。这证明该字段不能继续作为请求级耗时。

## 目标

- 只记录超过 500 ms 的 HTTP 请求，避免全量输出影响压测。
- `requestId`、慢请求阈值和耗时必须属于同一次请求。
- 在同一个 Keep-Alive socket 连续发送多个请求时，慢请求必须关联到正确的
  `requestId`。
- 先在 26 机器用真实 Keep-Alive 请求验证，再构建镜像。

## 非目标

- 不解析完整 HTTP 协议，不支持 HTTP/2 多路复用。
- 不把 socket 首包到应用读取的时间宣称为请求级耗时。
- 不修改现有 TCP 阶段指标；它们仍用于 socket/调度诊断。

## 方案

以当前请求第一次 `tcp_recvmsg` 成功返回为请求读取完成点，以该请求对应的
第一次 `tcp_sendmsg` 为响应开始写出点，计算：

```text
request_read_to_write = first tcp_sendmsg - first successful tcp_recvmsg return
```

`TCP_REQUEST_START` 在第一次读取时创建，在第一次写出时删除，因此该时间段与
当前请求生命周期一致。HTTP 慢请求阈值改为判断
`RequestTimings.read_to_write_ns`，不再判断 `arrival_to_write_ns`。

当请求超过 500 ms 时，eBPF 按顺序向同一个 ring buffer 写入：

1. 当前请求的 HTTP 请求头/请求体片段；
2. 当前请求的慢事件。

用户态先从请求片段提取 `requestId`，再把紧随其后的慢事件按 socket 关联到该
请求。日志主字段改为 `request_read_to_write_ms`。socket 首包阶段数据可以作为
附加诊断字段保留，但不得再命名或解释成请求总耗时。

## Keep-Alive 行为

同一 socket 上请求 A 完成写出后，`TCP_REQUEST_START` 和
`HTTP_REQUEST_HEADS` 被清理。请求 B 第一次读取时创建新的请求上下文；当 B
慢于阈值时，输出 B 的请求片段和慢事件。用户态在收到 B 的请求片段时覆盖该
socket 上已完成的 A 关联，因此慢事件必须得到 B 的 `requestId`。

## 验证标准

26 机器上使用单个持久连接依次发送：

1. 快请求 A；
2. 延迟超过 500 ms 的慢请求 B；
3. 快请求 C；
4. 延迟超过 500 ms 的慢请求 D。

结果必须满足：

- 只输出 B、D 的 `target http slow`；
- B、D 的 `requestId` 均非空且不串号；
- `request_read_to_write_ms` 与服务端人工延迟误差在可解释范围内；
- 不再使用 `arrival_to_write_ms` 与 MTR `costMs` 做请求级对比。

