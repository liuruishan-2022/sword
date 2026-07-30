# Sword Socket 生命周期清理设计

## 背景

性能压测中，Sword 输出的 `arrival_to_write_ms` 偶尔达到数秒甚至数小时，但同一
`requestId` 在 MTR 与 Risk 应用日志中的耗时只有数十毫秒。当前 eBPF 程序使用
`sock *` 地址作为请求状态键；Linux 关闭连接后可能复用该地址。

## 根因

`inet_sock_set_state` 在连接进入 `TCP_CLOSE` 时只删除
`TCP_REQUEST_START`，未删除以下按 socket 地址保存的状态：

- `TCP_PAYLOAD_ARRIVAL`
- `TCP_ACTIVE_FLOWS`
- `HTTP_REQUEST_HEADS`

其中 `tcp_data_queue` 在发现 `TCP_PAYLOAD_ARRIVAL` 已存在时不会覆盖时间戳。
因此，未被应用读取便关闭的旧连接会留下到达时间；同一 `sock *` 地址被新连接复用
后，新请求会继承旧时间戳并产生虚假的慢请求。

## 方案

新增统一的 socket 状态清理函数，在 `TCP_CLOSE` 时同时删除：

- 请求阶段上下文；
- 未消费的报文到达时间；
- 活跃请求标记；
- HTTP 请求头片段。

正常的 Keep-Alive 请求生命周期和“首个报文到达时间”语义保持不变，不引入超时
裁剪，也不重构 HTTP 解析逻辑。

## 验证

1. 单元测试约束关闭连接时必须覆盖全部四类 socket 状态。
2. 运行 Rust workspace 单元测试。
3. 构建 eBPF 与 Sword。
4. 在 26 机器验证短连接、Keep-Alive、请求未读即关闭以及后续新连接。

## 变更边界

仅修改 Sword eBPF socket 生命周期处理及其测试；不修改 `deployment.yaml`，不调整
采集阈值和业务服务配置。
