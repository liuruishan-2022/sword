# 网络 I/O 追踪

本文档整理网络 I/O，尤其是 TCP 性能追踪时的起点和逐步展开方式。当前项目先从 `tcp_sendmsg` 这个 kprobe 开始，因为它位于应用写入 TCP 协议栈的关键路径，能直接统计发送方向的调用次数和字节数。

## 追踪入口选择

网络 I/O 的追踪可以从多个层次开始：

- 系统调用层：`sendto`、`sendmsg`、`write`、`read` 等，适合看应用接口，但不一定都是 TCP。
- TCP socket 层：`tcp_sendmsg`、`tcp_cleanup_rbuf`、`tcp_set_state` 等，适合分析 TCP 吞吐、连接生命周期和异常。
- 协议栈包路径：`netif_receive_skb`、`net_dev_start_xmit`、`qdisc_enqueue` 等，适合进一步定位设备、队列和协议栈瓶颈。

对 TCP 网络 I/O 性能，建议优先从 TCP socket 层开始：

- `tcp_sendmsg`：发送方向，应用把数据写入 TCP 栈。
- `tcp_cleanup_rbuf`：接收方向，应用读走 TCP receive buffer 后清理缓冲区。
- `sock:inet_sock_set_state` 或 `tcp_set_state`：连接状态变化，用于统计连接生命周期。
- `tcp:tcp_retransmit_skb`：TCP 重传，用于分析丢包、拥塞和链路问题。

## 第一阶段：tcp_sendmsg

`tcp_sendmsg` 的典型内核函数原型是：

```c
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
```

在 kprobe 中，参数通过寄存器传入。对 `tcp_sendmsg` 来说：

- `arg0`：`struct sock *sk`
- `arg1`：`struct msghdr *msg`
- `arg2`：`size_t size`

第一版只需要读取 `arg2`，因为它就是本次应用写入 TCP 栈的字节数，不需要解析内核结构体，稳定且容易验证。

### bpftrace 验证

先确认系统是否能挂 `tcp_sendmsg`：

```bash
sudo bpftrace -l | grep '^kprobe' | grep 'tcp_sendmsg'
```

查看调用和发送大小：

```bash
sudo bpftrace -e '
kprobe:tcp_sendmsg
{
  printf("comm=%s pid=%d sk=%p msg=%p size=%lu\n",
         comm, pid, arg0, arg1, arg2);
}'
```

按进程名统计发送字节数：

```bash
sudo bpftrace -e '
kprobe:tcp_sendmsg
{
  @[comm] = sum(arg2);
}'
```

按进程 ID 和进程名统计：

```bash
sudo bpftrace -e '
kprobe:tcp_sendmsg
{
  @[pid, comm] = sum(arg2);
}'
```

### Aya eBPF 读取参数

在 Aya 的 kprobe 程序中，可以通过 `ProbeContext::arg()` 读取参数：

```rust
let size: usize = ctx.arg(2).ok_or(1u32)?;
```

最小统计逻辑：

```rust
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    // 这里累计调用次数和发送字节数。
    // 后续再从 arg0 的 struct sock 解析五元组。

    Ok(0)
}
```

## 第二阶段：连接维度

只统计 `size` 可以得到全局或进程维度的 TCP 发送量，但还不能区分具体连接。要进入连接维度，需要解析 `arg0`：

```text
arg0 -> struct sock *sk
```

从 `struct sock` / `struct inet_sock` 中可以进一步读取：

- 源地址
- 目标地址
- 源端口
- 目标端口
- 地址族
- TCP 状态

建议不要一开始手写字段偏移。优先用 BTF 或 `aya-tool` 生成内核结构体 bindings，或者先用 bpftrace 查看字段：

```bash
sudo bpftrace -lv 'struct sock'
sudo bpftrace -lv 'struct inet_sock'
```

如果当前内核支持 BTF，也可以优先尝试 fentry：

```bash
sudo bpftrace -lv 'fentry:tcp_sendmsg'
```

支持时可以使用命名参数：

```bash
sudo bpftrace -e '
fentry:tcp_sendmsg
{
  printf("comm=%s pid=%d size=%lu\n", comm, pid, args.size);
}'
```

## 第三阶段：接收方向

发送方向从 `tcp_sendmsg` 开始，接收方向可以从 `tcp_cleanup_rbuf` 开始。

`tcp_cleanup_rbuf` 在应用从 TCP 接收缓冲区读走数据后执行，适合统计接收方向吞吐。常见思路是读取其接收字节参数，按进程或连接维度累计。

可以先确认是否可挂：

```bash
sudo bpftrace -l | grep '^kprobe' | grep 'tcp_cleanup_rbuf'
```

如果该函数在当前内核中不可见，可能是内核版本差异、函数被优化或符号不可 kprobe。此时可以根据当前内核符号继续查找 TCP receive 路径的可挂函数。

## 第四阶段：连接生命周期

连接生命周期建议使用：

- `tracepoint:sock:inet_sock_set_state`
- `kprobe:tcp_set_state`

用途：

- 统计连接创建和关闭。
- 计算连接持续时间。
- 关联连接最终状态。
- 配合 `tcp_sendmsg` / `tcp_cleanup_rbuf` 汇总连接级发送和接收字节数。

优先使用 tracepoint：

```bash
sudo bpftrace -l | grep 'tracepoint:sock:inet_sock_set_state'
```

如果 tracepoint 字段满足需求，它比 kprobe 更稳定。

## 第五阶段：异常和瓶颈

当已经能看到 TCP 吞吐和连接后，再补异常路径：

- `tracepoint:tcp:tcp_retransmit_skb`：TCP 重传。
- `tracepoint:tcp:tcp_receive_reset`：收到 RST。
- `tracepoint:tcp:tcp_send_reset`：发送 RST。
- `tracepoint:tcp:tcp_probe`：TCP 窗口、拥塞相关观测。
- `tracepoint:skb:kfree_skb`：skb 释放和丢包路径。
- `tracepoint:qdisc:qdisc_enqueue` / `qdisc_dequeue`：排队规则和发送队列。
- `tracepoint:net:net_dev_start_xmit`：网卡发送路径。
- `tracepoint:net:netif_receive_skb`：网卡接收进入协议栈路径。

推荐排查顺序：

1. `tcp_sendmsg` 看应用发送到 TCP 的大小和频率。
2. `tcp_cleanup_rbuf` 看应用接收 TCP 数据的大小和频率。
3. `inet_sock_set_state` 看连接生命周期。
4. `tcp_retransmit_skb` 看重传。
5. `qdisc` / `net` tracepoints 看协议栈和设备队列。

## 项目实现建议

当前项目可以先实现最小闭环：

- eBPF：`kprobe:tcp_sendmsg`
- 参数：`--tcp-sendmsg-pid PID`，指定要跟踪的进程 ID
- map：`TCP_SENDMSG_TARGET`，保存用户态传入的目标 PID
- map：`TCP_SENDMSG_TOTAL`，累计调用次数
- map：`TCP_SENDMSG_BYTES_TOTAL`，累计发送字节数
- 用户态：挂载 `tcp_sendmsg`
- 指标：Prometheus 输出每 CPU 调用次数和发送字节数

运行示例：

```bash
RUST_LOG=info cargo run -- --tcp-sendmsg-pid 12345
```

通过参数配置 PID、写入 eBPF map、再由内核态 kprobe 读取配置并过滤的完整流程，见
[`kprobe_tcp_sendmsg_pid_filter.md`](./kprobe_tcp_sendmsg_pid_filter.md)。

后续再扩展：

- 支持多个 PID 或运行时更新 PID 过滤配置。
- 解析 `struct sock`，加入五元组维度。
- 增加 `tcp_cleanup_rbuf`，补接收方向。
- 增加 `inet_sock_set_state`，补连接生命周期。
- 增加重传、RST、qdisc、netdev 事件，用于定位异常。
