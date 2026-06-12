# eBPF 实战：如何按 PID 过滤 eBPF 事件

在使用 eBPF 做线上观测时，我们经常会挂载 kprobe、tracepoint、uprobes 等拦截点，用来观察系统调用、内核函数、网络收发、调度切换等行为。

这些拦截点有一个共同特点：它们是系统级的。只要系统执行到了这个位置，不管是谁触发的，eBPF 程序都会被执行。

这在调试时很快会带来两个问题。

第一，日志会被无关进程淹没。比如我们只想看某个 Rust 程序的网络发送行为，但浏览器、curl、系统服务、容器进程也在发送 TCP 数据，它们都会触发同一个 eBPF 程序。

第二，性能会被额外消耗。高频拦截点如果对所有进程都读取参数、解析结构体、打印日志或上报事件，就会给系统带来不必要的开销。

所以，在真正可用的 eBPF 工具里，过滤能力非常重要。最常见的一种过滤方式，就是按 PID 聚焦到我们关心的进程。

本文以 `tcp_sendmsg` 这个 kprobe 为例，介绍如何一步步实现按 PID 过滤：

1. 先理解为什么需要过滤。
2. 再看 `tcp_sendmsg` 在网络发送链路中的位置。
3. 第一版先把 PID 写死在 eBPF 代码里，完成功能闭环。
4. 第二版把 PID 做成启动参数，通过 eBPF map 从用户态传给内核态。
5. 最后详细解释用户态和内核态之间的数据传递方式。

## 一、为什么要按 PID 过滤

假设我们挂了一个 `kprobe:tcp_sendmsg`，想观察某个业务进程是否真的把数据写入了 TCP 协议栈。

如果不加过滤，所有触发 `tcp_sendmsg` 的进程都会出现在日志里：

```text
tcp_sendmsg pid=1012 comm=systemd size=...
tcp_sendmsg pid=2388 comm=browser size=...
tcp_sendmsg pid=12345 comm=rust-mouse size=...
tcp_sendmsg pid=3350 comm=curl size=...
```

这时我们真正关心的可能只有 `pid=12345`。其它事件不仅没有帮助，还会干扰分析。

一个更合理的执行流程应该是：

```text
kprobe/tracepoint 被触发
  读取当前触发事件的 PID
  和目标 PID 比较
  不匹配：直接返回
  匹配：继续读取参数、解析结构体、输出日志或更新指标
```

也就是说，过滤逻辑要尽量靠前。越早返回，就越少做无关工作，也越能降低对系统的影响。

这里的 PID 指 Linux 里的进程 ID，也就是 thread group id。eBPF helper `bpf_get_current_pid_tgid()` 返回一个 `u64`：

- 高 32 位是进程 ID，也就是通常在 `ps`、`pgrep` 里看到的 PID。
- 低 32 位是当前线程 ID，也就是 TID。

如果我们要过滤“某个进程”，应该比较高 32 位；只有在想过滤某个具体线程时，才比较低 32 位。

## 二、示例选择：tcp_sendmsg

本文用 `tcp_sendmsg` 作为例子。

`tcp_sendmsg` 是 TCP 发送路径中的关键内核函数。应用程序把数据写入 TCP socket 后，最终会进入 TCP 协议栈，而 `tcp_sendmsg` 就位于这个入口附近。

它的典型函数原型如下：

```c
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
```

在 kprobe 中，函数参数通过寄存器传入。使用 Aya 时，可以通过 `ProbeContext::arg()` 读取参数：

- `arg0`：`struct sock *sk`
- `arg1`：`struct msghdr *msg`
- `arg2`：`size_t size`

如果我们只想知道本次写入 TCP 栈的字节数，读取 `arg2` 就够了。如果还想知道源地址、目标地址、端口等连接信息，就需要继续从 `arg0` 指向的 `struct sock` 中解析。

先确认当前内核是否能挂到 `tcp_sendmsg`：

```bash
sudo bpftrace -l | grep '^kprobe' | grep 'tcp_sendmsg'
```

可以先用 bpftrace 打印所有触发 `tcp_sendmsg` 的进程：

```bash
sudo bpftrace -e '
kprobe:tcp_sendmsg
{
  printf("comm=%s pid=%d tid=%d sk=%p size=%lu\n",
         comm, pid, tid, arg0, arg2);
}'
```

这一步的作用是验证：当前机器上确实能捕获到 `tcp_sendmsg`，并且可以看到不同进程触发这个 kprobe。

## 三、从 Rust write 到 tcp_sendmsg

为了让例子更具体，我们用一个简单的 Rust 程序发送明文 HTTP 请求：

```rust
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect(("example.com", 80))?;

    stream.write_all(
        b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}
```

这里故意使用 HTTP，而不是 HTTPS。HTTPS 会先经过 TLS 库加密，然后把密文写入 TCP socket；最终仍然会进入 TCP 发送路径，但在 `tcp_sendmsg` 里看到的是 TLS 密文对应的发送字节。

上面这段程序调用 `write_all` 后，大致路径可以理解为：

```text
用户态 Rust
  TcpStream::write_all
  TcpStream::write
  libc write

系统调用入口
  __x64_sys_write
  ksys_write
  vfs_write

socket 文件操作
  sock_write_iter
  sock_sendmsg
  sock_sendmsg_nosec

INET/TCP 协议层
  inet_sendmsg
  tcp_sendmsg
```

如果应用调用的是 `sendmsg(2)`，前半段会不同，但后面也会收敛到 socket send 路径：

```text
用户态 sendmsg
  __x64_sys_sendmsg
  ___sys_sendmsg
  sock_sendmsg
  inet_sendmsg
  tcp_sendmsg
```

进入 `tcp_sendmsg` 后，TCP 层会把用户数据组织进 socket 发送缓冲区，并根据发送窗口、拥塞控制、MSS、Nagle、内存压力等条件决定如何构造和推出 skb。后续发送方向的大致路径是：

```text
tcp_sendmsg
  tcp_sendmsg_locked
  tcp_push 或 tcp_push_one
  __tcp_push_pending_frames
  tcp_write_xmit
  tcp_transmit_skb
  ip_queue_xmit
  __ip_queue_xmit
  ip_local_out
  ip_output
  dev_queue_xmit
  网卡驱动发送队列
  NIC
```

这些函数名会随内核版本有细节差异，但层次关系基本稳定：

- `tcp_sendmsg`：应用数据进入 TCP 发送逻辑。
- `tcp_write_xmit`：TCP 根据窗口、拥塞等规则决定发送哪些 skb。
- `ip_queue_xmit` / `ip_local_out`：进入 IP 层输出。
- `dev_queue_xmit`：进入 qdisc 和网络设备发送路径。
- 网卡驱动：最终把报文交给硬件。

因此，`tcp_sendmsg` 很适合作为本文的例子：它位置明确，容易触发，也可以通过 `arg2` 快速验证是否捕获到了目标进程的发送行为。

## 四、第一版：把 PID 写死在代码里

先实现最小版本：把目标 PID 写死在 eBPF 程序中。

虽然这种方式不够灵活，但它适合先验证核心逻辑：我们能不能在 kprobe 入口处读取当前进程 PID，并只保留目标进程的事件。

核心流程如下：

```text
tcp_sendmsg 被触发
  调用 bpf_get_current_pid_tgid()
  取高 32 位得到当前进程 PID
  和 TARGET_PID 比较
  不匹配：return
  匹配：读取 arg2 并打印
```

代码示例：

```rust
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

const TARGET_PID: u32 = 12345;

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let current_pid = (pid_tgid >> 32) as u32;
    let current_tid = pid_tgid as u32;

    if current_pid != TARGET_PID {
        return Ok(0);
    }

    let size: usize = ctx.arg(2).ok_or(1u32)?;
    info!(
        &ctx,
        "tcp_sendmsg pid={} tid={} size={}",
        current_pid,
        current_tid,
        size
    );

    Ok(0)
}
```

这里最关键的是这几行：

```rust
let pid_tgid = bpf_get_current_pid_tgid();
let current_pid = (pid_tgid >> 32) as u32;
let current_tid = pid_tgid as u32;
```

`current_pid` 用来做进程级过滤，`current_tid` 用来标记具体是哪一个线程触发了事件。

写死 PID 的版本可以证明功能是通的，但它有明显缺点：

- 每次换目标 PID 都要改代码。
- 改完要重新编译 eBPF 程序。
- 线上排查时无法灵活切换目标进程。
- 不方便做自动化和运行时更新。

因此，下一步要把 `TARGET_PID` 从代码常量变成用户态传入的配置。

## 五、第二版：通过参数配置 PID

更合理的使用方式是启动工具时传入目标 PID：

```bash
sudo RUST_LOG=info cargo run --release -- --tcp-sendmsg-pid 12345
```

此时用户态程序负责解析 `--tcp-sendmsg-pid 12345`，然后把 PID 写入 eBPF map；内核态 eBPF 程序在 kprobe 触发时读取这个 map，再决定是否继续处理当前事件。

完整链路如下：

```text
用户态命令行
  --tcp-sendmsg-pid 12345

用户态 loader
  解析参数得到 pid=12345
  加载 eBPF object
  打开 TCP_SENDMSG_TARGET map
  写入 TcpSendmsgTarget { pid: 12345 }
  attach kprobe:tcp_sendmsg

内核态 eBPF
  tcp_sendmsg 被任意进程触发
  读取当前触发事件的 PID
  从 TCP_SENDMSG_TARGET map 读取目标 PID
  不匹配：直接返回
  匹配：继续读取 tcp_sendmsg 参数和 socket 信息
```

这个版本的核心变化是：PID 不再写死在 eBPF 程序里，而是由用户态在启动时传入。eBPF 程序本身不需要因为目标 PID 改变而重新编译。

## 六、用户态和内核态如何传递数据

这里就引出了 eBPF 开发中非常重要的一个问题：用户态和内核态如何交换数据？

eBPF 程序运行在内核态，普通 Rust loader 运行在用户态。内核态 eBPF 程序不能直接读取用户态变量，用户态程序也不能像调用普通函数一样把参数传给 kprobe。

两边之间最常用的通信方式是 eBPF map。

可以把 eBPF map 理解为由内核管理的一块共享数据结构：

- 用户态程序通过 `bpf(2)` 系统调用读写 map。
- 内核态 eBPF 程序通过 map helper 读写 map。
- map 的生命周期由内核管理。
- 用户态和内核态通过 map 名称、fd、key/value 类型约定访问同一份数据。

在本文这个场景中，PID 配置是从用户态传给内核态，所以我们只需要一个配置 map：

```text
用户态写入：TCP_SENDMSG_TARGET[0] = 12345
内核态读取：target_pid = TCP_SENDMSG_TARGET[0]
```

当前项目里定义的是一个长度为 1 的 `Array` map：

```rust
#[map]
pub static TCP_SENDMSG_TARGET: Array<TcpSendmsgTarget> = Array::with_max_entries(1, 0);
```

为什么用 `Array`？因为这里只保存一个全局目标 PID，不需要复杂 key。`Array` 的 key 是下标，所以固定使用下标 `0`。

```text
TCP_SENDMSG_TARGET[0] = TcpSendmsgTarget { pid: 12345, _pad: 0 }
```

用户态和内核态要共享同一种数据结构。项目里把结构体定义在 `sword-common` 中：

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct TcpSendmsgTarget {
    pub pid: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpSendmsgTarget {}
```

这里有几个细节很重要。

`#[repr(C)]` 用来固定结构体内存布局，避免 Rust 编译器调整字段顺序或布局。

`pid: u32` 保存目标进程 ID。

`_pad: u32` 用来显式补齐结构体大小，避免用户态和内核态对结构体大小理解不一致。

`aya::Pod` 表示用户态 Aya 可以把这个结构体按原始字节写入 map。

用户态写入 map 的逻辑如下：

```rust
fn configure_tcp_sendmsg_target(ebpf: &mut aya::Ebpf, pid: u32) -> anyhow::Result<()> {
    let target = TcpSendmsgTarget { pid, _pad: 0 };
    let mut target_map: Array<MapData, TcpSendmsgTarget> = Array::try_from(
        ebpf.take_map("TCP_SENDMSG_TARGET")
            .ok_or_else(|| anyhow::anyhow!("map TCP_SENDMSG_TARGET not found"))?,
    )?;
    target_map.set(0, target, 0)?;
    Ok(())
}
```

这段代码做了三件事：

1. 把命令行参数里的 PID 包装成 `TcpSendmsgTarget`。
2. 从已加载的 eBPF object 中取出名为 `TCP_SENDMSG_TARGET` 的 map。
3. 把目标 PID 写入下标 `0`。

内核态读取 map 的逻辑如下：

```rust
fn matches_tcp_sendmsg_target() -> Result<bool, u32> {
    let target = TCP_SENDMSG_TARGET.get(0).ok_or(1u32)?;
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    Ok(current_pid == target.pid)
}
```

然后在 kprobe 入口处尽早调用它：

```rust
fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    if !matches_tcp_sendmsg_target()? {
        return Ok(0);
    }

    let sk: *const sock = ctx.arg(0).ok_or(1u32)?;
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    // 这里再继续解析 socket、输出日志或更新指标。

    Ok(0)
}
```

过滤逻辑一定要放在靠前的位置。因为 `tcp_sendmsg` 是系统级 kprobe，机器上任何进程发送 TCP 数据都会触发它。越早返回，就越少做无关工作。

## 七、为什么不能直接把参数传给 kprobe

很多刚接触 eBPF 的时候会有一个疑问：既然 PID 是用户传进来的，为什么不能直接把这个参数传给 kprobe 程序？

原因是 kprobe 程序不是普通函数调用。

用户态 loader 只负责加载 eBPF 程序，并把它 attach 到内核函数上。真正触发 eBPF 程序的是内核里的 `tcp_sendmsg` 调用，而不是用户态 loader。

所以不存在这样的调用方式：

```text
用户态直接调用 tcp_sendmsg_kprobe(pid=12345)
```

实际方式是：

```text
用户态 loader
  load eBPF object
  write pid into eBPF map
  attach kprobe
  keep running

内核态事件
  任意进程调用 tcp_sendmsg
  内核触发 eBPF kprobe 程序
  eBPF 程序从 map 读取目标 PID
  eBPF 程序决定是否处理当前事件
```

这就是 eBPF 工具里常见的控制面和数据面划分：

- 用户态是控制面：解析参数、加载程序、写配置、读取结果、导出指标。
- 内核态是数据面：在事件发生时过滤、采集、聚合。
- eBPF map 是两者之间的共享通道。

## 八、运行验证

先启动一个会发送 HTTP 请求的进程。可以使用项目里的 `rust-mouse net-request`，也可以使用前面的 `TcpStream` 示例。

查看目标 PID：

```bash
pgrep -af rust-mouse
```

假设目标 PID 是 `12345`，启动 sword：

```bash
sudo RUST_LOG=info cargo run --release -- --tcp-sendmsg-pid 12345
```

匹配时会看到类似日志：

```text
tcp_sendmsg pid=12345 tid=12345 family=ipv4 src=192.168.1.10:53122 dst=93.184.216.34:80 size=56
```

如果目标进程是多线程程序，需要注意：

- `pid` 是进程 ID，所有线程共享。
- `tid` 是具体触发 `tcp_sendmsg` 的线程 ID。
- 按进程过滤时比较 `bpf_get_current_pid_tgid() >> 32`。
- 只想跟踪某个线程时，才比较低 32 位 TID。

## 九、继续扩展

当前的 `Array` map 适合保存单个目标 PID。如果要支持多个 PID，可以改成 `HashMap<u32, u8>`：

```text
key = pid
value = 1
```

内核态逻辑变成查询当前 PID 是否存在：

```rust
let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
if TARGET_PIDS.get(&current_pid).is_none() {
    return Ok(0);
}
```

如果要支持运行时修改目标 PID，用户态可以保留 map handle，在程序运行过程中根据配置文件、HTTP API 或命令输入更新 map。eBPF 程序不需要重新加载，下一次 `tcp_sendmsg` 触发时就会读取到新配置。

如果要把采集结果从内核态传回用户态，也可以继续使用 map：

- `PerCpuArray<u64>`：适合全局计数，减少跨 CPU 竞争。
- `HashMap<Key, Value>`：适合按 PID、连接、状态等维度聚合。
- `RingBuf` / `PerfEventArray`：适合把事件流实时推给用户态。

## 总结

本文从一个实际需求出发：我们想跟踪 kprobe、tracepoint 等拦截点，但不希望系统里所有经过该拦截点的进程都被完整采集和打印。因此，需要按 PID 聚焦到目标进程。

以 `tcp_sendmsg` 为例，实现路径可以分成两步。

第一步，把 PID 写死在 eBPF 代码里，先完成功能验证：读取当前 PID，和目标 PID 比较，不匹配就直接返回。

第二步，把 PID 改成用户态参数，通过 eBPF map 写入内核态配置。这样工具启动时传入 `--tcp-sendmsg-pid`，内核态 eBPF 程序就可以读取 map 中的目标 PID，并按它过滤事件。

这个模式不只适用于 `tcp_sendmsg`。只要是系统级拦截点，只要你希望减少无关事件干扰，都可以采用同样的方式：用户态负责配置，内核态负责尽早过滤，eBPF map 负责连接两边。
