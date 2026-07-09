# 如何使用 PID 过滤 eBPF 事件

做 eBPF 观测时，经常不是抓不到数据，而是数据太多。

比如只想看服务 A 的 TCP 连接行为，直接把 `tcp_v4_connect`、`tcp_sendmsg`、`sched_switch` 这类事件挂上去，系统里所有进程都会触发日志。服务 B、服务 C、系统基础服务都在产生事件，终端很快被刷屏，真正关心的目标进程反而不好找。

这种全量采集还有两个问题：

- 排查效率低：日志里混着大量无关进程，很难快速定位目标服务。
- 运行成本高：eBPF 程序虽然轻量，但每个事件都执行过滤、日志和 map 操作，事件量大时仍然会影响系统。

所以我们需要一个基础能力：只观测指定进程。

常见做法有两种：

```text
方案 1：在 eBPF 代码里写死 PID。
方案 2：通过启动参数指定 PID，再由用户态写入 eBPF Map，内核态从 Map 读取 PID 并过滤事件。
```

写 demo 时可以先用第一种；只要希望运行时灵活切换目标进程，就需要第二种。

## 方案 1：在 eBPF 代码里写死 PID

最直接的方案，是在 eBPF 程序里直接判断当前进程 ID：

```rust
let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
if current_pid != 12345 {
    return Ok(0);
}
```

这样确实可以过滤掉无关进程。只有 PID 为 `12345` 的进程会继续执行后面的逻辑。

这个方案的问题也很直接：PID 每次启动都可能变化。今天要看服务 A，PID 是 `12345`；明天重启后可能变成 `23456`。如果 PID 写死在 eBPF 代码里，每换一次目标进程就要改代码、重新编译、重新加载。

其次，eBPF 程序运行在内核侧，它更适合做“快速判断”和“数据采集”，不适合放太多环境相关配置。目标 PID 是运行时配置，不是程序逻辑。

所以写死 PID 只能作为验证思路，不能作为项目长期方案。

## 方案 2：通过参数传递 PID

实际项目里更常用的方式是：

```text
用户态负责读取启动参数。
eBPF Map 负责承载运行时配置。
内核态 eBPF 程序负责读取 Map 并尽早过滤。
```

目标 PID 不再写死在 eBPF 代码中，而是在程序启动时通过参数传入。

运行时可以通过命令行参数指定：

```bash
sudo RUST_LOG=info cargo run --release -- --target-pid 12345
```

用户态程序从命令行参数里拿到目标 PID，再写入 eBPF Map。内核态 eBPF 程序每次事件触发时，从 Map 里读出目标 PID，和当前事件的 PID 做比较。

完整链路是：

```text
启动参数
    -> 用户态解析出 target_pid
    -> 用户态打开 eBPF Map
    -> 用户态把 target_pid 写入 Map[0]
    -> eBPF 程序在内核态读取 Map[0]
    -> eBPF 程序比较 current_pid 和 target_pid
    -> 不匹配则直接 return
```

### 用户态读取参数

用户态可以先定义一个加载配置结构：

```rust
#[derive(Debug)]
pub struct LoaderOptions {
    pub target_pid: Option<u32>,
}
```

命令行参数解析建议直接使用 `clap`，而不是手写 `std::env::args`。用户态程序就是普通 Rust 程序，可以自由使用 `std`、`clap`、`anyhow`、日志库和其他三方 crate。限制主要在 eBPF 内核态程序里：eBPF 侧通常是 `no_std` 环境，还要受 verifier、栈大小、循环和内存访问规则限制，所以参数解析这类事情应该放在用户态完成。

示例：

```rust
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "observer")]
pub struct Cli {
    #[arg(long = "target-pid")]
    pub target_pid: Option<u32>,
}

fn parse_loader_options() -> LoaderOptions {
    let cli = Cli::parse();
    LoaderOptions {
        target_pid: cli.target_pid,
    }
}
```

解析完成后，加载逻辑只需要读取 `LoaderOptions.target_pid`。

### 用户态通过 eBPF Map 传给内核态

eBPF 程序和用户态程序之间最常见的通信方式是 Map。

先定义一个用户态和 eBPF 侧共享的结构体：

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct TargetPid {
    pub pid: u32,
    pub _pad: u32,
}
```

这里使用 `#[repr(C)]`，是为了保证结构体内存布局在用户态和 eBPF 侧一致。`_pad` 用来补齐结构体大小，避免跨边界读写时出现对齐问题。

eBPF 侧定义一个 `Array` Map：

```rust
#[map]
pub static TARGET_PID: Array<TargetPid> = Array::with_max_entries(1, 0);
```

这个 Map 只有一个元素，索引 `0` 存当前目标 PID。

用户态在加载 kprobe 前，把参数里的 PID 写进去：

```rust
fn configure_target_pid(ebpf: &mut aya::Ebpf, pid: u32) -> anyhow::Result<()> {
    let target = TargetPid { pid, _pad: 0 };
    let map = ebpf
        .map_mut("TARGET_PID")
        .ok_or_else(|| anyhow::anyhow!("map TARGET_PID not found"))?;

    let mut target_map = Array::<_, TargetPid>::try_from(map)?;
    target_map.set(0, target, 0)?;

    Ok(())
}
```

这里的 `"TARGET_PID"` 不是随便起的字符串，它必须和 eBPF 侧定义的 Map 名称保持一致：

```rust
#[map]
pub static TARGET_PID: Array<TargetPid> = Array::with_max_entries(1, 0);
```

Aya 加载 eBPF object 后，会把 eBPF 程序里的 Map 暴露给用户态。用户态通过 `ebpf.map_mut("TARGET_PID")` 按名称查找这个 Map，然后把 PID 写进去。

可以把这个过程理解成：

```text
eBPF 侧声明 Map：
    pub static TARGET_PID

编译后进入 eBPF object：
    Map 名称仍然是 TARGET_PID

用户态加载 object：
    aya::Ebpf::load(...)

用户态按名称查找 Map：
    ebpf.map_mut("TARGET_PID")
```

所以如果 eBPF 侧把 Map 改名为 `TARGET_PROCESS`，用户态也必须同步改成：

```rust
ebpf.map_mut("TARGET_PROCESS")
```

否则用户态找不到对应 Map，就会返回 `map TARGET_PID not found`。

这一步完成了从用户态到内核态的配置传递：

```text
用户态变量 pid
    -> aya::Ebpf::map_mut("TARGET_PID")
    -> Array::set(0, TargetPid { pid })
    -> 内核态 eBPF Map
```

### 内核态读取 Map 并过滤事件

在 eBPF 程序里，事件一进来就读取当前 PID：

```rust
let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
```

然后读取 `TARGET_PID` Map：

```rust
fn matches_target_pid() -> Result<bool, u32> {
    let target = TARGET_PID.get(0).ok_or(1u32)?;
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    Ok(current_pid == target.pid)
}
```

在具体 hook 里，过滤逻辑应该放在最前面：

```rust
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    if !matches_target_pid()? {
        return Ok(0);
    }

    let sk: *const sock = ctx.arg(0).ok_or(1u32)?;
    let size: usize = ctx.arg(2).ok_or(1u32)?;

    // 只有目标进程才会继续解析 socket、读取字段、打印日志或更新指标。
    Ok(0)
}
```

这个判断要尽量靠前。只有确认是目标进程之后，才有必要继续读取 socket、解析地址、打印日志或更新 Map。

这里的原则很简单：

```text
越早过滤，越少开销。
```

### 只在有目标 PID 时加载对应 hook

如果没有传 `--target-pid`，可以选择不加载对应的 kprobe。

```rust
pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    if let Some(pid) = options.target_pid {
        configure_target_pid(ebpf, pid)?;

        KProberConfig::new("tcp_v4_connect", "tcp_v4_connect").load_kprobe(ebpf)?;
        KProberConfig::new("tcp_sendmsg", "tcp_sendmsg").load_kprobe(ebpf)?;
    }

    Ok(())
}
```

这样处理有两个好处：

- 没有目标 PID 时不会误做全量采集。
- 不会无意义地 attach 高频 hook，减少运行时开销。

## 运行方式

先找到目标进程：

```bash
pgrep -a -f 'service-a|service-b|service-c'
```

假设目标 PID 是 `12345`，运行：

```bash
sudo RUST_LOG=info cargo run --release -- --target-pid 12345
```

然后触发目标服务的网络行为，输出里就只会保留目标 PID 对应的 eBPF 事件。

## 小结

两种方案的差异可以压缩成一句话：

```text
写死 PID：
  简单，适合验证，但每次换目标都要改代码和重新编译。

参数传 PID：
  用户态读取启动参数，通过 eBPF Map 写入内核态，eBPF 程序从 Map 读取目标 PID 并过滤事件。
```

实际调试时，推荐使用第二种。PID 这类运行时配置由用户态传入，内核态只负责尽早判断和过滤。
