# 使用 Aya + Rust 开发 eBPF Tracepoint 入门

本文介绍使用 Rust 和 Aya 开发一个 eBPF tracepoint 程序的基本流程。示例目标是观察进程打开文件时触发的内核事件：`syscalls:sys_enter_open`。

参考资料：

- Aya 官方文档：https://aya-rs.dev/book/index.html
- Aya 项目模板：https://github.com/aya-rs/aya-template
- 本文示例项目：https://github.com/liuruishan-2022/open-trace/tree/learn-01

## 1. 开发前需要知道什么

eBPF 是 Linux 内核提供的一套可编程能力。开发者可以编写一小段程序，把它加载到内核中，并挂载到指定事件点上执行。它常用于系统观测、性能分析、网络处理和安全审计等场景。

从理解方式上看，eBPF 有点类似 Java 里的 AOP 思想：Java AOP 是在方法调用前后插入增强逻辑，eBPF 则是在内核事件发生时执行我们挂载上去的程序。比如本文的 `syscalls:sys_enter_open`，就是在进程进入 `open` 系统调用时触发我们编写的 eBPF 逻辑。

eBPF 程序不是直接随意运行在内核中的。加载时，内核会先通过 verifier 检查程序，确认它满足安全约束，例如不能无限循环、不能越界访问内存。检查通过后，程序才会被加载并执行。

tracepoint 是内核已经定义好的事件点，适合入门学习，因为它的字段格式可以直接从系统文件中查看。本文使用 `syscalls:sys_enter_open` 作为示例，当进程进入 `open` 系统调用时，这个 tracepoint 会被触发。

使用 Aya 开发时，通常会有两个 Rust 程序：

```text
open-trace-ebpf/  # eBPF 侧程序，编译后加载到内核执行
open-trace/       # 用户态程序，负责加载、attach、输出日志
```

eBPF 侧负责处理内核事件，用户态侧负责启动和管理 eBPF 程序。本文会按下面流程展开：

```text
准备环境 -> 创建项目 -> 查找 tracepoint -> 编写 eBPF 程序 -> 编写用户态加载逻辑 -> 运行验证
```

## 2. 准备开发环境

根据 Aya 官方文档，开发环境通常需要 Rust stable、Rust nightly、`rust-src`、`bpf-linker`、`cargo-generate` 和 `bpftool`。

安装 Rust 工具链：

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
```

安装项目生成工具和 eBPF linker：

```bash
cargo install cargo-generate
cargo install bpf-linker
```

安装 `bpftool`：

```bash
sudo apt install bpftool
```

不同 Linux 发行版的包名可能不同。如果安装失败，需要根据当前系统查询对应包。

## 3. 创建 Aya 项目

Aya 官方推荐使用 `aya-template` 创建项目：

```bash
cargo generate https://github.com/aya-rs/aya-template
```

生成过程中选择项目名和 eBPF 程序类型。本文要开发 tracepoint，因此选择 tracepoint 类型。

假设项目名为 `open-trace`，生成后会得到类似结构：

```text
open-trace/
open-trace-ebpf/
```

其中：

- `open-trace-ebpf`：编写 eBPF 侧代码。
- `open-trace`：编写用户态加载程序。

## 4. 查找 tracepoint 字段

本文使用 `syscalls:sys_enter_open` 作为入口点。先查看系统是否存在这个 tracepoint：

```bash
sudo ls /sys/kernel/debug/tracing/events/syscalls/
```

查看字段格式：

```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
```

可以看到类似内容：

```text
field:int __syscall_nr;         offset:8;  size:4;
field:const char * filename;    offset:16; size:8;
field:int flags;                offset:24; size:8;
field:umode_t mode;             offset:32; size:8;
```

写 tracepoint 程序时，需要根据 `format` 文件里的 `offset` 和 `size` 读取字段。

这里会用到的字段是：

- `__syscall_nr`：offset `8`
- `filename`：offset `16`
- `flags`：offset `24`
- `mode`：offset `32`

`filename` 的类型是 `const char *`，tracepoint 数据里保存的是用户空间地址。读取文件名时，需要先读取指针，再通过 eBPF helper 读取字符串内容。

如果 `/sys/kernel/debug/tracing` 不存在，可以先挂载 debugfs：

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

## 5. 编写 eBPF 侧程序

tracepoint 程序使用 Aya 的 `#[tracepoint]` 宏，入口函数参数使用 `TracePointContext`。

最小结构如下：

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_open(_ctx: TracePointContext) -> Result<u32, i64> {
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

关键点：

- `#[tracepoint]` 标记这是一个 tracepoint 程序。
- `sys_enter_open` 是 eBPF 程序名，用户态加载时会用到。
- `TracePointContext` 用来读取 tracepoint 事件数据。
- `try_sys_enter_open` 用来放实际处理逻辑。

## 6. 读取 tracepoint 参数

普通字段可以使用 `ctx.read_at` 按 offset 读取：

```rust
fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, i64> {
    let syscall_nr = unsafe { ctx.read_at::<u32>(8)? };
    let flags = unsafe { ctx.read_at::<u64>(24)? };
    let mode = unsafe { ctx.read_at::<u64>(32)? };

    let _ = syscall_nr;
    let _ = flags;
    let _ = mode;

    Ok(0)
}
```

读取时要让 Rust 类型和字段大小匹配：

- 4 字节字段可以用 `u32` 或 `i32`
- 8 字节字段可以用 `u64` 或 `i64`
- 指针在 64 位系统上通常按 8 字节读取

## 7. 读取文件名并输出日志

`filename` 是用户空间指针，需要先读取指针值，再调用 helper 读取字符串。

这个入门示例只读取文件名并打印日志，不需要定义 eBPF map。可以在栈上准备一个较小的临时 buffer：

```rust
use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

const BUF_SIZE: usize = 256;

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, i64> {
    unsafe {
        let filename_addr: u64 = ctx.read_at(16)?;
        let mut buf = [0u8; BUF_SIZE];

        let filename_bytes =
            bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf)?;
        let filename = core::str::from_utf8_unchecked(filename_bytes);

        info!(&ctx, "open filename={}", filename);
    }

    Ok(0)
}
```

代码执行流程：

1. `ctx.read_at(16)` 读取 `filename` 指针。
2. `let mut buf = [0u8; BUF_SIZE]` 准备临时 buffer。
3. `bpf_probe_read_user_str_bytes` 从用户空间读取字符串。
4. `info!` 把日志发送给用户态日志读取器。

后续如果需要跨事件保存状态、向用户态传递统计数据、做计数聚合，或者需要更大的临时空间，可以再引入 `#[map]`。

## 8. 编写用户态加载逻辑

eBPF 程序需要由用户态程序加载并 attach 到 tracepoint。

核心逻辑如下：

```rust
use aya::programs::TracePoint;

let program: &mut TracePoint =
    bpf.program_mut("sys_enter_open").unwrap().try_into()?;

program.load()?;
program.attach("syscalls", "sys_enter_open")?;
```

这里需要保证两个名字一致：

- `bpf.program_mut("sys_enter_open")` 对应 eBPF 侧函数名。
- `program.attach("syscalls", "sys_enter_open")` 对应内核 tracepoint。

完整 tracepoint 名可以理解为：

```text
syscalls:sys_enter_open
```

## 9. 初始化 eBPF 日志

eBPF 侧使用 `aya_log_ebpf::info!` 输出日志：

```rust
use aya_log_ebpf::info;

info!(&ctx, "open filename={}", filename);
```

用户态需要初始化 `aya_log::EbpfLogger`：

```rust
use aya_log::EbpfLogger;
use log::warn;

match EbpfLogger::init(&mut bpf) {
    Ok(logger) => {
        // 在异步程序里通常需要把 logger 注册到 async runtime，
        // 当 fd 可读时调用 flush()。
    }
    Err(e) => {
        warn!("failed to initialize eBPF logger: {e}");
    }
}
```

使用 Tokio 时，可以用 `tokio::io::unix::AsyncFd` 监听 logger，并在可读时调用 `flush()`。

## 10. 编译和运行

在项目根目录执行：

```bash
cargo build
```

运行 eBPF 程序通常需要 root 权限：

```bash
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

也可以直接运行：

```bash
sudo -E RUST_LOG=info cargo run
```

程序启动后，另开一个终端触发文件打开：

```bash
cat /etc/hosts >/dev/null
ls >/dev/null
```

如果 eBPF 侧已经写了 `info!`，用户态也正确初始化了 `EbpfLogger`，就可以在运行程序的终端看到类似日志：

```text
open filename=/etc/hosts
```

注意：`syscalls:sys_enter_open` 是系统级 tracepoint，不只会捕获你手动执行的 `cat` 或 `ls`，系统里其他进程打开文件时也会触发它。因此日志可能会非常多，入门调试时不一定容易分辨哪一条属于自己关注的进程。实际排查时可以先减少系统干扰，或者后续在 eBPF 侧增加 pid、进程名、路径前缀等过滤条件。

## 11. 查看加载结果

查看当前已加载的 eBPF 程序：

```bash
sudo bpftool prog list
```

查看当前已创建的 eBPF map：

```bash
sudo bpftool map list
```

如果程序加载失败，可以优先检查：

- 是否使用 root 权限运行。
- `syscalls:sys_enter_open` 是否存在。
- `program.attach("syscalls", "sys_enter_open")` 的名字是否正确。
- eBPF 日志初始化是否完成。
- `RUST_LOG=info` 是否生效。

## 小结

Aya + Rust 开发 tracepoint 的入门流程可以概括为：

```text
创建项目 -> 查看 tracepoint format -> 编写 eBPF 函数 -> 用户态 load 和 attach -> 初始化日志 -> 运行验证
```

掌握这个流程后，就可以继续学习 eBPF map、perf event、ring buffer、kprobe、uprobes、XDP 等更完整的 eBPF 开发能力。
