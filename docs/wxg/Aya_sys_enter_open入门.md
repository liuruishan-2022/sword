# 使用 Aya 编写 sys_enter_open 入门例子

本文基于本项目里的 `sword-ebpf/src/io/file.rs`，说明如何用 Aya 编写一个跟踪 `sys_enter_open` 的 eBPF 程序。目标不是一次讲完 eBPF，而是先建立一个能跑通的心智模型。

## 1. eBPF 是什么

eBPF 可以理解为 Linux 内核提供的一套安全插件机制。我们可以把一小段程序加载到内核，在指定事件发生时执行，例如：

- 系统调用进入时
- 函数执行前后
- 网络包进入网卡时
- CPU 调度切换时
- 文件读写发生时

这些程序运行在内核里，但不能随便做危险操作。eBPF verifier 会在加载前检查程序，确保它不会越界访问、不会无限循环、不会破坏内核。

在本项目里，我们用 Rust + Aya 来写 eBPF 程序。Aya 做的事情主要是：

- 在 eBPF 侧提供宏和类型，例如 `#[tracepoint]`、`TracePointContext`
- 在用户态加载 eBPF 程序
- 把 eBPF map 暴露给用户态读取
- attach 到内核 tracepoint

## 2. 用 Java AOP 来理解 eBPF tracepoint

如果你熟悉 Java，可以把 eBPF tracepoint 类比成 Linux 内核里的 AOP。

在 Java 里，AOP 大概是这样：

```java
@Around("execution(* com.example.FileService.open(..))")
public Object aroundOpen(ProceedingJoinPoint pjp) {
    // 方法执行前采集参数
    Object[] args = pjp.getArgs();

    // 继续执行原方法
    Object result = pjp.proceed();

    // 方法执行后记录结果
    return result;
}
```

对应到 eBPF tracepoint：

| Java AOP | eBPF / Aya |
| --- | --- |
| Pointcut | tracepoint，例如 `syscalls:sys_enter_open` |
| Advice | eBPF 程序，例如 `sys_enter_open(ctx)` |
| JoinPoint | 内核事件发生点 |
| 方法参数 | `TracePointContext` 里的字段 |
| 共享状态 | eBPF map |
| 日志/指标 | 用户态读取 map 或 eBPF log |

所以，`sys_enter_open` 可以理解为：

> 当任意进程进入 `open` 系统调用时，内核自动回调我们的 eBPF 函数。

这和 Java AOP 最大的区别是：eBPF 的切点发生在 Linux 内核层，不是在 JVM 内部。

## 3. sys_enter_open 的 tracepoint 格式

要读取 tracepoint 参数，第一步是查看内核提供的 format：

```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
```

本项目 `file.rs` 中记录的格式类似：

```text
field:int __syscall_nr;         offset:8;  size:4;
field:const char * filename;    offset:16; size:8;
field:int flags;                offset:24; size:8;
field:umode_t mode;             offset:32; size:8;
```

关键点：

- `__syscall_nr` 在 offset `8`
- `filename` 在 offset `16`
- `flags` 在 offset `24`
- `mode` 在 offset `32`

这里最容易踩坑的是 `filename`。

`filename` 不是直接嵌在 tracepoint 数据里的字符串，而是一个用户空间地址：

```text
const char * filename
```

所以读取分两步：

1. 先从 tracepoint payload 里读取这个地址
2. 再用 `bpf_probe_read_user_str_bytes` 从用户空间读取字符串内容

## 4. eBPF 侧代码结构

本项目的代码在：

```text
sword-ebpf/src/io/file.rs
```

一个最小的 `sys_enter_open` tracepoint 程序结构如下：

```rust
use aya_ebpf::{
    cty::c_long,
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1,
    }
}
```

这里有几个核心点。

`#[tracepoint]` 表示这是一个 tracepoint 类型的 eBPF 程序。函数名 `sys_enter_open` 后面会在用户态 loader 里用到。

`TracePointContext` 是 Aya 提供的上下文对象，可以通过 offset 读取 tracepoint payload。

`BUF` 是一个 `PerCpuArray`。它的作用是给每个 CPU 准备一块临时 buffer，用来读取用户空间字符串。eBPF 栈空间很小，不适合直接在栈上放很大的数组，所以这里用 map 来放 `1024` 字节 buffer。

## 5. 读取普通字段

普通整数字段可以直接用 `ctx.read_at`：

```rust
let syscall_nr = ctx.read_at::<u32>(8)?;
let flags = ctx.read_at::<u64>(24)?;
let mode = ctx.read_at::<u64>(32)?;

info!(&ctx, "sys_enter_open syscall_nr: {}", syscall_nr);
info!(&ctx, "flags: {}", flags);
info!(&ctx, "mode: {} (0x{:x})", mode, mode);
```

这里的 offset 来自 tracepoint format。

注意，`read_at::<T>(offset)` 里的 `T` 要和字段大小匹配。比如 offset `8` 的 `__syscall_nr` 是 4 字节，所以用 `u32` 或 `i32`；`flags` 和 `mode` 在当前 format 中 size 是 8，所以代码里用了 `u64`。

## 6. 读取 filename 字符串

`filename` 是指针，所以不能这样读：

```rust
let filename = ctx.read_at::<[u8; 256]>(16)?;
```

这是错的。offset `16` 位置放的是地址，不是字符串本体。

正确方式：

```rust
let filename_addr: u64 = ctx.read_at(16)?;
let buf = {
    let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
    &mut *ptr
};

let filename = {
    let len = bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf.buf)?;
    core::str::from_utf8_unchecked(len)
};

info!(&ctx, "sys_enter_open filename: {}", filename);
```

这段代码可以拆开理解：

- `ctx.read_at(16)`：读取 `filename` 指针值
- `BUF.get_ptr_mut(0)`：拿到当前 CPU 对应的临时 buffer
- `bpf_probe_read_user_str_bytes`：从用户空间地址读取 C 字符串
- `from_utf8_unchecked`：把字节转成 `&str`

在 eBPF 里经常会看到 `unsafe`，因为很多操作涉及裸指针、内核 helper、用户空间地址读取。这里的安全边界主要由 eBPF verifier 和 helper 函数保证。

## 7. 完整 try_sys_enter_open 示例

可以把 `try_sys_enter_open` 写成：

```rust
fn try_sys_enter_open(ctx: TracePointContext) -> Result<c_long, c_long> {
    unsafe {
        let syscall_nr = ctx.read_at::<u32>(8)?;
        let flags = ctx.read_at::<u64>(24)?;
        let mode = ctx.read_at::<u64>(32)?;

        let filename_addr: u64 = ctx.read_at(16)?;
        let buf = {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };

        let filename = {
            let len = bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf.buf)?;
            core::str::from_utf8_unchecked(len)
        };

        info!(
            &ctx,
            "sys_enter_open nr={} filename={} flags={} mode=0x{:x}",
            syscall_nr,
            filename,
            flags,
            mode
        );
    }

    Ok(0)
}
```

这个版本只是入门调试用。真实生产场景不建议对每次 `open` 都 `info!`，因为系统调用频率很高，日志输出会明显影响性能。

更适合生产的方式是：

- eBPF 侧只做计数或采样
- 用 map 聚合数据
- 用户态定期读取 map
- 暴露成 Prometheus 指标

本项目的 `sched_switch` 指标已经采用了这种思路。

## 8. 用户态加载程序

用户态 loader 在：

```text
sword/src/loader/io.rs
```

加载 `sys_enter_open` 的代码是：

```rust
use aya::programs::TracePoint;

pub fn load_sys_enter_open(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_open").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_open")?;
    Ok(())
}
```

这里的对应关系很重要：

```rust
ebpf.program_mut("sys_enter_open")
```

对应 eBPF 侧的函数名：

```rust
#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32
```

而：

```rust
program.attach("syscalls", "sys_enter_open")?;
```

对应内核 tracepoint：

```text
/sys/kernel/debug/tracing/events/syscalls/sys_enter_open
```

也就是：

```text
category = syscalls
name     = sys_enter_open
```

## 9. open 和 openat 的区别

本项目里还有 `sys_enter_openat`。它和 `sys_enter_open` 的核心区别是参数布局不同。

`sys_enter_open`：

```text
filename offset: 16
flags    offset: 24
mode     offset: 32
```

`sys_enter_openat`：

```text
dfd      offset: 16
filename offset: 24
flags    offset: 32
mode     offset: 40
```

所以同样是读取 filename：

```rust
// open
let filename_addr: u64 = ctx.read_at(16)?;

// openat
let filename_addr: u64 = ctx.read_at(24)?;
```

这也是写 tracepoint 程序时最重要的习惯：不要凭感觉猜参数位置，要先看 `/sys/kernel/debug/tracing/events/.../format`。

## 10. 小结

用 Aya 写一个 tracepoint 程序，可以按这个流程理解：

1. 找到内核 tracepoint，例如 `syscalls:sys_enter_open`
2. 查看 format，确认每个字段的 offset 和 size
3. 在 eBPF 侧用 `#[tracepoint]` 编写处理函数
4. 用 `TracePointContext::read_at` 读取普通字段
5. 遇到用户空间指针，用 `bpf_probe_read_user_str_bytes` 读取真实内容
6. 用户态用 Aya loader 加载并 attach 到对应 tracepoint
7. 调试阶段可以用 `aya_log_ebpf::info!`
8. 生产阶段优先使用 map 聚合，再由用户态暴露指标

用 Java AOP 的话来概括：

> eBPF tracepoint 就是在 Linux 内核事件上的 AOP。我们不是增强某个 Java 方法，而是在增强一个内核事件，比如系统调用进入、调度切换、网络收包。

