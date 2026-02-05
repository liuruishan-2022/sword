# eBPF Tracepoint 字段读取指南

本文档说明如何从 `tracepoint:sched:sched_switch` 的 format 信息中读取对应字段。

## Format 信息分析

```bash
# 查看 sched_switch 的 format 信息
cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
```

输出：
```
name: sched_switch
ID: 330
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:char prev_comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
	field:int prev_prio;	offset:28;	size:4;	signed:1;
	field:long prev_state;	offset:32;	size:8;	signed:1;
	field:char next_comm[16];	offset:40;	size:16;	signed:0;
	field:pid_t next_pid;	offset:56;	size:4;	signed:1;
	field:int next_prio;	offset:60;	size:4;	signed:1;
```

## 内存布局图

```
Offset  +0   +1   +2   +3   +4   +5   +6   +7   +8   +9   +10  +11  +12  +13  +14  +15
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x00   | common_type  | flg| pre|     common_pid        |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x10   |                        prev_comm[16]                          |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x20   |           prev_comm               | prev_pid    | prev_prio   |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x30   |                          prev_state                             |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x40   |                        next_comm[16]                          |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
0x50   |           next_comm               | next_pid    | next_prio   |
        +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
```

## 读取方法

### 方法 1: ctx.load() - 读取单个字段

```rust
use aya_ebpf::programs::TracePointContext;

// 读取 prev_pid (offset 24, 类型 i32)
if let Ok(prev_pid) = ctx.load::<i32>(24) {
    info!(&ctx, "prev_pid: {}", prev_pid);
}

// 读取 next_pid (offset 56, 类型 i32)
if let Ok(next_pid) = ctx.load::<i32>(56) {
    info!(&ctx, "next_pid: {}", next_pid);
}

// 读取 prev_state (offset 32, 类型 i64)
if let Ok(prev_state) = ctx.load::<i64>(32) {
    info!(&ctx, "prev_state: {}", prev_state);
}
```

**适用场景**：
- 只需要读取少量字段
- 字段是基本类型（i32, i64, u32 等）

### 方法 2: ctx.load_bytes() - 读取整个结构

```rust
// 读取整个事件数据（64字节）
let mut event_bytes = [0u8; 64];
if let Ok(()) = ctx.load_bytes(0, &mut event_bytes) {
    // 从字节数组中提取字段

    // prev_pid 在 offset 24
    let prev_pid = i32::from_le_bytes([
        event_bytes[24], event_bytes[25],
        event_bytes[26], event_bytes[27],
    ]);

    // next_pid 在 offset 56
    let next_pid = i32::from_le_bytes([
        event_bytes[56], event_bytes[57],
        event_bytes[58], event_bytes[59],
    ]);

    info!(&ctx, "switch: {} -> {}", prev_pid, next_pid);
}
```

**适用场景**：
- 需要读取多个字段
- 需要一次性获取所有数据

### 方法 3: 定义结构体并读取

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedSwitchEvent {
    // Common fields
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,

    // Previous task
    pub prev_comm: [u8; 16],
    pub prev_pid: i32,
    pub prev_prio: i32,
    pub prev_state: i64,

    // Next task
    pub next_comm: [u8; 16],
    pub next_pid: i32,
    pub next_prio: i32,
}

// 读取到结构体
let mut event: SchedSwitchEvent = unsafe { core::mem::zeroed() };
let event_bytes = unsafe {
    core::slice::from_raw_parts_mut(
        &mut event as *mut _ as *mut u8,
        core::mem::size_of::<SchedSwitchEvent>(),
    )
};
if let Ok(()) = ctx.load_bytes(0, event_bytes) {
    info!(&ctx, "prev: {}, next: {}", event.prev_pid, event.next_pid);
}
```

**适用场景**：
- 需要结构化访问所有字段
- 代码需要清晰易读

### 方法 4: 读取字符串字段

对于 `prev_comm` 和 `next_comm` 这类字符串数组：

```rust
// 读取 prev_comm (offset 8)
let mut comm_bytes = [0u8; 16];
if let Ok(()) = ctx.load_bytes(8, &mut comm_bytes) {
    // 找到字符串结束符
    let len = comm_bytes.iter()
        .position(|&b| b == 0)
        .unwrap_or(16);

    // 转换为字符串（unsafe 方式）
    let comm_str = unsafe {
        core::str::from_utf8_unchecked(&comm_bytes[..len])
    };

    info!(&ctx, "comm: {}", comm_str);
}

// 或使用辅助函数
if let Ok(()) = ctx.load_bytes(8, &mut comm_bytes) {
    let comm_str = unsafe { bytes_to_str(&comm_bytes) };
    info!(&ctx, "comm: {}", comm_str);
}
```

## 字段映射表

| 字段名 | Offset | 大小 | 类型 | 读取方法 |
|--------|--------|------|------|----------|
| common_type | 0 | 2 | u16 | `ctx.load::<u16>(0)` |
| common_flags | 2 | 1 | u8 | `ctx.load::<u8>(2)` |
| common_preempt_count | 3 | 1 | u8 | `ctx.load::<u8>(3)` |
| common_pid | 4 | 4 | i32 | `ctx.load::<i32>(4)` |
| prev_comm | 8 | 16 | [u8; 16] | `ctx.load_bytes(8, &mut buf)` |
| prev_pid | 24 | 4 | i32 | `ctx.load::<i32>(24)` |
| prev_prio | 28 | 4 | i32 | `ctx.load::<i32>(28)` |
| prev_state | 32 | 8 | i64 | `ctx.load::<i64>(32)` |
| next_comm | 40 | 16 | [u8; 16] | `ctx.load_bytes(40, &mut buf)` |
| next_pid | 56 | 4 | i32 | `ctx.load::<i32>(56)` |
| next_prio | 60 | 4 | i32 | `ctx.load::<i32>(60)` |

## 完整示例

```rust
use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let thread_id = bpf_get_current_pid_tgid() as u32;

    // 只处理特定 PID
    if thread_id != TARGET_PID {
        return Ok(0);
    }

    // 读取 prev_pid
    if let Ok(prev_pid) = ctx.load::<i32>(24) {
        // 读取 next_pid
        if let Ok(next_pid) = ctx.load::<i32>(56) {
            // 读取 prev_state
            if let Ok(prev_state) = ctx.load::<i64>(32) {
                info!(&ctx, "switch: {}(state:{}) -> {}",
                    prev_pid, prev_state, next_pid);
            }
        }
    }

    Ok(0)
}
```

## 注意事项

1. **字节序**：Linux x86_64 使用小端序（Little-Endian），使用 `from_le_bytes`
2. **对齐**：结构体使用 `#[repr(C)]` 确保正确的内存布局
3. **验证**：始终检查 `ctx.load()` 和 `ctx.load_bytes()` 的返回值
4. **字符串**：C 字符串以 `\0` 结尾，需要手动处理
5. **性能**：优先使用 `ctx.load()` 读取单个字段，避免不必要的内存拷贝

## 其他 Tracepoint

对于其他 tracepoint，步骤相同：

1. 查看 format 信息：
   ```bash
   cat /sys/kernel/debug/tracing/events/<category>/<event>/format
   ```

2. 记录每个字段的 offset 和 size

3. 使用对应的 offset 读取字段

4. 对于数组类型（如 `char name[32]`），使用 `ctx.load_bytes()`
