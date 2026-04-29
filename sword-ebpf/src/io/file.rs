///
/// 先从sys_enter_open/sys_enter_openat/sys_enter_openat2/sys_enter_read/write的调用
///
use aya_ebpf::{
    cty::c_long,
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};

const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static SYS_ENTER_OPEN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

fn inc_sys_enter_open_counter() {
    unsafe {
        if let Some(count) = SYS_ENTER_OPEN_COUNTER.get_ptr_mut(0) {
            *count += 1;
        }
    }
}

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1 as u32,
    }
}

///
/// name: sys_enter_open
/// ID: 708
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:const char * filename;    offset:16;      size:8; signed:0;
///         field:int flags;        offset:24;      size:8; signed:0;
///         field:umode_t mode;     offset:32;      size:8; signed:0;
///
/// 注意：filename 是一个指针（指向用户空间），不是内联的字符串数组
/// 需要先读取指针值，然后从用户空间读取字符串内容
///
fn try_sys_enter_open(_ctx: TracePointContext) -> Result<c_long, c_long> {
    inc_sys_enter_open_counter();
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1 as u32,
    }
}

///
/// name: sys_enter_openat
/// ID: 706
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:int dfd;         offset:16;      size:8; signed:0;
///         field:const char * filename;    offset:24;      size:8; signed:0;
///         field:int flags;        offset:32;      size:8; signed:0;
///         field:umode_t mode;     offset:40;      size:8; signed:0;
///
/// 注意：filename 是一个指针（指向用户空间），不是内联的字符串数组
/// 需要先读取指针值，然后从用户空间读取字符串内容
/// dfd 是目录文件描述符（AT_FDCWD 表示当前工作目录）
///
fn try_sys_enter_openat(ctx: TracePointContext) -> Result<c_long, c_long> {
    let _ = ctx;
    inc_sys_enter_open_counter();
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat2(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1 as u32,
    }
}

///
/// name: sys_enter_openat2
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:int dfd;          offset:16;      size:8; signed:0;
///         field:const char * filename;    offset:24;      size:8; signed:0;
///         field:struct open_how * how;    offset:32;      size:8; signed:0;
///         field:size_t size;      offset:40;      size:8; signed:0;
///
/// openat2 的 flags/mode/resolve 在用户空间的 struct open_how 里。
///
fn try_sys_enter_openat2(_ctx: TracePointContext) -> Result<c_long, c_long> {
    inc_sys_enter_open_counter();
    Ok(0)
}
