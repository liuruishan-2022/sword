use core::ops::Add;

///
/// 先从sys_enter_open/sys_enter_openat/sys_enter_read/write的调用
///
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

#[map]
pub static SYS_ENTER_OPEN_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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
fn try_sys_enter_open(ctx: TracePointContext) -> Result<c_long, c_long> {
    unsafe {
        if let Some(count) = SYS_ENTER_OPEN_COUNTER.get_ptr_mut(0) {
            *count += 1;
        }
        // 读取 __syscall_nr
        //let syscall_nr = ctx.read_at::<u32>(8)?;
        //info!(&ctx, "sys_enter_open syscall_nr: {}", syscall_nr);

        //let flags = ctx.read_at::<u64>(24)?;
        //info!(&ctx, "flags: {}", flags);
        //let mode = ctx.read_at::<u64>(32)?;
        //info!(&ctx, "mode: {} (0x{:x})", mode, mode);
    }
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
    unsafe {
        // 读取 __syscall_nr
        let syscall_nr = ctx.read_at::<u32>(8)?;
        info!(&ctx, "sys_enter_openat syscall_nr: {}", syscall_nr);
        let flags: u64 = ctx.read_at(32)?;
        info!(&ctx, "flags: {}", flags);
        let mode: u64 = ctx.read_at(40)?;
        let mode_val = mode as u32;
        info!(&ctx, "mode: {} (0x{:x})", mode_val, mode_val);

        //专门的读取filename这个信息,这个地方要注意,这个filename是一个指针,不是字符数组

        let filename_addr: u64 = ctx.read_at(24)?;
        let buf = {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };

        let filename = {
            let len = bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf.buf)?;
            core::str::from_utf8_unchecked(len)
        };

        info!(&ctx, "使用eBPF的Map获取到filename: {}", filename);
    }
    Ok(0)
}
