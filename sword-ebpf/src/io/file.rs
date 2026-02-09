///
/// 先从sys_enter_open/sys_enter_openat/sys_enter_read/write的调用
///
use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use core::str;

const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
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
        // 读取 __syscall_nr
        let syscall_nr = ctx.read_at::<u32>(8);
        match syscall_nr {
            Ok(nr) => info!(&ctx, "sys_enter_open syscall_nr: {}", nr),
            Err(_) => warn!(&ctx, "read __syscall_nr error"),
        }

        let filename: u64 = ctx.read_at(16)?;
        let ptr = {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };

        let filename = {
            let len = bpf_probe_read_user_str_bytes(filename as *const u8, &mut ptr.buf)?;
            core::str::from_utf8_unchecked(len)
        };

        info!(&ctx, "filename: {}", filename);

        // 读取 flags
        let flags = ctx.read_at::<u64>(24)?;
        info!(&ctx, "flags: {}", flags);

        // 读取 mode
        let mode = ctx.read_at::<u64>(32);
        match mode {
            Ok(m) => {
                // 将 mode 转换为十进制和十六进制显示
                let mode_val = m as u32;
                info!(&ctx, "mode: {} (0x{:x})", mode_val, mode_val);
            }
            Err(_) => warn!(&ctx, "read mode error"),
        }
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
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
        let syscall_nr = ctx.read_at::<u32>(8);
        match syscall_nr {
            Ok(nr) => info!(&ctx, "sys_enter_openat syscall_nr: {}", nr),
            Err(_) => warn!(&ctx, "read __syscall_nr error"),
        }

        // 读取 dfd (目录文件描述符)
        let dfd: u64 = ctx.read_at(16)?;
        // AT_FDCWD 通常定义为 -100 (0xFFFFFFFFFFFFFF9C)
        if dfd == 0xFFFFFFFFFFFFFF9C {
            info!(&ctx, "dfd: AT_FDCWD (current working directory)");
        } else {
            info!(&ctx, "dfd: {}", dfd);
        }

        let filename: u64 = ctx.read_at(24)?;
        let ptr = {
            let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
            &mut *ptr
        };

        let filename = {
            let len = bpf_probe_read_user_str_bytes(filename as *const u8, &mut ptr.buf)?;
            core::str::from_utf8_unchecked(len)
        };

        info!(&ctx, "filename: {}", filename);

        // 读取 flags
        let flags: u64 = ctx.read_at(32)?;
        info!(&ctx, "flags: {}", flags);

        // 读取 mode
        let mode: u64 = ctx.read_at(40)?;
        let mode_val = mode as u32;
        info!(&ctx, "mode: {} (0x{:x})", mode_val, mode_val);
    }
    Ok(0)
}
