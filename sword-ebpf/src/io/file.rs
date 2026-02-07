///
/// 先从sys_enter_open/sys_enter_openat/sys_enter_read/write的调用
///
use aya_ebpf::{macros::tracepoint, programs::TracePointContext, helpers::bpf_probe_read_user};
use aya_log_ebpf::{info, warn};
use core::str;

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
fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        // 读取 __syscall_nr
        let syscall_nr = ctx.read_at::<u32>(8);
        match syscall_nr {
            Ok(nr) => info!(&ctx, "sys_enter_open syscall_nr: {}", nr),
            Err(_) => warn!(&ctx, "read __syscall_nr error"),
        }

        // 读取 filename 指针（const char * 是 8 字节的指针）
        let filename_ptr = ctx.read_at::<u64>(16);
        if let Ok(ptr) = filename_ptr {
            if ptr != 0 {
                // 从用户空间读取字符串，最多读取 255 字节（保留 1 字节给 null 终止符）
                let mut filename_buf = [0u8; 256];
                let src_ptr = ptr as *const u8;

                // 逐字节读取，直到遇到 null 终止符或读取满 255 字节
                let mut len = 0;
                while len < 255 {
                    let byte_ptr = src_ptr.add(len);
                    match bpf_probe_read_user(byte_ptr) {
                        Ok(b) => {
                            if b == 0 {
                                break;
                            }
                            filename_buf[len] = b;
                            len += 1;
                        }
                        Err(_) => {
                            warn!(&ctx, "read filename byte at offset {} failed", len);
                            break;
                        }
                    }
                }

                if len > 0 {
                    let filename_str = str::from_utf8_unchecked(&filename_buf[..len]);
                    info!(&ctx, "filename: {}", filename_str);
                } else {
                    warn!(&ctx, "filename is empty");
                }
            } else {
                warn!(&ctx, "filename pointer is null");
            }
        } else {
            warn!(&ctx, "read filename pointer error");
        }

        // 读取 flags
        let flags = ctx.read_at::<u64>(24);
        match flags {
            Ok(f) => info!(&ctx, "flags: {}", f),
            Err(_) => warn!(&ctx, "read flags error"),
        }

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
