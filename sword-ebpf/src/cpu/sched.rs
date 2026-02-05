use core::str;

///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::info;

static mut count: u64 = 0;
const TARGET_PID: u32 = 899461;

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

///
///  在Linux的源码中的实现(6.18内核版本)
///  主实现: kernel/bpf/helpers.c:222-230
///  BPF_CALL_0(bpf_get_current_pid_tgid)
///  {
///        struct task_struct *task = current;
///
///        if (unlikely(!task))
///                return -EINVAL;
///
///        return (u64) task->tgid << 32 | task->pid;
///  }
///
///  从源码可知, bpf_get_current_pid_tgid会返回一个u64(8个字节的数字),结构如下
/// <---高位4个字节:tgid(进程id)---> <---低位4个字节:pid(线程id)--->
///
/// 所以想获取进程id: bpf_get_current_pid_tgid() >> 32
/// 想获取线程id: bpf_get_current_pid_tgid() & 0xFFFFFFFF 或者 bpf_get_current_pid_tgid() as u32(rust的写法,就是强转类型)
///
///
/// 下面是对应的tracepoint:sched:sched_switch的format信息
///
/// name: sched_switch
/// ID: 330
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;

/// 	field:char prev_comm[16];	offset:8;	size:16;	signed:0;
/// 	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
/// 	field:int prev_prio;	offset:28;	size:4;	signed:1;
/// 	field:long prev_state;	offset:32;	size:8;	signed:1;
/// 	field:char next_comm[16];	offset:40;	size:16;	signed:0;
/// 	field:pid_t next_pid;	offset:56;	size:4;	signed:1;
/// 	field:int next_prio;	offset:60;	size:4;	signed:1;

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let thread_id = bpf_get_current_pid_tgid() as u32;
    if thread_id == TARGET_PID {
        unsafe {
            count = count + 1;
            if count % 10 == 0 {
                info!(&ctx, "count: {}", count);
                handle_trace_point_context(&ctx);
            }
        }
    }
    Ok(0)
}

fn handle_trace_point_context(ctx: &TracePointContext) {
    unsafe {
        //1. prev_comm是线程的名字,长度16字节,如果不足16就按照不足的来,如果超过16就截断
        //   反正长度只有16
        let prev_comm = ctx.read_at::<[u8; 16]>(8);
        if let Ok(prev_comm) = prev_comm {
            let mut len = 0;
            for i in 0..16 {
                if prev_comm[i] == 0 {
                    break;
                }
                len = i + 1;
            }
            let comm_str = str::from_utf8_unchecked(&prev_comm[..len]);
            info!(&ctx, "prev_comm: {}", comm_str);
        }
    }
}
