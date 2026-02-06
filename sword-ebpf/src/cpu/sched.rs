use core::str;

///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};

static mut count: u64 = 0;
const TARGET_PID: u32 = 936909;

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
///
/// 字段解析:
/// prev_comm: 上一个进程的名字,
/// prev_pid:上一个进程的id,
/// prev_prio: 上一个进程的优先级,一般是120这个中间值
/// prev_state: 上一个进程的状态
/// 同理next也是这样子

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
        let prev_pid = ctx.read_at::<i32>(24);
        match prev_pid {
            Ok(prev_pid) => {
                info!(&ctx, "prev_pid: {}", prev_pid);
            }
            Err(_) => {
                info!(&ctx, "获取prev_pid错误");
            }
        }
        let prev_prio = ctx.read_at::<u32>(28);
        match prev_prio {
            Ok(prev_prio) => {
                info!(&ctx, "prev_prio: {}", prev_prio);
            }
            Err(_) => {
                info!(&ctx, "获取prev_prio错误");
            }
        }
        let prev_state = ctx.read_at::<u64>(32);
        match prev_state {
            Ok(prev_state) => {
                info!(&ctx, "prev_state: {}", prev_state);
            }
            Err(_) => {
                info!(&ctx, "获取prev_state错误");
            }
        }
        let next_comm = ctx.read_at::<[u8; 16]>(40);
        if let Ok(next_comm) = next_comm {
            let mut len = 0;
            for i in 0..16 {
                if next_comm[i] == 0 {
                    len = i;
                    break;
                }
            }
            info!(
                &ctx,
                "next_comm: {}",
                str::from_utf8_unchecked(&next_comm[..len])
            );
        }

        let prev_pid = ctx.read_at::<u32>(56);
        match prev_pid {
            Ok(prev_pid) => {
                info!(&ctx, "next_pid: {}", prev_pid);
            }
            Err(_) => {
                info!(&ctx, "获取next_pid错误");
            }
        }
        let next_prio = ctx.read_at::<u32>(60);
        match next_prio {
            Ok(next_prio) => {
                info!(&ctx, "next_prio: {}", next_prio);
            }
            Err(_) => {
                info!(&ctx, "获取next_prio错误");
            }
        }
    }
}

///
/// 继续跟踪: sched_wakeup这个tracepoint
/// name: sched_wakeup
/// ID: 332
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:char comm[16];	offset:8;	size:16;	signed:0;
/// 	field:pid_t pid;	offset:24;	size:4;	signed:1;
/// 	field:int prio;	offset:28;	size:4;	signed:1;
/// 	field:int target_cpu;	offset:32;	size:4;	signed:1;
///

#[tracepoint]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    match try_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_wakeup(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = ctx.read_at::<[u8; 16]>(8);
        if let Ok(comm) = comm {
            let mut len = 0;
            for i in 0..16 {
                if comm[i] == 0 {
                    break;
                }
                len = i + 1;
            }
            let comm_str = str::from_utf8_unchecked(&comm[..len]);
            info!(&ctx, "sched_wakeup comm: {}", comm_str);
        }
        let pid = ctx.read_at::<i32>(24);
        match pid {
            Ok(pid) => {
                info!(&ctx, "sched_wakeup pid: {}", pid);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup error: {}", e);
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wakeup prio: {}", prio);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup error: {}", e);
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_wakeup target_cpu: {}", target_cpu);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup error: {}", e);
            }
        }
    }
    Ok(0)
}

///
/// 继续跟踪: sched_wakeup_new这个tracepoint
/// name: sched_wakeup_new
/// ID: 331
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:char comm[16];	offset:8;	size:16;	signed:0;
/// 	field:pid_t pid;	offset:24;	size:4;	signed:1;
/// 	field:int prio;	offset:28;	size:4;	signed:1;
/// 	field:int target_cpu;	offset:32;	size:4;	signed:1;
///


#[tracepoint]
pub fn sched_wakeup_new(ctx: TracePointContext) -> u32 {
    match try_sched_wakeup_new(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_wakeup_new(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = ctx.read_at::<[u8; 16]>(8);
        if let Ok(comm) = comm {
            let mut len = 0;
            for i in 0..16 {
                if comm[i] == 0 {
                    break;
                }
                len = i + 1;
            }
            let comm_str = str::from_utf8_unchecked(&comm[..len]);
            info!(&ctx, "sched_wakeup_new comm: {}", comm_str);
        }
        let pid = ctx.read_at::<i32>(24);
        match pid {
            Ok(pid) => {
                info!(&ctx, "sched_wakeup_new pid: {}", pid);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup_new error: {}", e);
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wakeup_new prio: {}", prio);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup_new error: {}", e);
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_wakeup_new target_cpu: {}", target_cpu);
            }
            Err(e) => {
                warn!(&ctx, "sched_wakeup_new error: {}", e);
            }
        }
    }
    Ok(0)
}

///
/// 继续跟踪: sched_waking这个tracepoint
/// name: sched_waking
/// ID: 333
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:char comm[16];	offset:8;	size:16;	signed:0;
/// 	field:pid_t pid;	offset:24;	size:4;	signed:1;
/// 	field:int prio;	offset:28;	size:4;	signed:1;
/// 	field:int target_cpu;	offset:32;	size:4;	signed:1;
///


#[tracepoint]
pub fn sched_waking(ctx: TracePointContext) -> u32 {
    match try_sched_waking(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_waking(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = ctx.read_at::<[u8; 16]>(8);
        if let Ok(comm) = comm {
            let mut len = 0;
            for i in 0..16 {
                if comm[i] == 0 {
                    break;
                }
                len = i + 1;
            }
            let comm_str = str::from_utf8_unchecked(&comm[..len]);
            info!(&ctx, "sched_waking comm: {}", comm_str);
        }
        let pid = ctx.read_at::<i32>(24);
        match pid {
            Ok(pid) => {
                info!(&ctx, "sched_waking pid: {}", pid);
            }
            Err(e) => {
                warn!(&ctx, "sched_waking error: {}", e);
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_waking prio: {}", prio);
            }
            Err(e) => {
                warn!(&ctx, "sched_waking error: {}", e);
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_waking target_cpu: {}", target_cpu);
            }
            Err(e) => {
                warn!(&ctx, "sched_waking error: {}", e);
            }
        }
    }
    Ok(0)
}

///
/// 继续跟踪: sched_wait_task这个tracepoint
/// name: sched_wait_task
/// ID: 326
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:char comm[16];	offset:8;	size:16;	signed:0;
/// 	field:pid_t pid;	offset:24;	size:4;	signed:1;
/// 	field:int prio;	offset:28;	size:4;	signed:1;
///


#[tracepoint]
pub fn sched_wait_task(ctx: TracePointContext) -> u32 {
    match try_sched_wait_task(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_wait_task(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = ctx.read_at::<[u8; 16]>(8);
        if let Ok(comm) = comm {
            let mut len = 0;
            for i in 0..16 {
                if comm[i] == 0 {
                    break;
                }
                len = i + 1;
            }
            let comm_str = str::from_utf8_unchecked(&comm[..len]);
            info!(&ctx, "sched_wait_task comm: {}", comm_str);
        }
        let pid = ctx.read_at::<i32>(24);
        match pid {
            Ok(pid) => {
                info!(&ctx, "sched_wait_task pid: {}", pid);
            }
            Err(e) => {
                warn!(&ctx, "sched_wait_task error: {}", e);
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wait_task prio: {}", prio);
            }
            Err(e) => {
                warn!(&ctx, "sched_wait_task error: {}", e);
            }
        }
    }
    Ok(0)
}
