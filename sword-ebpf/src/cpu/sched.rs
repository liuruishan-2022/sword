use core::{f32::consts::E, str};

///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray},
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use sword_common::SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES;

use crate::common;

const LOG_EVERY_N: u32 = 10_000;
const PREV_PID_OFFSET: usize = 24;
const PREV_PRIO_OFFSET: usize = 28;
const PREV_STATE_OFFSET: usize = 32;
const NEXT_PID_OFFSET: usize = 56;
const NEXT_PRIO_OFFSET: usize = 60;

#[map]
pub static SCHED_SWITCH_TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub static SCHED_SWITCH_TARGET_TIDS: HashMap<u32, u8> =
    HashMap::with_max_entries(SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, 0);

#[map]
pub static SCHED_SWITCH_LOG_COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

/// 下面是对应的tracepoint:sched:sched_switch的format信息
///
/// name: sched_switch
/// ID: 330
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_COUNT;	offset:3;	size:1;	signed:0;
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

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    unsafe {
        let prev_comm = ctx.read_at::<[u8; 16]>(8)?;
        info!(
            &ctx,
            "sched_switch prev_comm: {}",
            common::byte_to_str(&prev_comm)
        );
        let prev_pid = ctx.read_at::<i32>(24)?;
        info!(&ctx, "sched_switch prev_pid: {}", prev_pid);
        let next_comm = ctx.read_at::<[u8; 16]>(40)?;
        info!(
            &ctx,
            "sched_switch next_comm: {}",
            common::byte_to_str(&next_comm)
        );
        let next_pid = ctx.read_at::<i32>(56)?;
        info!(&ctx, "sched_switch next_pid: {}", next_pid);
    }

    Ok(0)
}

///
/// 继续跟踪: sched_wakeup这个tracepoint
/// name: sched_wakeup
/// ID: 332
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_COUNT;	offset:3;	size:1;	signed:0;
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
            Err(_) => {
                warn!(&ctx, "sched_wakeup error reading pid");
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wakeup prio: {}", prio);
            }
            Err(_) => {
                warn!(&ctx, "sched_wakeup error reading prio");
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_wakeup target_cpu: {}", target_cpu);
            }
            Err(_) => {
                warn!(&ctx, "sched_wakeup error reading target_cpu");
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
/// 	field:unsigned char common_preempt_COUNT;	offset:3;	size:1;	signed:0;
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
            Err(_) => {
                warn!(&ctx, "sched_wakeup_new error reading pid");
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wakeup_new prio: {}", prio);
            }
            Err(_) => {
                warn!(&ctx, "sched_wakeup_new error reading prio");
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_wakeup_new target_cpu: {}", target_cpu);
            }
            Err(_) => {
                warn!(&ctx, "sched_wakeup_new error reading target_cpu");
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
/// 	field:unsigned char common_preempt_COUNT;	offset:3;	size:1;	signed:0;
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
            Err(_) => {
                warn!(&ctx, "sched_waking error reading pid");
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_waking prio: {}", prio);
            }
            Err(_) => {
                warn!(&ctx, "sched_waking error reading prio");
            }
        }
        let target_cpu = ctx.read_at::<i32>(32);
        match target_cpu {
            Ok(target_cpu) => {
                info!(&ctx, "sched_waking target_cpu: {}", target_cpu);
            }
            Err(_) => {
                warn!(&ctx, "sched_waking error reading target_cpu");
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
/// 	field:unsigned char common_preempt_COUNT;	offset:3;	size:1;	signed:0;
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
            Err(_) => {
                warn!(&ctx, "sched_wait_task error reading pid");
            }
        }
        let prio = ctx.read_at::<i32>(28);
        match prio {
            Ok(prio) => {
                info!(&ctx, "sched_wait_task prio: {}", prio);
            }
            Err(_) => {
                warn!(&ctx, "sched_wait_task error reading prio");
            }
        }
    }
    Ok(0)
}
