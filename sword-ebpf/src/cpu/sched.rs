///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray},
    programs::TracePointContext,
};
use sword_common::SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES;

#[map]
pub static SCHED_SWITCH_TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub static SCHED_SWITCH_TARGET_TIDS: HashMap<u32, u8> =
    HashMap::with_max_entries(SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, 0);

#[map]
pub static SCHED_SWITCH_LOG_COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static SCHED_SWITCH_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

fn try_sched_switch(_ctx: TracePointContext) -> Result<u32, i64> {
    unsafe {
        if let Some(total) = SCHED_SWITCH_TOTAL.get_ptr_mut(0) {
            *total = (*total).wrapping_add(1);
        }
    }

    Ok(0)
}
