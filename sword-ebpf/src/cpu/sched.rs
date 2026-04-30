///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray},
    programs::TracePointContext,
};
use sword_common::{
    SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES,
    SchedSwitchStateKey, ThreadComm, ThreadOffCpuStart,
};

#[map]
pub static SCHED_SWITCH_TARGET_TIDS: HashMap<u32, u8> =
    HashMap::with_max_entries(SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, 0);

#[map]
pub static SCHED_SWITCH_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

///
/// 进行CPU耗时的统计
///
#[map]
pub static THREAD_OFFCPU_START_NS: HashMap<u32, ThreadOffCpuStart> =
    HashMap::with_max_entries(SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, 0);

#[map]
pub static THREAD_OFFCPU_TOTAL_NS: HashMap<SchedSwitchStateKey, u64> =
    HashMap::with_max_entries(SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES, 0);

#[map]
pub static THREAD_SWITCH_OUT_TOTAL: HashMap<SchedSwitchStateKey, u64> =
    HashMap::with_max_entries(SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES, 0);

#[map]
pub static THREAD_COMM: HashMap<u32, ThreadComm> =
    HashMap::with_max_entries(SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES, 0);

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
        if let Some(total) = SCHED_SWITCH_TOTAL.get_ptr_mut(0) {
            *total = (*total).wrapping_add(1);
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let prev_comm: [u8; 16] = unsafe { ctx.read_at(8)? };
    let prev_pid: u32 = unsafe { ctx.read_at(24)? };
    let prev_state: i64 = unsafe { ctx.read_at(32)? };
    let next_comm: [u8; 16] = unsafe { ctx.read_at(40)? };
    let next_pid: u32 = unsafe { ctx.read_at(56)? };

    handle_switch_out(prev_pid, prev_state, prev_comm, now);
    handle_switch_in(next_pid, next_comm, now);

    Ok(0)
}

fn is_target_tid(tid: u32) -> bool {
    unsafe { SCHED_SWITCH_TARGET_TIDS.get(&tid).is_some() }
}

fn normalize_task_state(state: i64) -> u64 {
    if state < 0 { 0 } else { state as u64 }
}

fn increment_map_value<K: Copy>(map: &HashMap<K, u64>, key: K, delta: u64) {
    unsafe {
        if let Some(value) = map.get_ptr_mut(&key) {
            *value = (*value).wrapping_add(delta);
        } else {
            let _ = map.insert(&key, &delta, 0);
        }
    }
}

fn handle_switch_out(tid: u32, state: i64, comm: [u8; 16], now: u64) {
    if !is_target_tid(tid) {
        return;
    }

    let state = normalize_task_state(state);
    let key = SchedSwitchStateKey { tid, state };
    increment_map_value(&THREAD_SWITCH_OUT_TOTAL, key, 1);

    let start = ThreadOffCpuStart { ts_ns: now, state };
    let thread_comm = ThreadComm { comm };
    let _ = THREAD_OFFCPU_START_NS.insert(&tid, &start, 0);
    let _ = THREAD_COMM.insert(&tid, &thread_comm, 0);
}

fn handle_switch_in(tid: u32, comm: [u8; 16], now: u64) {
    if !is_target_tid(tid) {
        return;
    }

    if let Some(start) = unsafe { THREAD_OFFCPU_START_NS.get(&tid) } {
        let key = SchedSwitchStateKey {
            tid,
            state: start.state,
        };
        increment_map_value(
            &THREAD_OFFCPU_TOTAL_NS,
            key,
            now.saturating_sub(start.ts_ns),
        );
        let _ = THREAD_OFFCPU_START_NS.remove(&tid);
    }

    let thread_comm = ThreadComm { comm };
    let _ = THREAD_COMM.insert(&tid, &thread_comm, 0);
}
