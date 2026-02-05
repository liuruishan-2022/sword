///
/// 放置cpu调度相关的处理代码逻辑
///
use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};
use aya_log_ebpf::info;

static mut count: u64 = 0;
const TARGET_PID: u32 = 677824;

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let thread_id = bpf_get_current_pid_tgid() as u32;
    if thread_id == TARGET_PID {
        unsafe {
            count = count + 1;
            if count % 10 == 0 {
                info!(&ctx, "count: {}", count);
            }
        }
    }
    Ok(0)
}
