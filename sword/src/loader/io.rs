use aya::programs::TracePoint;

use crate::loader::TracePointConfig;

pub fn load_io(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let trace_points = vec![
        TracePointConfig::create_syscalls("sys_enter_open", "sys_enter_open"),
        TracePointConfig::create_syscalls("sys_enter_openat", "sys_enter_openat"),
    ];

    for ele in trace_points {
        ele.load_tracepoint(ebpf)?;
    }
    Ok(())
}
