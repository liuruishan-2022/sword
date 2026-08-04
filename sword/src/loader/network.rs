use crate::args::arguments::LoadOptions;
///
/// 放置网络相关的loader
///
use aya::maps::Array;
use log::info;
use sword_common::TargetPid;

use crate::loader::{KProberConfig, TracePointConfig};

const TARGET_PID: &str = "TARGET_PID";

pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoadOptions) -> anyhow::Result<()> {
    let kprobe_configs = vec![
        // KProberConfig::new("tcp_sendmsg", "tcp_sendmsg"),
        KProberConfig::new("tcp_v4_connect", "tcp_v4_connect"),
        KProberConfig::new("tcp_send_active_reset", "tcp_send_active_reset"),
    ];
    if let Some(pid) = options.first_target_pid() {
        info!("监听到我们的进程:{pid}");
        configure_tcp_sendmsg_target(ebpf, pid)?;
        for ele in kprobe_configs {
            ele.load_kprobe(ebpf)?;
        }
    }
    Ok(())
}

fn configure_tcp_sendmsg_target(ebpf: &mut aya::Ebpf, pid: u32) -> anyhow::Result<()> {
    let target = tcp_sendmsg_target(pid);
    let map = ebpf
        .map_mut(TARGET_PID)
        .ok_or_else(|| anyhow::anyhow!("map {TARGET_PID} not found"))?;

    let mut target_map = Array::<_, TargetPid>::try_from(map)?;
    target_map.set(0, target, 0)?;
    info!("configured kprobe:tcp_sendmsg target pid={pid}");
    Ok(())
}

fn tcp_sendmsg_target(pid: u32) -> TargetPid {
    TargetPid { pid, _pad: 0 }
}

///
/// 加載tracepoint
///
pub fn load_tracepoint(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let tracepoints = vec![
        TracePointConfig::create_syscalls("sys_enter_connect", "sys_enter_connect"),
        TracePointConfig::create_syscalls("sys_exit_connect", "sys_exit_connect"),
        TracePointConfig::create_syscalls("sys_enter_socket", "sys_enter_socket"),
        TracePointConfig::create_syscalls("sys_exit_socket", "sys_exit_socket"),
        TracePointConfig::create_sock("inet_sock_set_state", "inet_sock_set_state"),
        TracePointConfig::create_tcp("tcp_send_reset", "tcp_send_reset"),
    ];

    for ele in tracepoints {
        ele.load_tracepoint(ebpf)?;
    }
    Ok(())
}
