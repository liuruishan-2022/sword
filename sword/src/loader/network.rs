///
/// 放置网络相关的loader
///
use aya::maps::{Array, MapData};
use log::info;
use sword_common::TcpSendmsgTarget;

use crate::loader::{KProberConfig, LoaderOptions, TracePointConfig};

const TCP_SENDMSG_TARGET_MAP: &str = "TCP_SENDMSG_TARGET";

pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    let kprobe_configs = vec![KProberConfig::new("tcp_sendmsg", "tcp_sendmsg")];
    if let Some(pid) = options.tcp_sendmsg_pid {
        configure_tcp_sendmsg_target(ebpf, pid)?;
        for ele in kprobe_configs {
            ele.load_kprobe(ebpf)?;
        }
    }
    Ok(())
}

fn configure_tcp_sendmsg_target(ebpf: &mut aya::Ebpf, pid: u32) -> anyhow::Result<()> {
    let target = tcp_sendmsg_target(pid);
    let mut target_map: Array<MapData, TcpSendmsgTarget> = Array::try_from(
        ebpf.take_map(TCP_SENDMSG_TARGET_MAP)
            .ok_or_else(|| anyhow::anyhow!("map {TCP_SENDMSG_TARGET_MAP} not found"))?,
    )?;
    target_map.set(0, target, 0)?;
    info!("configured kprobe:tcp_sendmsg target pid={pid}");
    Ok(())
}

fn tcp_sendmsg_target(pid: u32) -> TcpSendmsgTarget {
    TcpSendmsgTarget { pid, _pad: 0 }
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
    ];

    for ele in tracepoints {
        ele.load_tracepoint(ebpf)?;
    }
    Ok(())
}
