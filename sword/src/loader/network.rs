use std::time::Duration;

use crate::args::arguments::LoadOptions;
use axum::http::header::WARNING;
///
/// 放置网络相关的loader
///
use aya::maps::{Array, MapData};
use log::{info, warn};
use sword_common::TargetPid;
use tokio::time;

use crate::loader::{KProberConfig, TracePointConfig};

const TARGET_PID: &str = "TARGET_PID";

pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoadOptions) -> anyhow::Result<()> {
    for ele in vec![
        // KProberConfig::new("tcp_sendmsg", "tcp_sendmsg"),
        KProberConfig::new("tcp_v4_connect", "tcp_v4_connect"),
        KProberConfig::new("tcp_send_active_reset", "tcp_send_active_reset"),
    ] {
        ele.load_kprobe(ebpf)?;
    }

    let mut target_map = take_target_pid_map(ebpf)?;
    let initial_pid = options.first_target_pid().unwrap_or(0);
    configure_target_pid(&mut target_map, initial_pid)?;

    spawn_target_pid_refresh(target_map, options.clone());
    Ok(())
}

fn take_target_pid_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<Array<MapData, TargetPid>> {
    let map = ebpf
        .take_map(TARGET_PID)
        .ok_or_else(|| anyhow::anyhow!("map {TARGET_PID} not found"))?;
    Ok(Array::try_from(map)?)
}

fn configure_target_pid(
    target_map: &mut Array<MapData, TargetPid>,
    pid: u32,
) -> anyhow::Result<()> {
    target_map.set(0, target_pid(pid), 0)?;
    info!("configured kprobe:tcp_sendmsg target pid={pid}");
    Ok(())
}

fn target_pid(pid: u32) -> TargetPid {
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

///
/// 使用tokio定时加载和刷寻任务数据
///

fn spawn_target_pid_refresh(mut target_map: Array<MapData, TargetPid>, option: LoadOptions) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(5));
        let mut current_pid = 0;
        loop {
            interval.tick().await;
            let new_pid = option.first_target_pid().unwrap_or(0);

            if new_pid == current_pid {
                continue;
            }

            match configure_target_pid(&mut target_map, new_pid) {
                Ok(()) => current_pid = new_pid,
                Err(err) => {
                    warn!("刷新目标:{} 的pid失败:{err}", option.command());
                }
            }
        }
    });
}
