///
/// 放置网络相关的loader
///
use aya::maps::{Array, MapData};
use aya::programs::KProbe;
use log::info;
use sword_common::TcpSendmsgTarget;

use crate::loader::LoaderOptions;

const TCP_SENDMSG_TARGET_MAP: &str = "TCP_SENDMSG_TARGET";

pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    if let Some(pid) = options.tcp_sendmsg_pid {
        load_tcp_sendmsg(ebpf)?;
        configure_tcp_sendmsg_target(ebpf, pid)?;
        attach_tcp_sendmsg(ebpf)?;
    }
    Ok(())
}

fn load_tcp_sendmsg(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    program.load()?;
    info!("loaded kprobe:tcp_sendmsg");
    Ok(())
}

fn attach_tcp_sendmsg(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    program.attach("tcp_sendmsg", 0)?;
    info!("attached kprobe:tcp_sendmsg");
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
