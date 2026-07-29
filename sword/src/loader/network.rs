///
/// 放置网络相关的loader
///
use aya::maps::Array;
use log::info;
use sword_common::TargetPid;

use crate::loader::{KProberConfig, LoaderOptions, TracePointConfig};

const TARGET_PID: &str = "TARGET_PID";

pub fn load_network_kprobe(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    let mut kprobe_configs = network_kprobes();
    if options.targeting_enabled() {
        if let Some(pid) = options.target_pid {
            kprobe_configs.push(KProberConfig::new("tcp_v4_connect", "tcp_v4_connect"));
            configure_tcp_sendmsg_target(ebpf, pid)?;
        }
        for ele in kprobe_configs {
            ele.load_kprobe(ebpf)?;
        }
    }
    Ok(())
}

fn network_kprobes() -> Vec<KProberConfig> {
    vec![
        KProberConfig::new("tcp_data_queue", "tcp_data_queue"),
        KProberConfig::new("tcp_sendmsg", "tcp_sendmsg"),
        KProberConfig::new("tcp_recvmsg", "tcp_recvmsg"),
        KProberConfig::new("tcp_recvmsg_ret", "tcp_recvmsg"),
    ]
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
    for tracepoint in network_tracepoints() {
        tracepoint.load_tracepoint(ebpf)?;
    }
    Ok(())
}

fn network_tracepoints() -> Vec<TracePointConfig> {
    vec![
        TracePointConfig::create_syscalls("sys_enter_connect", "sys_enter_connect"),
        TracePointConfig::create_syscalls("sys_exit_connect", "sys_exit_connect"),
        TracePointConfig::create_syscalls("sys_enter_socket", "sys_enter_socket"),
        TracePointConfig::create_syscalls("sys_exit_socket", "sys_exit_socket"),
        TracePointConfig::create_syscalls("sys_enter_epoll_wait", "sys_enter_epoll_wait"),
        TracePointConfig::create_syscalls("sys_exit_epoll_wait", "sys_exit_epoll_wait"),
        TracePointConfig::create_syscalls("sys_enter_epoll_pwait", "sys_enter_epoll_pwait"),
        TracePointConfig::create_syscalls("sys_exit_epoll_pwait", "sys_exit_epoll_pwait"),
        TracePointConfig::create_syscalls("sys_enter_read", "sys_enter_read"),
        TracePointConfig::create_syscalls("sys_exit_read", "sys_exit_read"),
        TracePointConfig::create_syscalls("sys_enter_readv", "sys_enter_readv"),
        TracePointConfig::create_syscalls("sys_exit_readv", "sys_exit_readv"),
        TracePointConfig::create_syscalls("sys_enter_recvfrom", "sys_enter_recvfrom"),
        TracePointConfig::create_syscalls("sys_exit_recvfrom", "sys_exit_recvfrom"),
        TracePointConfig::create_syscalls("sys_enter_recvmsg", "sys_enter_recvmsg"),
        TracePointConfig::create_syscalls("sys_exit_recvmsg", "sys_exit_recvmsg"),
        TracePointConfig::create_syscalls("sys_enter_write", "sys_enter_write"),
        TracePointConfig::create_syscalls("sys_exit_write", "sys_exit_write"),
        TracePointConfig::create_syscalls("sys_enter_writev", "sys_enter_writev"),
        TracePointConfig::create_syscalls("sys_exit_writev", "sys_exit_writev"),
        TracePointConfig::create_syscalls("sys_enter_sendto", "sys_enter_sendto"),
        TracePointConfig::create_syscalls("sys_exit_sendto", "sys_exit_sendto"),
        TracePointConfig::create_syscalls("sys_enter_sendmsg", "sys_enter_sendmsg"),
        TracePointConfig::create_syscalls("sys_exit_sendmsg", "sys_exit_sendmsg"),
        TracePointConfig::create_sock("inet_sock_set_state", "inet_sock_set_state"),
        TracePointConfig::create_tcp("tcp_send_reset", "tcp_send_reset"),
        TracePointConfig::create_tcp("tcp_receive_reset", "tcp_receive_reset"),
        TracePointConfig::create_tcp("tcp_retransmit_skb", "tcp_retransmit_skb"),
    ]
}

#[cfg(test)]
mod tests {
    use super::{network_kprobes, network_tracepoints};

    #[test]
    fn includes_tcp_data_queue_socket_arrival_kprobe() {
        let kprobes = network_kprobes();

        assert!(kprobes.iter().any(|kprobe| {
            kprobe.name() == "tcp_data_queue" && kprobe.fn_name() == "tcp_data_queue"
        }));
    }

    #[test]
    fn does_not_attach_kernel_layout_dependent_tcp_probe() {
        let tracepoints = network_tracepoints();

        assert!(!tracepoints.iter().any(|tracepoint| {
            tracepoint.uname() == "tcp_probe"
                && tracepoint.category() == "tcp"
                && tracepoint.kname() == "tcp_probe"
        }));
    }

    #[test]
    fn includes_epoll_wait_and_pwait_tracepoints() {
        let tracepoints = network_tracepoints();

        for name in [
            "sys_enter_epoll_wait",
            "sys_exit_epoll_wait",
            "sys_enter_epoll_pwait",
            "sys_exit_epoll_pwait",
        ] {
            assert!(tracepoints.iter().any(|tracepoint| {
                tracepoint.uname() == name
                    && tracepoint.category() == "syscalls"
                    && tracepoint.kname() == name
            }));
        }
    }

    #[test]
    fn includes_http_io_syscall_tracepoints() {
        let tracepoints = network_tracepoints();

        for syscall in [
            "read", "readv", "recvfrom", "recvmsg", "write", "writev", "sendto", "sendmsg",
        ] {
            for phase in ["enter", "exit"] {
                let name = format!("sys_{phase}_{syscall}");
                assert!(tracepoints.iter().any(|tracepoint| {
                    tracepoint.uname() == name
                        && tracepoint.category() == "syscalls"
                        && tracepoint.kname() == name
                }));
            }
        }
    }
}
