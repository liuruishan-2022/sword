use crate::network::bindings::{sock, sock_common};
///
/// 对tcp的整个生命周期进行操作
///
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::Array,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use sword_common::TcpSendmsgTarget;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map]
pub static TCP_SENDMSG_TARGET: Array<TcpSendmsgTarget> = Array::with_max_entries(1, 0);

///
/// kfunc:vmlinux:tcp_sendmsg
/// struct sock * sk
/// struct msghdr * msg
/// size_t size
/// int retval
#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_sendmsg(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcp_sendmsg(ctx: ProbeContext) -> Result<u32, u32> {
    if !matches_tcp_sendmsg_target()? {
        return Ok(0);
    }

    let sk: *const sock = ctx.arg(0).ok_or(1u32)?;
    let size: usize = ctx.arg(2).ok_or(1u32)?;
    let tuple = read_tcp_socket_tuple(sk)?;

    match tuple.family {
        AF_INET => info!(
            &ctx,
            "tcp_sendmsg pid={} tid={} family=ipv4 src={}.{}.{}.{}:{} dst={}.{}.{}.{}:{} size={}",
            tuple.pid,
            tuple.tid,
            ipv4_octet(tuple.saddr_v4, 0),
            ipv4_octet(tuple.saddr_v4, 1),
            ipv4_octet(tuple.saddr_v4, 2),
            ipv4_octet(tuple.saddr_v4, 3),
            tuple.sport,
            ipv4_octet(tuple.daddr_v4, 0),
            ipv4_octet(tuple.daddr_v4, 1),
            ipv4_octet(tuple.daddr_v4, 2),
            ipv4_octet(tuple.daddr_v4, 3),
            tuple.dport,
            size
        ),
        AF_INET6 => info!(
            &ctx,
            "tcp_sendmsg pid={} tid={} family=ipv6 src={:x}:{:x}:{:x}:{:x}:{} dst={:x}:{:x}:{:x}:{:x}:{} size={}",
            tuple.pid,
            tuple.tid,
            tuple.saddr_v6[0],
            tuple.saddr_v6[1],
            tuple.saddr_v6[2],
            tuple.saddr_v6[3],
            tuple.sport,
            tuple.daddr_v6[0],
            tuple.daddr_v6[1],
            tuple.daddr_v6[2],
            tuple.daddr_v6[3],
            tuple.dport,
            size
        ),
        _ => info!(
            &ctx,
            "tcp_sendmsg pid={} tid={} family={} size={}", tuple.pid, tuple.tid, tuple.family, size
        ),
    }

    Ok(0)
}
struct TcpSocketTuple {
    pid: u32,
    tid: u32,
    family: u16,
    saddr_v4: u32,
    daddr_v4: u32,
    saddr_v6: [u32; 4],
    daddr_v6: [u32; 4],
    sport: u16,
    dport: u16,
}

fn read_tcp_socket_tuple(sk: *const sock) -> Result<TcpSocketTuple, u32> {
    if sk.is_null() {
        return Err(1);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let sk_common = unsafe { bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common) }
        .map_err(|_| 1u32)?;
    let family = sk_common.skc_family as u16;
    let ports = unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1 };
    let sport = ports.skc_num as u16;
    let dport = u16::from_be(ports.skc_dport as u16);

    let mut tuple = TcpSocketTuple {
        pid,
        tid,
        family,
        saddr_v4: 0,
        daddr_v4: 0,
        saddr_v6: [0; 4],
        daddr_v6: [0; 4],
        sport,
        dport,
    };

    if family == AF_INET {
        let addrs = unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1 };
        tuple.saddr_v4 = u32::from_be(addrs.skc_rcv_saddr as u32);
        tuple.daddr_v4 = u32::from_be(addrs.skc_daddr as u32);
    } else if family == AF_INET6 {
        tuple.saddr_v6 = unsafe { sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32 };
        tuple.daddr_v6 = unsafe { sk_common.skc_v6_daddr.in6_u.u6_addr32 };
    }

    Ok(tuple)
}

fn ipv4_octet(addr: u32, index: u32) -> u32 {
    (addr >> (24 - index * 8)) & 0xff
}

fn matches_tcp_sendmsg_target() -> Result<bool, u32> {
    let target = TCP_SENDMSG_TARGET.get(0).ok_or(1u32)?;
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    Ok(current_pid == target.pid)
}
