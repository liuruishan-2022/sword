use crate::{
    common,
    network::bindings::{sock, sock_common},
};
///
/// 对tcp的整个生命周期进行操作
/// 整个TCP的生命周期如下:
/// 系统调用阶段：sys_enter_connect
/// TCP连接: tcp_v4_connect->inet_hash_connect->tcp_connect->tcp_rcv_state_process
/// 发送数据: sys_enter_write->tcp_sendmsg->tcp_write_xmit->tcp_transmit_skb->ip_queue_xmit->dev_queue_xmit
///
use aya_ebpf::{
    bindings::{BPF_TCP_CLOSE, BPF_TCP_ESTABLISHED, BPF_TCP_SYN_SENT, sockaddr},
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user,
        generated::bpf_ktime_get_ns,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use sword_common::{
    SLOW_TCP_PHASE_ARRIVAL_TO_READ, SLOW_TCP_PHASE_READ_TO_WRITE, SlowTcpEvent, SysEnterType,
    TargetPid, TcpFlowKey,
};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const RISK_TCP_RETRANSMIT_INDEX: u32 = 0;
const RISK_TCP_RECEIVE_RESET_INDEX: u32 = 1;
const RISK_TCP_SEND_RESET_INDEX: u32 = 2;
const RISK_TCP_READ_INDEX: u32 = 3;
const RISK_TCP_WRITE_INDEX: u32 = 4;
const RISK_TCP_SLOW_INDEX: u32 = 5;
const RISK_TCP_EVENT_DROPPED_INDEX: u32 = 6;
const RISK_TCP_PAYLOAD_ARRIVAL_INDEX: u32 = 7;
const RISK_TCP_ARRIVAL_TO_READ_INDEX: u32 = 8;
const RISK_TCP_ARRIVAL_TO_READ_SLOW_INDEX: u32 = 9;

#[map]
pub static TARGET_PID: Array<TargetPid> = Array::with_max_entries(1, 0);

#[map]
pub static SYS_ENTER_CONNECT: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(4096, 0);

#[map]
pub static START: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static RISK_TCP_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(10, 0);

#[map]
pub static TCP_RECV_INFLIGHT: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static TCP_REQUEST_START: HashMap<u64, u64> = HashMap::with_max_entries(32768, 0);

#[map]
pub static TCP_PAYLOAD_ARRIVAL: LruHashMap<TcpFlowKey, u64> =
    LruHashMap::with_max_entries(32768, 0);

#[map]
pub static TCP_ACTIVE_FLOWS: LruHashMap<TcpFlowKey, u8> =
    LruHashMap::with_max_entries(32768, 0);

#[map]
pub static SLOW_TCP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

///
/// 这个主要是统计我们的SYS_ENTER的调用统计
#[map]
pub static SYS_ENTER_STATISTICS: PerCpuHashMap<SysEnterType, u64> =
    PerCpuHashMap::with_max_entries(4096, 0);

pub unsafe fn sys_enter_statistics_inc(pid: u32, enter_type: u32) -> Result<u32, i64> {
    let key = SysEnterType {
        pid: 1,
        enter_type: enter_type,
    };
    match SYS_ENTER_STATISTICS.get_ptr_mut(&key) {
        Some(count) => {
            *count = *count + 1;
        }
        None => {
            SYS_ENTER_STATISTICS.insert(&key, 1, 0)?;
        }
    }

    return Ok(0);
}

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
    let sk: *const sock = ctx.arg(0).ok_or(1u32)?;
    let tuple = read_target_server_socket_tuple(sk)?;
    let flow = tuple.flow_key()?;
    let _ = TCP_ACTIVE_FLOWS.remove(&flow);
    increment_risk_tcp_counter(RISK_TCP_WRITE_INDEX);

    let socket_key = sk as u64;
    let Some(start_ns) = (unsafe { TCP_REQUEST_START.get(&socket_key) }).copied() else {
        return Ok(0);
    };
    let _ = TCP_REQUEST_START.remove(&socket_key);

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let latency_ns = now_ns.saturating_sub(start_ns);
    let Some(config) = crate::common::risk_target_config() else {
        return Ok(0);
    };
    if latency_ns < config.slow_threshold_ns {
        return Ok(0);
    }

    increment_risk_tcp_counter(RISK_TCP_SLOW_INDEX);
    output_slow_tcp_event(
        &tuple,
        now_ns,
        latency_ns,
        SLOW_TCP_PHASE_READ_TO_WRITE,
    );

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

impl TcpSocketTuple {
    fn flow_key(&self) -> Result<TcpFlowKey, u32> {
        if self.family == AF_INET {
            return Ok(TcpFlowKey::ipv4(
                self.saddr_v4,
                self.daddr_v4,
                self.sport,
                self.dport,
            ));
        }
        if self.family == AF_INET6 {
            return Ok(TcpFlowKey::ipv6(
                self.saddr_v6,
                self.daddr_v6,
                self.sport,
                self.dport,
            ));
        }
        Err(1)
    }
}

fn output_slow_tcp_event(
    tuple: &TcpSocketTuple,
    timestamp_ns: u64,
    latency_ns: u64,
    phase: u8,
) {
    let event = SlowTcpEvent {
        timestamp_ns,
        latency_ns,
        tgid: tuple.pid,
        tid: tuple.tid,
        source_addr_v4: tuple.saddr_v4,
        destination_addr_v4: tuple.daddr_v4,
        source_port: tuple.sport,
        destination_port: tuple.dport,
        family: tuple.family,
        phase,
        _pad: 0,
    };
    if SLOW_TCP_EVENTS.output::<SlowTcpEvent>(&event, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
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

fn read_target_server_socket_tuple(sk: *const sock) -> Result<TcpSocketTuple, u32> {
    let Some(config) = crate::common::risk_target_config() else {
        return Err(1);
    };
    let current_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !crate::common::is_risk_target_tgid(current_tgid) {
        return Err(1);
    }
    let tuple = read_tcp_socket_tuple(sk)?;
    if tuple.sport != config.server_port {
        return Err(1);
    }
    Ok(tuple)
}

fn matches_tcp_sendmsg_target() -> Result<bool, u32> {
    let target = TARGET_PID.get(0).ok_or(1u32)?;
    let current_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    Ok(current_pid == target.pid)
}

///
/// 跟蹤一些tracepoint來做一些鏈接信息的統計
///

///
/// /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
/// name: sys_enter_connect
/// ID: 1674
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:int fd;	offset:16;	size:8;	signed:0;
/// 	field:struct sockaddr * uservaddr;	offset:24;	size:8;	signed:0;
/// 	field:int addrlen;	offset:32;	size:8;	signed:0;
///
/// print fmt: "fd: 0x%08lx, uservaddr: 0x%08lx, addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->uservaddr)), ((unsigned long)(REC->addrlen))
///
/// 定义enter_type: 1
///
#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_sys_enter_connect(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_sys_enter_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let (pid, _tid) = common::thread_id();

    unsafe {
        sys_enter_statistics_inc(pid, 1)?;
        match SYS_ENTER_CONNECT.get_ptr_mut(&pid) {
            Some(count) => {
                *count = *count + 1;
            }
            None => {
                SYS_ENTER_CONNECT.insert(pid, 1, 0)?;
            }
        }
    }

    Ok(0)
}

///
/// name: sys_exit_connect
/// ID: 1553
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:long ret;	offset:16;	size:8;	signed:1;
///
/// print fmt: "0x%lx", REC->ret
///
#[tracepoint]
pub fn sys_exit_connect(ctx: TracePointContext) -> u32 {
    match try_sys_exit_connect(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_sys_exit_connect(ctx: TracePointContext) -> Result<u32, i64> {
    unsafe {
        let ret = ctx.read_at::<i64>(16)?;
    }
    Ok(0)
}

///
/// 继续挂载sys_enter_socket
///
/// 执行的顺序是 sys_enter_socket--->sys_enter_connect
///
/// name: sys_enter_socket
/// ID: 1566
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:int family;	offset:16;	size:8;	signed:0;
/// 	field:int type;	offset:24;	size:8;	signed:0;
/// 	field:int protocol;	offset:32;	size:8;	signed:0;
///
/// print fmt: "family: 0x%08lx, type: 0x%08lx, protocol: 0x%08lx", ((unsigned long)(REC->family)), ((unsigned long)(REC->type)), ((unsigned long)(REC->protocol))
///
#[tracepoint]
pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    match try_sys_enter_socket(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_sys_enter_socket(ctx: TracePointContext) -> Result<u32, i64> {
    let (pid, _tid) = common::thread_id();
    unsafe {
        sys_enter_statistics_inc(pid, 1)?;
    }
    Ok(0)
}

///
/// 进入sys_exit_socket的追踪
///
/// name: sys_exit_socket
/// ID: 1565
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:long ret;	offset:16;	size:8;	signed:1;
///
/// print fmt: "0x%lx", REC->ret
///

#[tracepoint]
pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    match try_sys_exit_socket(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_sys_exit_socket(ctx: TracePointContext) -> Result<u32, i64> {
    Ok(0)
}

/// Linux 5.14 tcp:tcp_probe records the first payload arrival for a server flow.
#[tracepoint]
pub fn tcp_probe(ctx: TracePointContext) -> u32 {
    match try_tcp_probe(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_probe(ctx: TracePointContext) -> Result<u32, i64> {
    const SPORT_OFFSET: usize = 68;
    const DPORT_OFFSET: usize = 70;
    const FAMILY_OFFSET: usize = 72;
    const DATA_LEN_OFFSET: usize = 80;

    let Some(config) = crate::common::risk_target_config() else {
        return Ok(0);
    };
    let source_port: u16 = unsafe { ctx.read_at(SPORT_OFFSET)? };
    let data_len: u32 = unsafe { ctx.read_at(DATA_LEN_OFFSET)? };
    if source_port != config.server_port || data_len == 0 {
        return Ok(0);
    }

    let destination_port: u16 = unsafe { ctx.read_at(DPORT_OFFSET)? };
    let family: u16 = unsafe { ctx.read_at(FAMILY_OFFSET)? };
    let flow = read_tcp_probe_flow(&ctx, family, source_port, destination_port)?;
    increment_risk_tcp_counter(RISK_TCP_PAYLOAD_ARRIVAL_INDEX);

    if unsafe { TCP_ACTIVE_FLOWS.get(&flow) }.is_some()
        || unsafe { TCP_PAYLOAD_ARRIVAL.get(&flow) }.is_some()
    {
        return Ok(0);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    if TCP_PAYLOAD_ARRIVAL.insert(&flow, &now_ns, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    Ok(0)
}

fn read_tcp_probe_flow(
    ctx: &TracePointContext,
    family: u16,
    source_port: u16,
    destination_port: u16,
) -> Result<TcpFlowKey, i64> {
    if family == AF_INET {
        let source_addr = u32::from_be(unsafe { ctx.read_at::<u32>(16)? });
        let destination_addr = u32::from_be(unsafe { ctx.read_at::<u32>(44)? });
        return Ok(TcpFlowKey::ipv4(
            source_addr,
            destination_addr,
            source_port,
            destination_port,
        ));
    }
    if family == AF_INET6 {
        let source_addr = [
            unsafe { ctx.read_at::<u32>(20)? },
            unsafe { ctx.read_at::<u32>(24)? },
            unsafe { ctx.read_at::<u32>(28)? },
            unsafe { ctx.read_at::<u32>(32)? },
        ];
        let destination_addr = [
            unsafe { ctx.read_at::<u32>(48)? },
            unsafe { ctx.read_at::<u32>(52)? },
            unsafe { ctx.read_at::<u32>(56)? },
            unsafe { ctx.read_at::<u32>(60)? },
        ];
        return Ok(TcpFlowKey::ipv6(
            source_addr,
            destination_addr,
            source_port,
            destination_port,
        ));
    }
    Err(1)
}

///
/// 抓取tcp_recvmsg这个krprobe
/// kfunc:vmlinux:tcp_recvmsg
///     struct sock * sk TCP的sock对象
///     struct msghdr * msg 本次recv的消息描述结构
///     size_t len 应用这次想要读取的最大字节数
///     int flags MSG_DONTWAIT 非阻塞 MSG_PEEK 窥探 MSG_WAITALL 尽量读 MSG_TRUNC 截断语义相关
///     int * addr_len 用于返回对端的地址长度
///     int retval 返回值
///

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_tcp_recvmsg(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let sk: *const sock = ctx.arg(0).ok_or(1i64)?;
    read_target_server_socket_tuple(sk).map_err(|_| 1i64)?;
    let tid = bpf_get_current_pid_tgid() as u32;
    if TCP_RECV_INFLIGHT.insert(&tid, &(sk as u64), 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    Ok(0)
}

#[kretprobe]
pub fn tcp_recvmsg_ret(ctx: RetProbeContext) -> u32 {
    match try_tcp_recvmsg_ret(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_recvmsg_ret(ctx: RetProbeContext) -> Result<u32, i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(socket_key) = (unsafe { TCP_RECV_INFLIGHT.get(&tid) }).copied() else {
        return Ok(0);
    };
    let _ = TCP_RECV_INFLIGHT.remove(&tid);

    let bytes_read: i64 = ctx.ret();
    if bytes_read <= 0 {
        return Ok(0);
    }

    let sk = socket_key as *const sock;
    let tuple = read_target_server_socket_tuple(sk).map_err(|_| 1i64)?;
    if unsafe { TCP_REQUEST_START.get(&socket_key) }.is_none() {
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if TCP_REQUEST_START.insert(&socket_key, &now_ns, 0).is_err() {
            increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
        }
    }
    increment_risk_tcp_counter(RISK_TCP_READ_INDEX);

    let flow = tuple.flow_key().map_err(|_| 1i64)?;
    if unsafe { TCP_ACTIVE_FLOWS.get(&flow) }.is_some() {
        return Ok(0);
    }
    if TCP_ACTIVE_FLOWS.insert(&flow, &1, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }

    let arrival_ns = unsafe { TCP_PAYLOAD_ARRIVAL.get(&flow) }.copied();
    let _ = TCP_PAYLOAD_ARRIVAL.remove(&flow);
    let Some(arrival_ns) = arrival_ns else {
        return Ok(0);
    };

    increment_risk_tcp_counter(RISK_TCP_ARRIVAL_TO_READ_INDEX);
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let latency_ns = now_ns.saturating_sub(arrival_ns);
    let Some(config) = crate::common::risk_target_config() else {
        return Ok(0);
    };
    if latency_ns >= config.slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_ARRIVAL_TO_READ_SLOW_INDEX);
        output_slow_tcp_event(
            &tuple,
            now_ns,
            latency_ns,
            SLOW_TCP_PHASE_ARRIVAL_TO_READ,
        );
    }
    Ok(0)
}

///
/// 捕获TCP连接建立的耗时时长
/// sudo bpftrace -lv kfunc:tcp_v4_connect
/// kfunc:vmlinux:tcp_v4_connect
///     struct sock * sk
///     struct sockaddr * uaddr
///     int addr_len
///     int retval
///

#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_v4_connect(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_v4_connect(ctx: ProbeContext) -> Result<u32, u64> {
    if !matches_tcp_sendmsg_target()? {
        return Ok(0);
    }
    let sock = ctx.arg::<u64>(0).ok_or(1u64)?;
    let start_time = unsafe { bpf_ktime_get_ns() };
    let is_ok = START.insert(&sock, start_time, 0);
    if is_ok.is_err() {
        return Err(is_ok.unwrap_err() as u64);
    }
    Ok(0)
}

///
/// 跟踪 tracepoint:sock:inet_sock_set_state
/// 利用 (ESTABLISHED) - tcp_v4_connect的时候来获取tcp连接耗时
///
/// sudo cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
///name: inet_sock_set_state
///ID: 1603
///format:
///	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
///	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
///	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
///	field:int common_pid;	offset:4;	size:4;	signed:1;
///
///	field:const void * skaddr;	offset:8;	size:8;	signed:0;
///	field:int oldstate;	offset:16;	size:4;	signed:1;
///	field:int newstate;	offset:20;	size:4;	signed:1;
///	field:__u16 sport;	offset:24;	size:2;	signed:0;
///	field:__u16 dport;	offset:26;	size:2;	signed:0;
///	field:__u16 family;	offset:28;	size:2;	signed:0;
///	field:__u16 protocol;	offset:30;	size:2;	signed:0;
///	field:__u8 saddr[4];	offset:32;	size:4;	signed:0;
///	field:__u8 daddr[4];	offset:36;	size:4;	signed:0;
///	field:__u8 saddr_v6[16];	offset:40;	size:16;	signed:0;
///	field:__u8 daddr_v6[16];	offset:56;	size:16;	signed:0;
///
///print fmt: "family=%s protocol=%s sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c oldstate=%s newstate=%s", __print_symbolic(REC->family, { 2, "AF_INET" }, { 10, "AF_INET6" }), __print_symbolic(REC->protocol, { 6, "IPPROTO_TCP" }, { 33, "IPPROTO_DCCP" }, { 132, "IPPROTO_SCTP" }, { 262, "IPPROTO_MPTCP" }), REC->sport, REC->dport, REC->saddr, REC->daddr, REC->saddr_v6, REC->daddr_v6, __print_symbolic(REC->oldstate, { 1, "TCP_ESTABLISHED" }, { 2, "TCP_SYN_SENT" }, { 3, "TCP_SYN_RECV" }, { 4, "TCP_FIN_WAIT1" }, { 5, "TCP_FIN_WAIT2" }, { 6, "TCP_TIME_WAIT" }, { 7, "TCP_CLOSE" }, { 8, "TCP_CLOSE_WAIT" }, { 9, "TCP_LAST_ACK" }, { 10, "TCP_LISTEN" }, { 11, "TCP_CLOSING" }, { 12, "TCP_NEW_SYN_RECV" }), __print_symbolic(REC->newstate, { 1, "TCP_ESTABLISHED" }, { 2, "TCP_SYN_SENT" }, { 3, "TCP_SYN_RECV" }, { 4, "TCP_FIN_WAIT1" }, { 5, "TCP_FIN_WAIT2" }, { 6, "TCP_TIME_WAIT" }, { 7, "TCP_CLOSE" }, { 8, "TCP_CLOSE_WAIT" }, { 9, "TCP_LAST_ACK" }, { 10, "TCP_LISTEN" }, { 11, "TCP_CLOSING" }, { 12, "TCP_NEW_SYN_RECV" })
///

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, i64> {
    unsafe {
        // void * 这个其实是sock类型的指针
        let skaddr = ctx.read_at::<u64>(8)?;
        let old_state = ctx.read_at::<u32>(16)?;
        let new_state = ctx.read_at::<u32>(20)?;

        if new_state == BPF_TCP_CLOSE {
            let _ = TCP_REQUEST_START.remove(&skaddr);
        }
        if old_state == BPF_TCP_SYN_SENT && new_state == BPF_TCP_ESTABLISHED {
            if let Some(start_ns) = START.get(&skaddr) {
                let current_ns = bpf_ktime_get_ns();
                let cost_ns = current_ns - start_ns;
            }
        }
    }
    Ok(0)
}

///
/// 跟蹤tracepoint sys_enter_accept/accept4
///
/// name: sys_enter_accept
/// ID: 1676
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:int fd;	offset:16;	size:8;	signed:0;
/// 	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
/// 	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
///
/// print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen))
///

#[tracepoint]
pub fn sys_enter_accept(ctx: TracePointContext) -> u32 {
    match try_sys_enter_accept(ctx) {
        Ok(ret) => ret as u32,
        Err(err) => err as u32,
    }
}

fn try_sys_enter_accept(ctx: TracePointContext) -> Result<u32, i64> {
    let (pid, _tid) = common::thread_id();
    unsafe {
        sys_enter_statistics_inc(pid, 3)?;
    }
    Ok(0)
}

///
/// 跟蹤 sys_enter_accept4
///
/// name: sys_enter_accept4
/// ID: 1678
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:int fd;	offset:16;	size:8;	signed:0;
/// 	field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
/// 	field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;
/// 	field:int flags;	offset:40;	size:8;	signed:0;
///
/// print fmt: "fd: 0x%08lx, upeer_sockaddr: 0x%08lx, upeer_addrlen: 0x%08lx, flags: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->upeer_sockaddr)), ((unsigned long)(REC->upeer_addrlen)), ((unsigned long)(REC->flags))
///

#[tracepoint]
pub fn sys_enter_accept4(ctx: TracePointContext) -> u32 {
    match try_sys_enter_accept4(ctx) {
        Ok(ret) => ret as u32,
        Err(err) => err as u32,
    }
}

fn try_sys_enter_accept4(ctx: TracePointContext) -> Result<u32, i64> {
    let (pid, _tid) = common::thread_id();
    unsafe {
        sys_enter_statistics_inc(pid, 4)?;
    }
    Ok(0)
}

///
/// 跟蹤對應的exit系列的方法
///
/// name: sys_exit_accept4
/// ID: 1677
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:long ret;	offset:16;	size:8;	signed:1;
///
/// print fmt: "0x%lx", REC->ret
///
/// name: sys_exit_accept
/// ID: 1675
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
/// 	field:long ret;	offset:16;	size:8;	signed:1;
///
/// print fmt: "0x%lx", REC->ret
///

#[tracepoint]
pub fn sys_exit_accept(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

#[tracepoint]
pub fn sys_exit_accept4(ctx: TracePointContext) -> u32 {
    match try_sys_exit_accept(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_sys_exit_accept(ctx: TracePointContext) -> Result<u32, i64> {
    Ok(0)
}

///
/// 跟踪tcp的reset系列
/// /sys/kernel/debug/tracing/events/tcp/tcp_send_reset/format
/// name: tcp_send_reset
/// ID: 1596
/// format:
/// 	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
/// 	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
/// 	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
/// 	field:int common_pid;	offset:4;	size:4;	signed:1;
///
/// 	field:const void * skbaddr;	offset:8;	size:8;	signed:0;
/// 	field:const void * skaddr;	offset:16;	size:8;	signed:0;
/// 	field:int state;	offset:24;	size:4;	signed:1;
/// 	field:__u16 sport;	offset:28;	size:2;	signed:0;
/// 	field:__u16 dport;	offset:30;	size:2;	signed:0;
/// 	field:__u16 family;	offset:32;	size:2;	signed:0;
/// 	field:__u8 saddr[4];	offset:34;	size:4;	signed:0;
/// 	field:__u8 daddr[4];	offset:38;	size:4;	signed:0;
/// 	field:__u8 saddr_v6[16];	offset:42;	size:16;	signed:0;
/// 	field:__u8 daddr_v6[16];	offset:58;	size:16;	signed:0;
///
#[tracepoint]
pub fn tcp_send_reset(ctx: TracePointContext) -> u32 {
    match try_tcp_send_reset(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_send_reset(ctx: TracePointContext) -> Result<u32, i64> {
    count_target_tcp_event(&ctx, RISK_TCP_SEND_RESET_INDEX)
}

#[tracepoint]
pub fn tcp_receive_reset(ctx: TracePointContext) -> u32 {
    match count_target_tcp_event(&ctx, RISK_TCP_RECEIVE_RESET_INDEX) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

#[tracepoint]
pub fn tcp_retransmit_skb(ctx: TracePointContext) -> u32 {
    match count_target_tcp_event(&ctx, RISK_TCP_RETRANSMIT_INDEX) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn count_target_tcp_event(ctx: &TracePointContext, counter_index: u32) -> Result<u32, i64> {
    const TCP_EVENT_LOCAL_PORT_OFFSET: usize = 36;

    let Some(config) = crate::common::risk_target_config() else {
        return Ok(0);
    };
    let source_port: u16 = unsafe { ctx.read_at(TCP_EVENT_LOCAL_PORT_OFFSET)? };
    if source_port != config.server_port {
        return Ok(0);
    }

    increment_risk_tcp_counter(counter_index);
    Ok(0)
}

fn increment_risk_tcp_counter(counter_index: u32) {
    unsafe {
        if let Some(counter) = RISK_TCP_COUNTERS.get_ptr_mut(counter_index) {
            *counter = (*counter).wrapping_add(1);
        }
    }
}
