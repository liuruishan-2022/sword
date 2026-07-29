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
        bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user_buf,
        generated::bpf_ktime_get_ns,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use sword_common::{
    HTTP_PAYLOAD_CHUNK_MAX_LEN, HTTP_PAYLOAD_DIRECTION_REQUEST, HTTP_PAYLOAD_DIRECTION_RESPONSE,
    HttpPayloadEvent, HttpRequestId, RISK_TARGET_FLAG_HTTP_TRACE_ALL, RequestTimings,
    SLOW_TCP_PHASE_ARRIVAL_TO_EPOLL, SLOW_TCP_PHASE_ARRIVAL_TO_READ,
    SLOW_TCP_PHASE_ARRIVAL_TO_WRITE, SLOW_TCP_PHASE_EPOLL_TO_RECV, SLOW_TCP_PHASE_READ_TO_WRITE,
    SLOW_TCP_PHASE_RECV_DURATION, SlowTcpEvent, SysEnterType, TargetPid,
    http_request_capture_lengths,
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
const RISK_TCP_ARRIVAL_TO_EPOLL_LATENCY_NS_INDEX: u32 = 10;
const RISK_TCP_ARRIVAL_TO_EPOLL_SLOW_INDEX: u32 = 11;
const RISK_TCP_EPOLL_TO_RECV_LATENCY_NS_INDEX: u32 = 12;
const RISK_TCP_EPOLL_TO_RECV_SLOW_INDEX: u32 = 13;
const RISK_TCP_RECV_DURATION_NS_INDEX: u32 = 14;
const RISK_TCP_RECV_DURATION_SLOW_INDEX: u32 = 15;
const HTTP_REQUEST_SLOW_THRESHOLD_NS: u64 = 500_000_000;
const MSGHDR_MSG_ITER_OFFSET: usize = 16;
const IOV_ITER_TYPE_OFFSET: usize = 0;
const IOV_ITER_IOV_OFFSET_OFFSET: usize = 8;
const IOV_ITER_BUFFER_OFFSET: usize = 16;
const IOV_ITER_COUNT_OFFSET: usize = 24;
const ITER_UBUF: u8 = 0;
const ITER_IOVEC: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpRecvInflight {
    socket_key: u64,
    user_buffer: u64,
    buffer_len: u64,
    recv_enter_ns: u64,
    epoll_exit_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpRequestContext {
    arrival_ns: u64,
    epoll_exit_ns: u64,
    recv_enter_ns: u64,
    read_ns: u64,
}

#[map]
pub static TARGET_PID: Array<TargetPid> = Array::with_max_entries(1, 0);

#[map]
pub static SYS_ENTER_CONNECT: PerCpuHashMap<u32, u64> = PerCpuHashMap::with_max_entries(4096, 0);

#[map]
pub static START: HashMap<u64, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static RISK_TCP_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

#[map]
pub static TCP_RECV_INFLIGHT: HashMap<u32, TcpRecvInflight> = HashMap::with_max_entries(4096, 0);

#[map]
pub static EPOLL_WAIT_ENTER_NS: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static EPOLL_EVENT_EXIT_NS: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
pub static HTTP_PAYLOAD_BUFFER: PerCpuArray<HttpPayloadEvent> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static HTTP_REQUEST_HEADS: LruHashMap<u64, HttpPayloadEvent> =
    LruHashMap::with_max_entries(8192, 0);

#[map]
pub static TCP_REQUEST_START: HashMap<u64, TcpRequestContext> = HashMap::with_max_entries(32768, 0);

#[map]
pub static TCP_PAYLOAD_ARRIVAL: LruHashMap<u64, u64> =
    LruHashMap::with_max_entries(32768, 0);

#[map]
pub static TCP_ACTIVE_FLOWS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(32768, 0);

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
    let socket_key = sk as u64;
    let _ = TCP_ACTIVE_FLOWS.remove(&socket_key);
    increment_risk_tcp_counter(RISK_TCP_WRITE_INDEX);

    let Some(request) = (unsafe { TCP_REQUEST_START.get(&socket_key) }).copied() else {
        let _ = HTTP_REQUEST_HEADS.remove(&socket_key);
        return Ok(0);
    };
    let _ = TCP_REQUEST_START.remove(&socket_key);

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let read_to_write_ns = now_ns.saturating_sub(request.read_ns);
    let Some(config) = crate::common::risk_target_config() else {
        let _ = HTTP_REQUEST_HEADS.remove(&socket_key);
        return Ok(0);
    };
    if read_to_write_ns >= config.slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_SLOW_INDEX);
        output_slow_tcp_event(
            &tuple,
            now_ns,
            read_to_write_ns,
            SLOW_TCP_PHASE_READ_TO_WRITE,
        );
    }

    let timings = RequestTimings::from_phase_timestamps(
        request.arrival_ns,
        request.epoll_exit_ns,
        request.recv_enter_ns,
        request.read_ns,
        now_ns,
    );
    let slow_http =
        request.arrival_ns != 0 && timings.arrival_to_write_ns >= HTTP_REQUEST_SLOW_THRESHOLD_NS;
    let trace_all = config.flags & RISK_TARGET_FLAG_HTTP_TRACE_ALL != 0;
    if trace_all || slow_http {
        output_http_request_payload(socket_key);
        output_http_response_payload(&ctx, socket_key);
    }
    if slow_http {
        output_slow_http_event(&tuple, socket_key, now_ns, timings);
    }
    let _ = HTTP_REQUEST_HEADS.remove(&socket_key);

    Ok(0)
}

#[tracepoint]
pub fn sys_enter_epoll_wait(ctx: TracePointContext) -> u32 {
    match try_sys_enter_epoll_wait(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn sys_enter_epoll_pwait(ctx: TracePointContext) -> u32 {
    match try_sys_enter_epoll_wait(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_enter_epoll_wait(_ctx: TracePointContext) -> Result<u32, i64> {
    let (tgid, tid) = common::thread_id();
    if !common::is_risk_target_tgid(tgid) {
        return Ok(0);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let _ = EPOLL_EVENT_EXIT_NS.remove(&tid);
    if EPOLL_WAIT_ENTER_NS.insert(&tid, &now_ns, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_epoll_wait(ctx: TracePointContext) -> u32 {
    match try_sys_exit_epoll_wait(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

#[tracepoint]
pub fn sys_exit_epoll_pwait(ctx: TracePointContext) -> u32 {
    match try_sys_exit_epoll_wait(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_sys_exit_epoll_wait(ctx: TracePointContext) -> Result<u32, i64> {
    let (tgid, tid) = common::thread_id();
    if !common::is_risk_target_tgid(tgid) {
        return Ok(0);
    }
    if unsafe { EPOLL_WAIT_ENTER_NS.get(&tid).is_none() } {
        return Ok(0);
    }
    let _ = EPOLL_WAIT_ENTER_NS.remove(&tid);

    let ready: i64 = unsafe { ctx.read_at(16)? };
    if ready <= 0 {
        let _ = EPOLL_EVENT_EXIT_NS.remove(&tid);
        return Ok(0);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    if EPOLL_EVENT_EXIT_NS.insert(&tid, &now_ns, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
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

fn output_slow_tcp_event(tuple: &TcpSocketTuple, timestamp_ns: u64, latency_ns: u64, phase: u8) {
    let event = SlowTcpEvent {
        timestamp_ns,
        latency_ns,
        arrival_to_epoll_ns: 0,
        epoll_to_recv_ns: 0,
        recv_duration_ns: 0,
        arrival_to_read_ns: 0,
        read_to_write_ns: 0,
        socket_key: 0,
        tgid: tuple.pid,
        tid: tuple.tid,
        source_addr_v4: tuple.saddr_v4,
        destination_addr_v4: tuple.daddr_v4,
        source_port: tuple.sport,
        destination_port: tuple.dport,
        family: tuple.family,
        phase,
        _pad: 0,
        request_id: HttpRequestId::default(),
    };
    if SLOW_TCP_EVENTS.output::<SlowTcpEvent>(&event, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
}

fn output_slow_http_event(
    tuple: &TcpSocketTuple,
    socket_key: u64,
    timestamp_ns: u64,
    timings: RequestTimings,
) {
    let event = SlowTcpEvent {
        timestamp_ns,
        latency_ns: timings.arrival_to_write_ns,
        arrival_to_epoll_ns: timings.arrival_to_epoll_ns,
        epoll_to_recv_ns: timings.epoll_to_recv_ns,
        recv_duration_ns: timings.recv_duration_ns,
        arrival_to_read_ns: timings.arrival_to_read_ns,
        read_to_write_ns: timings.read_to_write_ns,
        socket_key,
        tgid: tuple.pid,
        tid: tuple.tid,
        source_addr_v4: tuple.saddr_v4,
        destination_addr_v4: tuple.daddr_v4,
        source_port: tuple.sport,
        destination_port: tuple.dport,
        family: tuple.family,
        phase: SLOW_TCP_PHASE_ARRIVAL_TO_WRITE,
        _pad: 0,
        request_id: HttpRequestId::default(),
    };
    if SLOW_TCP_EVENTS.output::<SlowTcpEvent>(&event, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
}

fn output_http_request_payload(socket_key: u64) {
    let Some(request) = (unsafe { HTTP_REQUEST_HEADS.get(&socket_key) }) else {
        return;
    };
    output_http_payload(request);
}

fn output_http_response_payload(ctx: &ProbeContext, socket_key: u64) {
    let Some(msg) = ctx.arg::<u64>(1) else {
        return;
    };
    let Some(bytes_to_write) = ctx.arg::<u64>(2) else {
        return;
    };
    let Ok((user_buffer, buffer_len)) = read_msg_user_buffer(msg) else {
        return;
    };
    let Some(response) = HTTP_PAYLOAD_BUFFER.get_ptr_mut(0) else {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
        return;
    };
    unsafe {
        (*response).socket_key = socket_key;
        (*response).direction = HTTP_PAYLOAD_DIRECTION_RESPONSE;
        (*response)._pad = [0; 3];
        (*response).first_payload_len = 0;
        (*response).second_payload_len = 0;
    }
    capture_first_payload_chunks(response, user_buffer, buffer_len, bytes_to_write);
    if unsafe { (*response).first_payload_len } != 0 {
        output_http_payload(unsafe { &*response });
    }
}

fn output_http_payload(payload: &HttpPayloadEvent) {
    if SLOW_TCP_EVENTS
        .output::<HttpPayloadEvent>(payload, 0)
        .is_err()
    {
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
    let current_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !crate::common::is_risk_target_tgid(current_tgid) {
        return Err(1);
    }
    read_server_socket_tuple(sk)
}

fn read_server_socket_tuple(sk: *const sock) -> Result<TcpSocketTuple, u32> {
    let Some(config) = crate::common::risk_target_config() else {
        return Err(1);
    };
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

/// Record when payload enters the target server socket. Using the socket
/// pointer as the key avoids kernel-dependent IPv6 flow tuple layouts.
#[kprobe]
pub fn tcp_data_queue(ctx: ProbeContext) -> u32 {
    match try_tcp_data_queue(ctx) {
        Ok(ret) => ret,
        Err(err) => err as u32,
    }
}

fn try_tcp_data_queue(ctx: ProbeContext) -> Result<u32, i64> {
    let sk: *const sock = ctx.arg(0).ok_or(1i64)?;
    read_server_socket_tuple(sk).map_err(|_| 1i64)?;
    let socket_key = sk as u64;
    increment_risk_tcp_counter(RISK_TCP_PAYLOAD_ARRIVAL_INDEX);

    if unsafe { TCP_ACTIVE_FLOWS.get(&socket_key) }.is_some()
        || unsafe { TCP_PAYLOAD_ARRIVAL.get(&socket_key) }.is_some()
    {
        return Ok(0);
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    if TCP_PAYLOAD_ARRIVAL
        .insert(&socket_key, &now_ns, 0)
        .is_err()
    {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    Ok(0)
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
    let msg = ctx.arg::<u64>(1).ok_or(1i64)?;
    let (user_buffer, buffer_len) = read_msg_user_buffer(msg).unwrap_or((0, 0));
    let tid = bpf_get_current_pid_tgid() as u32;
    let recv_enter_ns = unsafe { bpf_ktime_get_ns() };
    let epoll_exit_ns = unsafe { EPOLL_EVENT_EXIT_NS.get(&tid) }
        .copied()
        .unwrap_or(0);
    let inflight = TcpRecvInflight {
        socket_key: sk as u64,
        user_buffer,
        buffer_len,
        recv_enter_ns,
        epoll_exit_ns,
    };
    if TCP_RECV_INFLIGHT.insert(&tid, &inflight, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    Ok(0)
}

fn read_msg_user_buffer(msg: u64) -> Result<(u64, u64), i64> {
    let iter = msg + MSGHDR_MSG_ITER_OFFSET as u64;
    let iter_type =
        unsafe { bpf_probe_read_kernel((iter + IOV_ITER_TYPE_OFFSET as u64) as *const u8) }?;
    let iov_offset =
        unsafe { bpf_probe_read_kernel((iter + IOV_ITER_IOV_OFFSET_OFFSET as u64) as *const u64) }?;

    let (base, len) = if iter_type == ITER_UBUF {
        let base =
            unsafe { bpf_probe_read_kernel((iter + IOV_ITER_BUFFER_OFFSET as u64) as *const u64) }?;
        let len =
            unsafe { bpf_probe_read_kernel((iter + IOV_ITER_COUNT_OFFSET as u64) as *const u64) }?;
        (base, len)
    } else if iter_type == ITER_IOVEC {
        let iov =
            unsafe { bpf_probe_read_kernel((iter + IOV_ITER_BUFFER_OFFSET as u64) as *const u64) }?;
        if iov == 0 {
            return Err(1);
        }
        let base = unsafe { bpf_probe_read_kernel(iov as *const u64) }?;
        let len = unsafe { bpf_probe_read_kernel((iov + 8) as *const u64) }?;
        (base, len)
    } else {
        return Err(1);
    };

    if base == 0 || iov_offset >= len {
        return Err(1);
    }
    Ok((base + iov_offset, len - iov_offset))
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
    let Some(inflight) = (unsafe { TCP_RECV_INFLIGHT.get(&tid) }).copied() else {
        return Ok(0);
    };
    let _ = TCP_RECV_INFLIGHT.remove(&tid);

    let bytes_read: i64 = ctx.ret();
    if bytes_read <= 0 {
        return Ok(0);
    }

    let socket_key = inflight.socket_key;
    let sk = socket_key as *const sock;
    let tuple = read_target_server_socket_tuple(sk).map_err(|_| 1i64)?;
    let existing = unsafe { TCP_REQUEST_START.get(&socket_key) }.copied();
    let first_read = existing.is_none();
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let request = existing.unwrap_or_else(|| {
        let arrival_ns = unsafe { TCP_PAYLOAD_ARRIVAL.get(&socket_key) }
            .copied()
            .unwrap_or(0);
        TcpRequestContext {
            arrival_ns,
            epoll_exit_ns: inflight.epoll_exit_ns,
            recv_enter_ns: inflight.recv_enter_ns,
            read_ns: now_ns,
        }
    });
    capture_request_head(socket_key, &inflight, bytes_read as u64, first_read);
    if TCP_REQUEST_START.insert(&socket_key, &request, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }
    increment_risk_tcp_counter(RISK_TCP_READ_INDEX);

    if !first_read {
        return Ok(0);
    }
    if TCP_ACTIVE_FLOWS.insert(&socket_key, &1, 0).is_err() {
        increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
    }

    let _ = TCP_PAYLOAD_ARRIVAL.remove(&socket_key);
    if request.arrival_ns == 0 {
        return Ok(0);
    }

    increment_risk_tcp_counter(RISK_TCP_ARRIVAL_TO_READ_INDEX);
    let latency_ns = now_ns.saturating_sub(request.arrival_ns);
    let Some(config) = crate::common::risk_target_config() else {
        return Ok(0);
    };
    if latency_ns >= config.slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_ARRIVAL_TO_READ_SLOW_INDEX);
        output_slow_tcp_event(&tuple, now_ns, latency_ns, SLOW_TCP_PHASE_ARRIVAL_TO_READ);
    }
    record_recv_phase_metrics(
        &tuple,
        now_ns,
        RequestTimings::from_phase_timestamps(
            request.arrival_ns,
            request.epoll_exit_ns,
            request.recv_enter_ns,
            request.read_ns,
            request.read_ns,
        ),
        config.slow_threshold_ns,
    );
    Ok(0)
}

fn record_recv_phase_metrics(
    tuple: &TcpSocketTuple,
    timestamp_ns: u64,
    timings: RequestTimings,
    slow_threshold_ns: u64,
) {
    add_risk_tcp_counter(
        RISK_TCP_ARRIVAL_TO_EPOLL_LATENCY_NS_INDEX,
        timings.arrival_to_epoll_ns,
    );
    if timings.arrival_to_epoll_ns >= slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_ARRIVAL_TO_EPOLL_SLOW_INDEX);
        output_slow_tcp_event(
            tuple,
            timestamp_ns,
            timings.arrival_to_epoll_ns,
            SLOW_TCP_PHASE_ARRIVAL_TO_EPOLL,
        );
    }
    add_risk_tcp_counter(
        RISK_TCP_EPOLL_TO_RECV_LATENCY_NS_INDEX,
        timings.epoll_to_recv_ns,
    );
    if timings.epoll_to_recv_ns >= slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_EPOLL_TO_RECV_SLOW_INDEX);
        output_slow_tcp_event(
            tuple,
            timestamp_ns,
            timings.epoll_to_recv_ns,
            SLOW_TCP_PHASE_EPOLL_TO_RECV,
        );
    }
    add_risk_tcp_counter(RISK_TCP_RECV_DURATION_NS_INDEX, timings.recv_duration_ns);
    if timings.recv_duration_ns >= slow_threshold_ns {
        increment_risk_tcp_counter(RISK_TCP_RECV_DURATION_SLOW_INDEX);
        output_slow_tcp_event(
            tuple,
            timestamp_ns,
            timings.recv_duration_ns,
            SLOW_TCP_PHASE_RECV_DURATION,
        );
    }
}

fn capture_request_head(
    socket_key: u64,
    inflight: &TcpRecvInflight,
    bytes_read: u64,
    first_read: bool,
) {
    if inflight.user_buffer == 0 || inflight.buffer_len == 0 {
        return;
    }

    if first_read {
        let Some(request) = HTTP_PAYLOAD_BUFFER.get_ptr_mut(0) else {
            increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
            return;
        };
        unsafe {
            (*request).socket_key = socket_key;
            (*request).direction = HTTP_PAYLOAD_DIRECTION_REQUEST;
            (*request)._pad = [0; 3];
            (*request).first_payload_len = 0;
            (*request).second_payload_len = 0;
        }
        capture_first_payload_chunks(
            request,
            inflight.user_buffer,
            inflight.buffer_len,
            bytes_read,
        );
        if unsafe { (*request).first_payload_len } != 0
            && HTTP_REQUEST_HEADS
                .insert(&socket_key, unsafe { &*request }, 0)
                .is_err()
        {
            increment_risk_tcp_counter(RISK_TCP_EVENT_DROPPED_INDEX);
        }
        return;
    }

    let Some(request) = HTTP_REQUEST_HEADS.get_ptr_mut(&socket_key) else {
        return;
    };
    capture_second_payload_chunk(
        request,
        inflight.user_buffer,
        inflight.buffer_len,
        bytes_read,
    );
}

fn capture_first_payload_chunks(
    payload_event: *mut HttpPayloadEvent,
    user_buffer: u64,
    buffer_len: u64,
    payload_len: u64,
) {
    let (first_len, second_len) = http_request_capture_lengths(payload_len, buffer_len);
    if first_len == 0 {
        return;
    }

    let destination = unsafe { (*payload_event).first_bytes.as_mut_ptr() };
    let payload = unsafe { core::slice::from_raw_parts_mut(destination, first_len) };
    if unsafe { bpf_probe_read_user_buf(user_buffer as *const u8, payload) }.is_ok() {
        unsafe {
            (*payload_event).first_payload_len = first_len as u16;
        }
    }
    if second_len == 0 {
        return;
    }

    let destination = unsafe { (*payload_event).second_bytes.as_mut_ptr() };
    let payload = unsafe { core::slice::from_raw_parts_mut(destination, second_len) };
    let source = user_buffer + HTTP_PAYLOAD_CHUNK_MAX_LEN as u64;
    if unsafe { bpf_probe_read_user_buf(source as *const u8, payload) }.is_ok() {
        unsafe {
            (*payload_event).second_payload_len = second_len as u16;
        }
    }
}

fn capture_second_payload_chunk(
    payload_event: *mut HttpPayloadEvent,
    user_buffer: u64,
    buffer_len: u64,
    payload_len: u64,
) {
    if unsafe { (*payload_event).second_payload_len } != 0 {
        return;
    }
    let copy_len = payload_len
        .min(buffer_len)
        .min(HTTP_PAYLOAD_CHUNK_MAX_LEN as u64) as usize;
    if copy_len == 0 {
        return;
    }

    let destination = unsafe { (*payload_event).second_bytes.as_mut_ptr() };
    let payload = unsafe { core::slice::from_raw_parts_mut(destination, copy_len) };
    if unsafe { bpf_probe_read_user_buf(user_buffer as *const u8, payload) }.is_ok() {
        unsafe {
            (*payload_event).second_payload_len = copy_len as u16;
        }
    }
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
    add_risk_tcp_counter(counter_index, 1);
}

fn add_risk_tcp_counter(counter_index: u32, value: u64) {
    unsafe {
        if let Some(counter) = RISK_TCP_COUNTERS.get_ptr_mut(counter_index) {
            *counter = (*counter).wrapping_add(value);
        }
    }
}
