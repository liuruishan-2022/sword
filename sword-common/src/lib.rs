#![no_std]

pub const SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES: u32 = 4096;
pub const SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES: u32 = 32768;
pub const TASK_COMM_LEN: usize = 16;
pub const RISK_TARGET_CONFIG_MAX_ENTRIES: u32 = 1;
pub const RISK_TARGET_TGIDS_MAX_ENTRIES: u32 = 128;
pub const SLOW_TCP_PHASE_READ_TO_WRITE: u8 = 1;
pub const SLOW_TCP_PHASE_ARRIVAL_TO_READ: u8 = 2;
pub const SLOW_TCP_PHASE_ARRIVAL_TO_WRITE: u8 = 3;
pub const SLOW_TCP_PHASE_ARRIVAL_TO_EPOLL: u8 = 4;
pub const SLOW_TCP_PHASE_EPOLL_TO_RECV: u8 = 5;
pub const SLOW_TCP_PHASE_RECV_DURATION: u8 = 6;
pub const HTTP_REQUEST_ID_MAX_LEN: usize = 64;
pub const HTTP_PAYLOAD_CHUNK_MAX_LEN: usize = 1024;
pub const HTTP_PAYLOAD_DIRECTION_REQUEST: u8 = 1;
pub const HTTP_PAYLOAD_DIRECTION_RESPONSE: u8 = 2;
pub const RISK_TARGET_FLAG_HTTP_TRACE_ALL: u16 = 1;

pub fn http_request_capture_lengths(bytes_read: u64, buffer_len: u64) -> (usize, usize) {
    let available = bytes_read
        .min(buffer_len)
        .min((HTTP_PAYLOAD_CHUNK_MAX_LEN * 2) as u64) as usize;
    let first_len = available.min(HTTP_PAYLOAD_CHUNK_MAX_LEN);
    let second_len = available
        .saturating_sub(first_len)
        .min(HTTP_PAYLOAD_CHUNK_MAX_LEN);
    (first_len, second_len)
}

const HTTP_REQUEST_ID_PREFIX: &[u8; 13] = b"\"requestId\":\"";

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRequestId {
    pub bytes: [u8; HTTP_REQUEST_ID_MAX_LEN],
    pub len: u8,
    pub _pad: [u8; 7],
}

impl Default for HttpRequestId {
    fn default() -> Self {
        Self {
            bytes: [0; HTTP_REQUEST_ID_MAX_LEN],
            len: 0,
            _pad: [0; 7],
        }
    }
}

impl HttpRequestId {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpRequestIdState {
    request_id: HttpRequestId,
    prefix_len: u8,
    capturing: u8,
    complete: u8,
    _pad: [u8; 5],
}

impl HttpRequestIdState {
    pub fn consume(&mut self, chunk: &[u8]) {
        for byte in chunk {
            if self.complete != 0 {
                break;
            }
            if self.capturing != 0 {
                if *byte == b'"' {
                    if self.request_id.len != 0 {
                        self.complete = 1;
                    }
                    self.capturing = 0;
                    continue;
                }
                let index = self.request_id.len as usize;
                if index >= HTTP_REQUEST_ID_MAX_LEN {
                    self.capturing = 0;
                    self.prefix_len = 0;
                    self.request_id = HttpRequestId::default();
                    continue;
                }
                unsafe {
                    *self.request_id.bytes.get_unchecked_mut(index) = *byte;
                }
                self.request_id.len += 1;
                continue;
            }

            let prefix_index = self.prefix_len as usize;
            if prefix_index >= HTTP_REQUEST_ID_PREFIX.len() {
                self.prefix_len = 0;
                continue;
            }
            let expected = unsafe { *HTTP_REQUEST_ID_PREFIX.get_unchecked(prefix_index) };
            if *byte == expected {
                self.prefix_len += 1;
                if self.prefix_len as usize == HTTP_REQUEST_ID_PREFIX.len() {
                    self.prefix_len = 0;
                    self.capturing = 1;
                }
            } else {
                self.prefix_len = u8::from(*byte == b'"');
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete != 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.request_id.as_bytes()
    }

    pub fn request_id(&self) -> HttpRequestId {
        self.request_id
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpPayloadEvent {
    pub socket_key: u64,
    pub direction: u8,
    pub _pad: [u8; 3],
    pub first_payload_len: u16,
    pub second_payload_len: u16,
    pub first_bytes: [u8; HTTP_PAYLOAD_CHUNK_MAX_LEN],
    pub second_bytes: [u8; HTTP_PAYLOAD_CHUNK_MAX_LEN],
}

impl Default for HttpPayloadEvent {
    fn default() -> Self {
        Self {
            socket_key: 0,
            direction: 0,
            _pad: [0; 3],
            first_payload_len: 0,
            second_payload_len: 0,
            first_bytes: [0; HTTP_PAYLOAD_CHUNK_MAX_LEN],
            second_bytes: [0; HTTP_PAYLOAD_CHUNK_MAX_LEN],
        }
    }
}

impl HttpPayloadEvent {
    pub fn first_payload(&self) -> &[u8] {
        let payload_len = (self.first_payload_len as usize).min(HTTP_PAYLOAD_CHUNK_MAX_LEN);
        &self.first_bytes[..payload_len]
    }

    pub fn second_payload(&self) -> &[u8] {
        let payload_len = (self.second_payload_len as usize).min(HTTP_PAYLOAD_CHUNK_MAX_LEN);
        &self.second_bytes[..payload_len]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestTimings {
    pub arrival_to_epoll_ns: u64,
    pub epoll_to_recv_ns: u64,
    pub recv_duration_ns: u64,
    pub arrival_to_read_ns: u64,
    pub read_to_write_ns: u64,
    pub arrival_to_write_ns: u64,
}

impl RequestTimings {
    pub fn from_timestamps(arrival_ns: u64, read_ns: u64, write_ns: u64) -> Self {
        Self {
            arrival_to_epoll_ns: 0,
            epoll_to_recv_ns: 0,
            recv_duration_ns: 0,
            arrival_to_read_ns: read_ns.saturating_sub(arrival_ns),
            read_to_write_ns: write_ns.saturating_sub(read_ns),
            arrival_to_write_ns: write_ns.saturating_sub(arrival_ns),
        }
    }

    pub fn from_phase_timestamps(
        arrival_ns: u64,
        epoll_exit_ns: u64,
        recv_enter_ns: u64,
        read_ns: u64,
        write_ns: u64,
    ) -> Self {
        let valid_epoll =
            arrival_ns != 0 && epoll_exit_ns >= arrival_ns && recv_enter_ns >= epoll_exit_ns;
        Self {
            arrival_to_epoll_ns: if valid_epoll {
                epoll_exit_ns - arrival_ns
            } else {
                0
            },
            epoll_to_recv_ns: if valid_epoll {
                recv_enter_ns - epoll_exit_ns
            } else {
                0
            },
            recv_duration_ns: non_zero_delta(recv_enter_ns, read_ns),
            arrival_to_read_ns: non_zero_delta(arrival_ns, read_ns),
            read_to_write_ns: non_zero_delta(read_ns, write_ns),
            arrival_to_write_ns: non_zero_delta(arrival_ns, write_ns),
        }
    }
}

fn non_zero_delta(start_ns: u64, end_ns: u64) -> u64 {
    if start_ns == 0 || end_ns < start_ns {
        return 0;
    }
    end_ns - start_ns
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiskTargetConfig {
    pub tgid: u32,
    pub server_port: u16,
    pub flags: u16,
    pub slow_threshold_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq)]
pub struct TcpFlowKey {
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub family: u16,
    pub _pad: u16,
}

impl TcpFlowKey {
    pub fn ipv4(local_addr: u32, remote_addr: u32, local_port: u16, remote_port: u16) -> Self {
        Self {
            local_addr: [local_addr, 0, 0, 0],
            remote_addr: [remote_addr, 0, 0, 0],
            local_port,
            remote_port,
            family: 2,
            _pad: 0,
        }
    }

    pub fn ipv6(
        local_addr: [u32; 4],
        remote_addr: [u32; 4],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            family: 10,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlowTcpEvent {
    pub timestamp_ns: u64,
    pub latency_ns: u64,
    pub arrival_to_epoll_ns: u64,
    pub epoll_to_recv_ns: u64,
    pub recv_duration_ns: u64,
    pub arrival_to_read_ns: u64,
    pub read_to_write_ns: u64,
    pub socket_key: u64,
    pub tgid: u32,
    pub tid: u32,
    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub family: u16,
    pub phase: u8,
    pub _pad: u8,
    pub request_id: HttpRequestId,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SchedSwitchStateKey {
    pub state: u64,
    pub tid: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ThreadComm {
    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlowSchedEvent {
    pub wakeup_ns: u64,
    pub switch_in_ns: u64,
    pub latency_ns: u64,
    pub tid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ThreadOffCpuStart {
    pub ts_ns: u64,
    pub state: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct TargetPid {
    pub pid: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SysEnterType {
    pub pid: u32,
    pub enter_type: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SchedSwitchStateKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadComm {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadOffCpuStart {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TargetPid {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SysEnterType {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RiskTargetConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SlowTcpEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SlowSchedEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpFlowKey {}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        HTTP_PAYLOAD_DIRECTION_REQUEST, HTTP_PAYLOAD_DIRECTION_RESPONSE, HttpPayloadEvent,
        HttpRequestIdState, RequestTimings, SLOW_TCP_PHASE_ARRIVAL_TO_READ,
        SLOW_TCP_PHASE_ARRIVAL_TO_WRITE, SLOW_TCP_PHASE_READ_TO_WRITE, SlowTcpEvent, TcpFlowKey,
        http_request_capture_lengths,
    };

    #[test]
    fn tcp_flow_key_builds_ipv4_and_ipv6_server_flows() {
        let ipv4 = TcpFlowKey::ipv4(
            u32::from_be_bytes([172, 16, 15, 139]),
            u32::from_be_bytes([172, 16, 1, 30]),
            8080,
            54321,
        );
        assert_eq!(ipv4.local_addr[0], u32::from_be_bytes([172, 16, 15, 139]));
        assert_eq!(ipv4.remote_addr[0], u32::from_be_bytes([172, 16, 1, 30]));
        assert_eq!(ipv4.local_port, 8080);
        assert_eq!(ipv4.remote_port, 54321);
        assert_eq!(ipv4.family, 2);

        let ipv6 = TcpFlowKey::ipv6([1, 2, 3, 4], [5, 6, 7, 8], 8080, 12345);
        assert_eq!(ipv6.local_addr, [1, 2, 3, 4]);
        assert_eq!(ipv6.remote_addr, [5, 6, 7, 8]);
        assert_eq!(ipv6.family, 10);
    }

    #[test]
    fn slow_tcp_event_keeps_abi_size_and_has_distinct_phases() {
        assert_eq!(size_of::<SlowTcpEvent>(), 160);
        assert_eq!(size_of::<HttpPayloadEvent>(), 2064);
        assert_ne!(SLOW_TCP_PHASE_READ_TO_WRITE, SLOW_TCP_PHASE_ARRIVAL_TO_READ);
        assert_ne!(
            SLOW_TCP_PHASE_ARRIVAL_TO_READ,
            SLOW_TCP_PHASE_ARRIVAL_TO_WRITE
        );
    }

    #[test]
    fn extracts_request_id_across_receive_chunks() {
        let mut state = HttpRequestIdState::default();

        state.consume(
            br#"POST /evaluate HTTP/1.1
Content-Type: application/json

{"reque"#,
        );
        assert!(!state.is_complete());

        state.consume(br#"stId":"7fbb215d-a5d1-4478-b134-fad7a388dea3","packId":"p1"}"#);

        assert!(state.is_complete());
        assert_eq!(state.as_bytes(), b"7fbb215d-a5d1-4478-b134-fad7a388dea3");
    }

    #[test]
    fn extracts_request_id_after_first_512_bytes_in_one_receive() {
        let mut payload = [b'x'; 1800];
        let request_id = br#""requestId":"7fbb215d-a5d1-4478-b134-fad7a388dea3""#;
        payload[1500..1500 + request_id.len()].copy_from_slice(request_id);

        let (first_len, second_len) =
            http_request_capture_lengths(payload.len() as u64, payload.len() as u64);
        let mut state = HttpRequestIdState::default();
        state.consume(&payload[..first_len]);
        state.consume(&payload[first_len..first_len + second_len]);

        assert!(state.is_complete());
        assert_eq!(state.as_bytes(), b"7fbb215d-a5d1-4478-b134-fad7a388dea3");
    }

    #[test]
    fn http_payload_event_distinguishes_request_and_response() {
        let request = HttpPayloadEvent {
            direction: HTTP_PAYLOAD_DIRECTION_REQUEST,
            ..Default::default()
        };
        let response = HttpPayloadEvent {
            direction: HTTP_PAYLOAD_DIRECTION_RESPONSE,
            ..Default::default()
        };

        assert_ne!(request.direction, response.direction);
    }

    #[test]
    fn splits_arrival_to_write_into_queue_and_processing_time() {
        let timings = RequestTimings::from_timestamps(1_000, 51_000, 651_000);

        assert_eq!(timings.arrival_to_read_ns, 50_000);
        assert_eq!(timings.read_to_write_ns, 600_000);
        assert_eq!(timings.arrival_to_write_ns, 650_000);
    }

    #[test]
    fn splits_socket_to_xnio_read_into_epoll_and_recv_phases() {
        let timings = RequestTimings::from_phase_timestamps(1_000, 11_000, 31_000, 51_000, 651_000);

        assert_eq!(timings.arrival_to_epoll_ns, 10_000);
        assert_eq!(timings.epoll_to_recv_ns, 20_000);
        assert_eq!(timings.recv_duration_ns, 20_000);
        assert_eq!(timings.arrival_to_read_ns, 50_000);
        assert_eq!(timings.read_to_write_ns, 600_000);
        assert_eq!(timings.arrival_to_write_ns, 650_000);
    }
}
