#![no_std]

pub const SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES: u32 = 4096;
pub const SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES: u32 = 32768;
pub const TASK_COMM_LEN: usize = 16;
pub const RISK_TARGET_CONFIG_MAX_ENTRIES: u32 = 1;
pub const RISK_TARGET_TGIDS_MAX_ENTRIES: u32 = 128;
pub const SLOW_TCP_PHASE_READ_TO_WRITE: u8 = 1;
pub const SLOW_TCP_PHASE_ARRIVAL_TO_READ: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiskTargetConfig {
    pub tgid: u32,
    pub server_port: u16,
    pub _pad: u16,
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
    pub tgid: u32,
    pub tid: u32,
    pub source_addr_v4: u32,
    pub destination_addr_v4: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub family: u16,
    pub phase: u8,
    pub _pad: u8,
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
unsafe impl aya::Pod for TcpFlowKey {}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        SLOW_TCP_PHASE_ARRIVAL_TO_READ, SLOW_TCP_PHASE_READ_TO_WRITE, SlowTcpEvent, TcpFlowKey,
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
        assert_eq!(size_of::<SlowTcpEvent>(), 40);
        assert_ne!(SLOW_TCP_PHASE_READ_TO_WRITE, SLOW_TCP_PHASE_ARRIVAL_TO_READ);
    }
}
