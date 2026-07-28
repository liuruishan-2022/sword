#![no_std]

pub const SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES: u32 = 4096;
pub const SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES: u32 = 32768;
pub const TASK_COMM_LEN: usize = 16;
pub const RISK_TARGET_CONFIG_MAX_ENTRIES: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiskTargetConfig {
    pub tgid: u32,
    pub server_port: u16,
    pub _pad: u16,
    pub slow_threshold_ns: u64,
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
    pub _pad: u16,
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
