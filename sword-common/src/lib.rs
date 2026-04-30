#![no_std]

pub const SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES: u32 = 4096;
pub const SCHED_SWITCH_THREAD_STATE_MAX_ENTRIES: u32 = 32768;

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
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ThreadOffCpuStart {
    pub ts_ns: u64,
    pub state: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SchedSwitchStateKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadComm {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadOffCpuStart {}
