use std::sync::atomic::AtomicU64;

use aya::maps::{HashMap, MapData, MapError, PerCpuArray};
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use sword_common::{SchedSwitchStateKey, ThreadComm};

///
/// 主要是放置CPU的ebpf采集到的相关的指标信息
///

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SchedSwitchLabels {
    cpu: u32,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ThreadStateLabels {
    tid: u32,
    comm: String,
    state: String,
}

pub struct CpuMetrics {
    sched_switch_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
    sys_enter_open_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
    thread_sched_switch_out_total: Family<ThreadStateLabels, Gauge<u64, AtomicU64>>,
    thread_offcpu_ns_total: Family<ThreadStateLabels, Gauge<u64, AtomicU64>>,
    target_thread_runqueue_total: Gauge<u64, AtomicU64>,
    target_thread_runqueue_latency_ns_total: Gauge<u64, AtomicU64>,
    target_thread_runqueue_slow_total: Gauge<u64, AtomicU64>,
}

impl CpuMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let sched_switch_total = Family::<SchedSwitchLabels, Gauge<u64, AtomicU64>>::default();
        let sys_enter_open_total = Family::<SchedSwitchLabels, Gauge<u64, AtomicU64>>::default();
        let thread_sched_switch_out_total =
            Family::<ThreadStateLabels, Gauge<u64, AtomicU64>>::default();
        let thread_offcpu_ns_total = Family::<ThreadStateLabels, Gauge<u64, AtomicU64>>::default();
        let target_thread_runqueue_total = Gauge::default();
        let target_thread_runqueue_latency_ns_total = Gauge::default();
        let target_thread_runqueue_slow_total = Gauge::default();
        registry.register(
            "sched_switch_total",
            "Total number of sched_switch events per CPU",
            sched_switch_total.clone(),
        );
        registry.register(
            "sys_enter_open_total",
            "Total number of sys_enter_open events per CPU",
            sys_enter_open_total.clone(),
        );
        registry.register(
            "thread_sched_switch_out_total",
            "Total number of sched_switch switch-out events per tracked thread and task state",
            thread_sched_switch_out_total.clone(),
        );
        registry.register(
            "thread_offcpu_ns_total",
            "Total off-CPU time in nanoseconds per tracked thread and switch-out task state",
            thread_offcpu_ns_total.clone(),
        );
        registry.register(
            "sword_target_thread_runqueue_total",
            "Total target thread wakeup-to-running events",
            target_thread_runqueue_total.clone(),
        );
        registry.register(
            "sword_target_thread_runqueue_latency_ns_total",
            "Total target thread wakeup-to-running latency in nanoseconds",
            target_thread_runqueue_latency_ns_total.clone(),
        );
        registry.register(
            "sword_target_thread_runqueue_slow_total",
            "Total target thread wakeup-to-running events over the configured threshold",
            target_thread_runqueue_slow_total.clone(),
        );
        Self {
            sched_switch_total,
            sys_enter_open_total,
            thread_sched_switch_out_total,
            thread_offcpu_ns_total,
            target_thread_runqueue_total,
            target_thread_runqueue_latency_ns_total,
            target_thread_runqueue_slow_total,
        }
    }

    pub fn inc_sched_switch_total(&self, cpu: u32, count: u64) {
        self.sched_switch_total
            .get_or_create(&SchedSwitchLabels { cpu: cpu })
            .set(count);
    }

    pub fn inc_sys_enter_open_total(&self, cpu: u32, count: u64) {
        self.sys_enter_open_total
            .get_or_create(&SchedSwitchLabels { cpu: cpu })
            .set(count);
    }

    pub fn set_thread_sched_switch_out_total(
        &self,
        tid: u32,
        comm: String,
        state: String,
        count: u64,
    ) {
        self.thread_sched_switch_out_total
            .get_or_create(&ThreadStateLabels { tid, comm, state })
            .set(count);
    }

    pub fn set_thread_offcpu_ns_total(&self, tid: u32, comm: String, state: String, ns: u64) {
        self.thread_offcpu_ns_total
            .get_or_create(&ThreadStateLabels { tid, comm, state })
            .set(ns);
    }

    fn set_target_runqueue(&self, events: u64, latency_ns: u64, slow: u64) {
        self.target_thread_runqueue_total.set(events);
        self.target_thread_runqueue_latency_ns_total.set(latency_ns);
        self.target_thread_runqueue_slow_total.set(slow);
    }
}

///
/// 放置cpu执行ebpf的map数据和我们的指标之间的转换的关系
///
pub struct CpuCollector {
    sched_switch: PerCpuArray<MapData, u64>,
    sys_enter_open: PerCpuArray<MapData, u64>,
    thread_switch_out: HashMap<MapData, SchedSwitchStateKey, u64>,
    thread_offcpu: HashMap<MapData, SchedSwitchStateKey, u64>,
    thread_comm: HashMap<MapData, u32, ThreadComm>,
    runqueue_metrics: PerCpuArray<MapData, u64>,
    registry: Registry,
    cpu: CpuMetrics,
}

impl CpuCollector {
    pub fn new(
        sched_switch: PerCpuArray<MapData, u64>,
        sys_enter_open: PerCpuArray<MapData, u64>,
        thread_switch_out: HashMap<MapData, SchedSwitchStateKey, u64>,
        thread_offcpu: HashMap<MapData, SchedSwitchStateKey, u64>,
        thread_comm: HashMap<MapData, u32, ThreadComm>,
        runqueue_metrics: PerCpuArray<MapData, u64>,
    ) -> Self {
        let mut registry = Registry::default();
        let cpu = CpuMetrics::new(&mut registry);
        Self {
            sched_switch: sched_switch,
            sys_enter_open: sys_enter_open,
            thread_switch_out,
            thread_offcpu,
            thread_comm,
            runqueue_metrics,
            registry: registry,
            cpu: cpu,
        }
    }

    pub async fn collect(&self) -> Result<(), MapError> {
        let sched_switch_cpus = self.sched_switch.get(&0, 0)?;
        sched_switch_cpus
            .iter()
            .enumerate()
            .for_each(|(index, count)| {
                self.cpu.inc_sched_switch_total(index as u32, *count);
            });
        let sys_enter_open_cpus = self.sys_enter_open.get(&0, 0)?;
        sys_enter_open_cpus
            .iter()
            .enumerate()
            .for_each(|(index, count)| {
                self.cpu.inc_sys_enter_open_total(index as u32, *count);
            });
        for item in self.thread_switch_out.iter() {
            let (key, count) = item?;
            let comm = self.thread_comm(key.tid);
            let state = sched_switch_state_label(key.state);
            self.cpu
                .set_thread_sched_switch_out_total(key.tid, comm, state, count);
        }
        for item in self.thread_offcpu.iter() {
            let (key, ns) = item?;
            let comm = self.thread_comm(key.tid);
            let state = sched_switch_state_label(key.state);
            self.cpu
                .set_thread_offcpu_ns_total(key.tid, comm, state, ns);
        }
        self.cpu.set_target_runqueue(
            self.per_cpu_total(0)?,
            self.per_cpu_total(1)?,
            self.per_cpu_total(2)?,
        );
        Ok(())
    }

    pub async fn metrics(&self) -> anyhow::Result<String> {
        self.collect().await?;
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry)?;
        Ok(buffer)
    }

    fn thread_comm(&self, tid: u32) -> String {
        self.thread_comm
            .get(&tid, 0)
            .map(|comm| thread_comm_label(&comm))
            .unwrap_or_default()
    }

    fn per_cpu_total(&self, index: u32) -> Result<u64, MapError> {
        Ok(self.runqueue_metrics.get(&index, 0)?.iter().copied().sum())
    }
}

fn thread_comm_label(thread_comm: &ThreadComm) -> String {
    let len = thread_comm
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(thread_comm.comm.len());
    String::from_utf8_lossy(&thread_comm.comm[..len]).into_owned()
}

fn sched_switch_state_label(state: u64) -> String {
    match state {
        0 => "TASK_RUNNING".to_string(),
        1 => "TASK_INTERRUPTIBLE".to_string(),
        2 => "TASK_UNINTERRUPTIBLE".to_string(),
        4 => "TASK_STOPPED".to_string(),
        8 => "TASK_TRACED".to_string(),
        16 => "EXIT_DEAD".to_string(),
        32 => "EXIT_ZOMBIE".to_string(),
        64 => "TASK_PARKED".to_string(),
        128 => "TASK_DEAD".to_string(),
        256 => "TASK_WAKEKILL".to_string(),
        512 => "TASK_WAKING".to_string(),
        1024 => "TASK_NOLOAD".to_string(),
        2048 => "TASK_NEW".to_string(),
        4096 => "TASK_RTLOCK_WAIT".to_string(),
        _ => format!("0x{state:x}"),
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::CpuMetrics;

    #[test]
    fn exports_target_runqueue_metrics_without_thread_labels() {
        let mut registry = Registry::default();
        let metrics = CpuMetrics::new(&mut registry);
        metrics.set_target_runqueue(7, 123_000_000, 2);

        let mut output = String::new();
        encode(&mut output, &registry).unwrap();

        assert!(output.contains("sword_target_thread_runqueue_total 7"));
        assert!(output.contains("sword_target_thread_runqueue_latency_ns_total 123000000"));
        assert!(output.contains("sword_target_thread_runqueue_slow_total 2"));
    }
}
