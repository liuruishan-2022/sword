use std::sync::atomic::AtomicU64;

use aya::maps::{MapData, MapError, PerCpuArray};
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};

///
/// 主要是放置CPU的ebpf采集到的相关的指标信息
///

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SchedSwitchLabels {
    cpu: u32,
}

pub struct CpuMetrics {
    sched_switch_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
    sys_enter_open_total: Family<SchedSwitchLabels, Gauge<u64, AtomicU64>>,
}

impl CpuMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let sched_switch_total = Family::<SchedSwitchLabels, Gauge<u64, AtomicU64>>::default();
        let sys_enter_open_total = Family::<SchedSwitchLabels, Gauge<u64, AtomicU64>>::default();
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
        Self {
            sched_switch_total,
            sys_enter_open_total,
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
}

///
/// 放置cpu执行ebpf的map数据和我们的指标之间的转换的关系
///
pub struct CpuCollector {
    sched_switch: PerCpuArray<MapData, u64>,
    sys_enter_open: PerCpuArray<MapData, u64>,
    registry: Registry,
    cpu: CpuMetrics,
}

impl CpuCollector {
    pub fn new(
        sched_switch: PerCpuArray<MapData, u64>,
        sys_enter_open: PerCpuArray<MapData, u64>,
    ) -> Self {
        let mut registry = Registry::default();
        let cpu = CpuMetrics::new(&mut registry);
        Self {
            sched_switch: sched_switch,
            sys_enter_open: sys_enter_open,
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
        Ok(())
    }

    pub async fn metrics(&self) -> anyhow::Result<String> {
        self.collect().await?;
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry)?;
        Ok(buffer)
    }
}
