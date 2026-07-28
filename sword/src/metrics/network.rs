use std::sync::atomic::AtomicU64;

use aya::maps::{MapData, MapError, PerCpuArray, PerCpuHashMap};
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sword_common::SysEnterType;

///
/// 放置network相關的指標獲取
///
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TcpLabels {
    pid: u32,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SysEnterLabels {
    pid: u32,
    enter_type: u32,
}

pub struct NetworkMetrics {
    pid_tcp_total: Family<TcpLabels, Gauge<u64, AtomicU64>>,
    sys_enter_statistics: Family<SysEnterLabels, Gauge<u64, AtomicU64>>,
    target_tcp_retransmit_total: Gauge<u64, AtomicU64>,
    target_tcp_receive_reset_total: Gauge<u64, AtomicU64>,
    target_tcp_send_reset_total: Gauge<u64, AtomicU64>,
}

impl NetworkMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let pid_tcp_total = Family::default();
        registry.register(
            "network_tcp_pid_total",
            "網絡層面的進程級別的TCP統計信息",
            pid_tcp_total.clone(),
        );

        let sys_enter_statistics = Family::default();
        registry.register(
            "sys_enter_statistics",
            "所有sys_enter开头的统计",
            sys_enter_statistics.clone(),
        );
        let target_tcp_retransmit_total = Gauge::default();
        registry.register(
            "sword_target_tcp_retransmit_total",
            "Total TCP retransmits for the target server port",
            target_tcp_retransmit_total.clone(),
        );
        let target_tcp_receive_reset_total = Gauge::default();
        registry.register(
            "sword_target_tcp_receive_reset_total",
            "Total TCP resets received by the target server port",
            target_tcp_receive_reset_total.clone(),
        );
        let target_tcp_send_reset_total = Gauge::default();
        registry.register(
            "sword_target_tcp_send_reset_total",
            "Total TCP resets sent by the target server port",
            target_tcp_send_reset_total.clone(),
        );
        Self {
            pid_tcp_total,
            sys_enter_statistics,
            target_tcp_retransmit_total,
            target_tcp_receive_reset_total,
            target_tcp_send_reset_total,
        }
    }

    pub fn pid_tcp_total(&self, pid: u32, count: u64) {
        self.pid_tcp_total
            .get_or_create(&TcpLabels { pid })
            .set(count);
    }

    pub fn inc_sys_enter_statistics(&self, pid: u32, enter_type: u32, count: u64) {
        self.sys_enter_statistics
            .get_or_create(&SysEnterLabels {
                pid: pid,
                enter_type: enter_type,
            })
            .set(count);
    }

    pub fn remove_pid_tcp_total(&self, pid: u32) {
        self.pid_tcp_total.remove(&TcpLabels { pid });
    }

    fn set_target_tcp_events(&self, retransmits: u64, receive_resets: u64, send_resets: u64) {
        self.target_tcp_retransmit_total.set(retransmits);
        self.target_tcp_receive_reset_total.set(receive_resets);
        self.target_tcp_send_reset_total.set(send_resets);
    }
}

pub struct NetworkCollector {
    sys_enter_connect: PerCpuHashMap<MapData, u32, u64>,
    sys_enter_statistics: PerCpuHashMap<MapData, SysEnterType, u64>,
    risk_tcp_counters: PerCpuArray<MapData, u64>,
    registry: Registry,
    network: NetworkMetrics,
}

impl NetworkCollector {
    pub fn new(
        sys_enter_connect: PerCpuHashMap<MapData, u32, u64>,
        sys_enter_statistics: PerCpuHashMap<MapData, SysEnterType, u64>,
        risk_tcp_counters: PerCpuArray<MapData, u64>,
    ) -> Self {
        let mut registry = Registry::default();
        let network = NetworkMetrics::new(&mut registry);
        Self {
            sys_enter_connect,
            sys_enter_statistics,
            risk_tcp_counters,
            registry,
            network,
        }
    }

    pub async fn collect(&mut self) -> Result<(), MapError> {
        self.collect_sys_enter_connect()?;
        self.collect_sys_enter_statistics()?;
        self.network.set_target_tcp_events(
            self.per_cpu_counter(0)?,
            self.per_cpu_counter(1)?,
            self.per_cpu_counter(2)?,
        );
        Ok(())
    }

    fn collect_sys_enter_connect(&mut self) -> Result<(), MapError> {
        let mut stale_pids = Vec::new();

        for item in self.sys_enter_connect.iter() {
            let (pid, counts) = item?;
            if !pid_exists(pid) {
                stale_pids.push(pid);
                continue;
            }

            let total = counts.iter().copied().sum();
            self.network.pid_tcp_total(pid, total);
        }

        for pid in stale_pids {
            self.sys_enter_connect.remove(&pid)?;
            self.network.remove_pid_tcp_total(pid);
        }

        Ok(())
    }

    fn collect_sys_enter_statistics(&self) -> Result<(), MapError> {
        for item in self.sys_enter_statistics.iter() {
            let (enter, count) = item?;

            let total = count.iter().copied().sum();
            self.network
                .inc_sys_enter_statistics(enter.pid, enter.enter_type, total);
        }

        Ok(())
    }

    fn per_cpu_counter(&self, index: u32) -> Result<u64, MapError> {
        Ok(self.risk_tcp_counters.get(&index, 0)?.iter().copied().sum())
    }

    pub async fn metrics(&mut self) -> anyhow::Result<String> {
        self.collect().await?;
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry)?;
        Ok(buffer)
    }
}

fn pid_exists(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(test)]
mod tests {
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::NetworkMetrics;

    #[test]
    fn exports_target_tcp_transport_metrics() {
        let mut registry = Registry::default();
        let metrics = NetworkMetrics::new(&mut registry);
        metrics.set_target_tcp_events(3, 2, 1);

        let mut output = String::new();
        encode(&mut output, &registry).unwrap();

        assert!(output.contains("sword_target_tcp_retransmit_total 3"));
        assert!(output.contains("sword_target_tcp_receive_reset_total 2"));
        assert!(output.contains("sword_target_tcp_send_reset_total 1"));
    }
}
