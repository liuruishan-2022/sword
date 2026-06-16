use std::sync::atomic::AtomicU64;

use aya::maps::{MapData, MapError, PerCpuHashMap};
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

///
/// 放置network相關的指標獲取
///
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TcpLabels {
    pid: u32,
}

pub struct NetworkMetrics {
    pid_tcp_total: Family<TcpLabels, Gauge<u64, AtomicU64>>,
}

impl NetworkMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let pid_tcp_total = Family::default();
        registry.register(
            "network_tcp_pid_total",
            "網絡層面的進程級別的TCP統計信息",
            pid_tcp_total.clone(),
        );
        Self {
            pid_tcp_total: pid_tcp_total,
        }
    }

    pub fn pid_tcp_total(&self, pid: u32, count: u64) {
        self.pid_tcp_total
            .get_or_create(&TcpLabels { pid })
            .set(count);
    }

    pub fn remove_pid_tcp_total(&self, pid: u32) {
        self.pid_tcp_total.remove(&TcpLabels { pid });
    }
}

pub struct NetworkCollector {
    sys_enter_connect: PerCpuHashMap<MapData, u32, u64>,
    registry: Registry,
    network: NetworkMetrics,
}

impl NetworkCollector {
    pub fn new(sys_enter_connect: PerCpuHashMap<MapData, u32, u64>) -> Self {
        let mut registry = Registry::default();
        let network = NetworkMetrics::new(&mut registry);
        Self {
            sys_enter_connect,
            registry,
            network,
        }
    }

    pub async fn collect(&mut self) -> Result<(), MapError> {
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
