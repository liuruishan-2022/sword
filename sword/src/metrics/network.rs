use std::{mem::size_of, net::Ipv4Addr, ptr, sync::atomic::AtomicU64};

use aya::maps::{MapData, MapError, PerCpuArray, PerCpuHashMap};
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sword_common::{
    SLOW_TCP_PHASE_ARRIVAL_TO_READ, SLOW_TCP_PHASE_ARRIVAL_TO_WRITE, SlowTcpEvent, SysEnterType,
};

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
    target_tcp_read_total: Gauge<u64, AtomicU64>,
    target_tcp_write_total: Gauge<u64, AtomicU64>,
    target_tcp_read_to_write_slow_total: Gauge<u64, AtomicU64>,
    target_event_dropped_total: Gauge<u64, AtomicU64>,
    target_tcp_payload_arrival_total: Gauge<u64, AtomicU64>,
    target_tcp_arrival_to_read_total: Gauge<u64, AtomicU64>,
    target_tcp_arrival_to_read_slow_total: Gauge<u64, AtomicU64>,
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
        let target_tcp_read_total = Gauge::default();
        registry.register(
            "sword_target_tcp_read_total",
            "Total successful TCP reads by the target server port",
            target_tcp_read_total.clone(),
        );
        let target_tcp_write_total = Gauge::default();
        registry.register(
            "sword_target_tcp_write_total",
            "Total TCP writes by the target server port",
            target_tcp_write_total.clone(),
        );
        let target_tcp_read_to_write_slow_total = Gauge::default();
        registry.register(
            "sword_target_tcp_read_to_write_slow_total",
            "Total target TCP requests whose first read to first write latency exceeded the threshold",
            target_tcp_read_to_write_slow_total.clone(),
        );
        let target_event_dropped_total = Gauge::default();
        registry.register(
            "sword_target_event_dropped_total",
            "Total slow TCP events dropped because the event buffer was full",
            target_event_dropped_total.clone(),
        );
        let target_tcp_payload_arrival_total = Gauge::default();
        registry.register(
            "sword_target_tcp_payload_arrival_total",
            "Total TCP payload arrivals for the target server port",
            target_tcp_payload_arrival_total.clone(),
        );
        let target_tcp_arrival_to_read_total = Gauge::default();
        registry.register(
            "sword_target_tcp_arrival_to_read_total",
            "Total target TCP payload arrivals correlated with a successful application read",
            target_tcp_arrival_to_read_total.clone(),
        );
        let target_tcp_arrival_to_read_slow_total = Gauge::default();
        registry.register(
            "sword_target_tcp_arrival_to_read_slow_total",
            "Total target TCP payload arrival to application read latencies that exceeded the threshold",
            target_tcp_arrival_to_read_slow_total.clone(),
        );
        Self {
            pid_tcp_total,
            sys_enter_statistics,
            target_tcp_retransmit_total,
            target_tcp_receive_reset_total,
            target_tcp_send_reset_total,
            target_tcp_read_total,
            target_tcp_write_total,
            target_tcp_read_to_write_slow_total,
            target_event_dropped_total,
            target_tcp_payload_arrival_total,
            target_tcp_arrival_to_read_total,
            target_tcp_arrival_to_read_slow_total,
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

    fn set_target_tcp_events(
        &self,
        retransmits: u64,
        receive_resets: u64,
        send_resets: u64,
        reads: u64,
        writes: u64,
        slow_requests: u64,
        dropped_events: u64,
        payload_arrivals: u64,
        arrival_to_reads: u64,
        slow_arrival_to_reads: u64,
    ) {
        self.target_tcp_retransmit_total.set(retransmits);
        self.target_tcp_receive_reset_total.set(receive_resets);
        self.target_tcp_send_reset_total.set(send_resets);
        self.target_tcp_read_total.set(reads);
        self.target_tcp_write_total.set(writes);
        self.target_tcp_read_to_write_slow_total.set(slow_requests);
        self.target_event_dropped_total.set(dropped_events);
        self.target_tcp_payload_arrival_total.set(payload_arrivals);
        self.target_tcp_arrival_to_read_total.set(arrival_to_reads);
        self.target_tcp_arrival_to_read_slow_total
            .set(slow_arrival_to_reads);
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
            self.per_cpu_counter(3)?,
            self.per_cpu_counter(4)?,
            self.per_cpu_counter(5)?,
            self.per_cpu_counter(6)?,
            self.per_cpu_counter(7)?,
            self.per_cpu_counter(8)?,
            self.per_cpu_counter(9)?,
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

pub(crate) fn decode_slow_tcp_event(bytes: &[u8]) -> Option<SlowTcpEvent> {
    if bytes.len() != size_of::<SlowTcpEvent>() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<SlowTcpEvent>()) })
}

pub(crate) fn format_slow_tcp_event(event: &SlowTcpEvent) -> String {
    if event.phase == SLOW_TCP_PHASE_ARRIVAL_TO_WRITE {
        let request_id = std::str::from_utf8(event.request_id.as_bytes()).unwrap_or("<invalid>");
        return format!(
            "target http slow requestId={request_id} arrival_to_read_ms={:.3} read_to_write_ms={:.3} arrival_to_write_ms={:.3} pid={} tid={} src={}:{} dst={}:{} family={}",
            event.arrival_to_read_ns as f64 / 1_000_000.0,
            event.read_to_write_ns as f64 / 1_000_000.0,
            event.latency_ns as f64 / 1_000_000.0,
            event.tgid,
            event.tid,
            Ipv4Addr::from(event.source_addr_v4),
            event.source_port,
            Ipv4Addr::from(event.destination_addr_v4),
            event.destination_port,
            event.family
        );
    }
    let phase = if event.phase == SLOW_TCP_PHASE_ARRIVAL_TO_READ {
        "arrival-to-read"
    } else {
        "read-to-write"
    };
    format!(
        "target tcp {phase} slow latency_ms={:.3} pid={} tid={} src={}:{} dst={}:{} family={}",
        event.latency_ns as f64 / 1_000_000.0,
        event.tgid,
        event.tid,
        Ipv4Addr::from(event.source_addr_v4),
        event.source_port,
        Ipv4Addr::from(event.destination_addr_v4),
        event.destination_port,
        event.family
    )
}

#[cfg(test)]
mod tests {
    use prometheus_client::{encoding::text::encode, registry::Registry};

    use std::{mem::size_of, slice};

    use sword_common::{
        HttpRequestIdState, SLOW_TCP_PHASE_ARRIVAL_TO_READ, SLOW_TCP_PHASE_ARRIVAL_TO_WRITE,
        SLOW_TCP_PHASE_READ_TO_WRITE, SlowTcpEvent,
    };

    use super::{NetworkMetrics, decode_slow_tcp_event, format_slow_tcp_event};

    #[test]
    fn exports_target_tcp_transport_metrics() {
        let mut registry = Registry::default();
        let metrics = NetworkMetrics::new(&mut registry);
        metrics.set_target_tcp_events(7, 6, 5, 4, 3, 2, 1, 8, 9, 10);

        let mut output = String::new();
        encode(&mut output, &registry).unwrap();

        assert!(output.contains("sword_target_tcp_retransmit_total 7"));
        assert!(output.contains("sword_target_tcp_receive_reset_total 6"));
        assert!(output.contains("sword_target_tcp_send_reset_total 5"));
        assert!(output.contains("sword_target_tcp_read_total 4"));
        assert!(output.contains("sword_target_tcp_write_total 3"));
        assert!(output.contains("sword_target_tcp_read_to_write_slow_total 2"));
        assert!(output.contains("sword_target_event_dropped_total 1"));
        assert!(output.contains("sword_target_tcp_payload_arrival_total 8"));
        assert!(output.contains("sword_target_tcp_arrival_to_read_total 9"));
        assert!(output.contains("sword_target_tcp_arrival_to_read_slow_total 10"));
    }

    #[test]
    fn decodes_and_formats_slow_tcp_metadata_without_payload() {
        let event = SlowTcpEvent {
            timestamp_ns: 1,
            latency_ns: 123_000_000,
            arrival_to_read_ns: 0,
            read_to_write_ns: 0,
            tgid: 42,
            tid: 43,
            source_addr_v4: u32::from_be_bytes([172, 16, 15, 139]),
            destination_addr_v4: u32::from_be_bytes([172, 16, 1, 30]),
            source_port: 8080,
            destination_port: 54321,
            family: 2,
            phase: SLOW_TCP_PHASE_READ_TO_WRITE,
            _pad: 0,
            request_id: Default::default(),
        };
        let bytes = unsafe {
            slice::from_raw_parts(
                (&event as *const SlowTcpEvent).cast::<u8>(),
                size_of::<SlowTcpEvent>(),
            )
        };

        let decoded = decode_slow_tcp_event(bytes).unwrap();
        assert_eq!(decoded, event);
        assert!(decode_slow_tcp_event(&bytes[..bytes.len() - 1]).is_none());
        let line = format_slow_tcp_event(&decoded);
        assert!(line.contains("latency_ms=123.000"));
        assert!(line.contains("pid=42 tid=43"));
        assert!(line.contains("src=172.16.15.139:8080"));
        assert!(!line.contains("content"));
    }

    #[test]
    fn formats_arrival_to_read_slow_phase() {
        let event = SlowTcpEvent {
            timestamp_ns: 1,
            latency_ns: 456_000_000,
            arrival_to_read_ns: 0,
            read_to_write_ns: 0,
            tgid: 42,
            tid: 43,
            source_addr_v4: u32::from_be_bytes([172, 16, 15, 139]),
            destination_addr_v4: u32::from_be_bytes([172, 16, 1, 30]),
            source_port: 8080,
            destination_port: 54321,
            family: 2,
            phase: SLOW_TCP_PHASE_ARRIVAL_TO_READ,
            _pad: 0,
            request_id: Default::default(),
        };

        let line = format_slow_tcp_event(&event);

        assert!(line.contains("target tcp arrival-to-read slow"));
        assert!(line.contains("latency_ms=456.000"));
    }

    #[test]
    fn formats_slow_http_request_with_request_id_and_phase_latencies() {
        let mut request_id = HttpRequestIdState::default();
        request_id.consume(br#"{"requestId":"7fbb215d-a5d1-4478-b134-fad7a388dea3","items":[]}"#);
        let event = SlowTcpEvent {
            timestamp_ns: 1,
            latency_ns: 650_000_000,
            arrival_to_read_ns: 50_000_000,
            read_to_write_ns: 600_000_000,
            tgid: 42,
            tid: 43,
            source_addr_v4: u32::from_be_bytes([172, 16, 15, 139]),
            destination_addr_v4: u32::from_be_bytes([172, 16, 1, 30]),
            source_port: 8080,
            destination_port: 54321,
            family: 2,
            phase: SLOW_TCP_PHASE_ARRIVAL_TO_WRITE,
            _pad: 0,
            request_id: request_id.request_id(),
        };

        let line = format_slow_tcp_event(&event);

        assert!(line.contains("target http slow"));
        assert!(line.contains("requestId=7fbb215d-a5d1-4478-b134-fad7a388dea3"));
        assert!(line.contains("arrival_to_read_ms=50.000"));
        assert!(line.contains("read_to_write_ms=600.000"));
        assert!(line.contains("arrival_to_write_ms=650.000"));
    }
}
