use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Response, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
};
use aya::maps::{HashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf};
use log::{error, info, warn};
use sword_common::{SchedSwitchStateKey, SysEnterType, ThreadComm};
use tokio::io::unix::AsyncFd;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::metrics::cpu::CpuCollector;
use crate::metrics::network::{NetworkCollector, decode_slow_tcp_event, format_slow_tcp_event};

pub mod cpu;
pub mod network;

const SCHED_SWITCH_TOTAL_MAP: &str = "SCHED_SWITCH_TOTAL";
const THREAD_SWITCH_OUT_TOTAL_MAP: &str = "THREAD_SWITCH_OUT_TOTAL";
const THREAD_OFFCPU_TOTAL_NS_MAP: &str = "THREAD_OFFCPU_TOTAL_NS";
const THREAD_COMM_MAP: &str = "THREAD_COMM";
const RUNQUEUE_METRICS_MAP: &str = "RUNQUEUE_METRICS";
const SYS_ENTER_OPEN_COUNTER_MAP: &str = "SYS_ENTER_OPEN_COUNTER";
const SYS_ENTER_CONNECT: &str = "SYS_ENTER_CONNECT";
const SYS_ENTER_STATISTICS: &str = "SYS_ENTER_STATISTICS";
const RISK_TCP_COUNTERS_MAP: &str = "RISK_TCP_COUNTERS";
const SLOW_TCP_EVENTS_MAP: &str = "SLOW_TCP_EVENTS";

pub async fn spawn_prometheus_exporter(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .take_map(SCHED_SWITCH_TOTAL_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TOTAL_MAP} not found"))?;
    let sched_switch_total_map: PerCpuArray<MapData, u64> = PerCpuArray::try_from(map)?;

    let map = ebpf
        .take_map(SYS_ENTER_OPEN_COUNTER_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SYS_ENTER_OPEN_COUNTER_MAP} not found"))?;
    let sys_enter_open_counter_map: PerCpuArray<MapData, u64> = PerCpuArray::try_from(map)?;

    let map = ebpf
        .take_map(THREAD_SWITCH_OUT_TOTAL_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {THREAD_SWITCH_OUT_TOTAL_MAP} not found"))?;
    let thread_switch_out_total_map: HashMap<MapData, SchedSwitchStateKey, u64> =
        HashMap::try_from(map)?;

    let map = ebpf
        .take_map(THREAD_OFFCPU_TOTAL_NS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {THREAD_OFFCPU_TOTAL_NS_MAP} not found"))?;
    let thread_offcpu_total_ns_map: HashMap<MapData, SchedSwitchStateKey, u64> =
        HashMap::try_from(map)?;

    let map = ebpf
        .take_map(THREAD_COMM_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {THREAD_COMM_MAP} not found"))?;
    let thread_comm_map: HashMap<MapData, u32, ThreadComm> = HashMap::try_from(map)?;

    let map = ebpf
        .take_map(RUNQUEUE_METRICS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {RUNQUEUE_METRICS_MAP} not found"))?;
    let runqueue_metrics_map: PerCpuArray<MapData, u64> = PerCpuArray::try_from(map)?;

    let map = ebpf
        .take_map(SYS_ENTER_CONNECT)
        .ok_or_else(|| anyhow::anyhow!("map {SYS_ENTER_CONNECT} not found"))?;
    let sys_enter_connect_map: PerCpuHashMap<MapData, u32, u64> = PerCpuHashMap::try_from(map)?;

    let map = ebpf
        .take_map(SYS_ENTER_STATISTICS)
        .ok_or_else(|| anyhow::anyhow!("map {SYS_ENTER_STATISTICS} notfound"))?;
    let sys_enter_statistics_map: PerCpuHashMap<MapData, SysEnterType, u64> =
        PerCpuHashMap::try_from(map)?;

    let map = ebpf
        .take_map(RISK_TCP_COUNTERS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {RISK_TCP_COUNTERS_MAP} not found"))?;
    let risk_tcp_counters_map: PerCpuArray<MapData, u64> = PerCpuArray::try_from(map)?;

    let map = ebpf
        .take_map(SLOW_TCP_EVENTS_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SLOW_TCP_EVENTS_MAP} not found"))?;
    let slow_tcp_events = RingBuf::try_from(map)?;
    spawn_slow_tcp_event_reader(slow_tcp_events)?;

    let cpu_state = CpuCollector::new(
        sched_switch_total_map,
        sys_enter_open_counter_map,
        thread_switch_out_total_map,
        thread_offcpu_total_ns_map,
        thread_comm_map,
        runqueue_metrics_map,
    );
    let network_state = NetworkCollector::new(
        sys_enter_connect_map,
        sys_enter_statistics_map,
        risk_tcp_counters_map,
    );
    let exporter_state = Arc::new(Mutex::new(MetricsState {
        cpu: cpu_state,
        network: network_state,
    }));

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(exporter_state);
    let listener = TcpListener::bind("0.0.0.0:9898").await?;

    tokio::spawn(async move {
        info!("prometheus metrics listening on http://0.0.0.0:9898/metrics");
        if let Err(err) = axum::serve(listener, app).await {
            error!("prometheus metrics server stopped: {err}");
        }
    });

    Ok(())
}

fn spawn_slow_tcp_event_reader(ring_buf: RingBuf<MapData>) -> anyhow::Result<()> {
    let mut ring_buf = AsyncFd::new(ring_buf)?;
    tokio::spawn(async move {
        loop {
            let mut guard = match ring_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(err) => {
                    error!("slow TCP event reader stopped: {err}");
                    return;
                }
            };
            while let Some(item) = guard.get_inner_mut().next() {
                match decode_slow_tcp_event(&item) {
                    Some(event) => warn!("{}", format_slow_tcp_event(&event)),
                    None => warn!("discarded malformed slow TCP event size={}", item.len()),
                }
            }
            guard.clear_ready();
        }
    });
    Ok(())
}

async fn health_handler() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("ok"))
        .unwrap()
}

async fn metrics_handler(
    State(metrics_state): State<Arc<Mutex<MetricsState>>>,
) -> impl IntoResponse {
    match metrics_state.lock().await.metrics().await {
        Ok(metrics) => Response::builder()
            .header(
                CONTENT_TYPE,
                "application/openmetrics-text;version=1.0.0; charset=utf-8",
            )
            .body(Body::from(metrics))
            .unwrap(),
        Err(err) => {
            error!("failed to collect metrics: {err}");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to collect metrics"))
                .unwrap()
        }
    }
}

struct MetricsState {
    cpu: CpuCollector,
    network: NetworkCollector,
}

impl MetricsState {
    async fn metrics(&mut self) -> anyhow::Result<String> {
        let mut metrics = trim_openmetrics_eof(self.cpu.metrics().await?);
        metrics.push_str(&trim_openmetrics_eof(self.network.metrics().await?));
        metrics.push_str("# EOF\n");
        Ok(metrics)
    }
}

fn trim_openmetrics_eof(mut metrics: String) -> String {
    const EOF_MARKER: &str = "# EOF\n";
    if metrics.ends_with(EOF_MARKER) {
        metrics.truncate(metrics.len() - EOF_MARKER.len());
    }
    metrics
}
