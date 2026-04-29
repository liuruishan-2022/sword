use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Response, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
};
use aya::maps::PerCpuArray;
use log::{error, info};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::metrics::cpu::CpuCollector;

pub mod cpu;

const SCHED_SWITCH_TOTAL_MAP: &str = "SCHED_SWITCH_TOTAL";
const SYS_ENTER_OPEN_COUNTER_MAP: &str = "SYS_ENTER_OPEN_COUNTER";

pub async fn spawn_prometheus_exporter(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .take_map(SCHED_SWITCH_TOTAL_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TOTAL_MAP} not found"))?;
    let sched_switch_total_map: PerCpuArray<_, u64> = PerCpuArray::try_from(map)?;

    let cpu_state = CpuCollector::new(sched_switch_total_map);
    let cpu_state = Arc::new(Mutex::new(cpu_state));

    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(cpu_state);
    let listener = TcpListener::bind("0.0.0.0:9898").await?;

    tokio::spawn(async move {
        info!("prometheus metrics listening on http://0.0.0.0:9898/metrics");
        if let Err(err) = axum::serve(listener, app).await {
            error!("prometheus metrics server stopped: {err}");
        }
    });

    Ok(())
}

async fn metrics_handler(
    State(cpu_collector): State<Arc<Mutex<CpuCollector>>>,
) -> impl IntoResponse {
    match cpu_collector.lock().await.metrics().await {
        Ok(metrics) => Response::builder()
            .header(
                CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
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
