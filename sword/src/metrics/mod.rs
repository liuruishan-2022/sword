use std::{env, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Response, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::get,
};
use aya::maps::{MapData, PerCpuArray};
use log::{error, info};
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9898";
const METRICS_ADDR_ENV: &str = "SWORD_METRICS_ADDR";
const SCHED_SWITCH_TOTAL_MAP: &str = "SCHED_SWITCH_TOTAL";

pub async fn spawn_prometheus_exporter(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let map = ebpf
        .take_map(SCHED_SWITCH_TOTAL_MAP)
        .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TOTAL_MAP} not found"))?;
    let sched_switch_total_map: PerCpuArray<_, u64> = PerCpuArray::try_from(map)?;
    let addr: SocketAddr = env::var(METRICS_ADDR_ENV)
        .unwrap_or_else(|_| DEFAULT_METRICS_ADDR.to_owned())
        .parse()?;

    let state = Arc::new(MetricsState::new(sched_switch_total_map));
    let app = Router::new()
        .route("/api/v1/version", get(version))
        .route("/metrics", get(metrics_handler))
        .with_state(state);
    let listener = TcpListener::bind(addr).await?;

    tokio::spawn(async move {
        info!("prometheus metrics listening on http://{addr}/metrics");
        if let Err(err) = axum::serve(listener, app).await {
            error!("prometheus metrics server stopped: {err}");
        }
    });

    Ok(())
}

struct MetricsState {
    registry: Mutex<Registry>,
    metrics: SwordMetrics,
    last_sched_switch_per_cpu: Mutex<Vec<u64>>,
    sched_switch_total_map: Mutex<PerCpuArray<MapData, u64>>,
}

impl MetricsState {
    fn new(sched_switch_total_map: PerCpuArray<MapData, u64>) -> Self {
        let mut registry = Registry::default();
        let metrics = SwordMetrics::new();
        registry.register(
            "sword_sched_switch",
            "Total sched:sched_switch events observed.",
            metrics.sched_switch_total.clone(),
        );

        Self {
            registry: Mutex::new(registry),
            metrics,
            last_sched_switch_per_cpu: Mutex::new(Vec::new()),
            sched_switch_total_map: Mutex::new(sched_switch_total_map),
        }
    }

    async fn render(&self) -> anyhow::Result<String> {
        self.refresh_sched_switch_total().await?;

        let mut body = String::new();
        let registry = self.registry.lock().await;
        encode(&mut body, &registry)?;
        Ok(body)
    }

    async fn refresh_sched_switch_total(&self) -> anyhow::Result<()> {
        let current = self.read_sched_switch_per_cpu().await?;
        let mut previous = self.last_sched_switch_per_cpu.lock().await;
        if previous.len() < current.len() {
            previous.resize(current.len(), 0);
        }

        for (cpu, current_value) in current.iter().enumerate() {
            let previous_value = previous[cpu];
            let delta = if *current_value >= previous_value {
                *current_value - previous_value
            } else {
                *current_value
            };

            if delta > 0 {
                self.metrics
                    .inc_sched_switch_total(&SchedSwitchLabels { cpu: cpu as u32 }, delta);
            }
            previous[cpu] = *current_value;
        }

        Ok(())
    }

    async fn read_sched_switch_per_cpu(&self) -> anyhow::Result<Vec<u64>> {
        let map = self.sched_switch_total_map.lock().await;
        let per_cpu = map.get(&0, 0)?;

        Ok(per_cpu.iter().copied().collect())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SchedSwitchLabels {
    cpu: u32,
}

pub struct SwordMetrics {
    sched_switch_total: Family<SchedSwitchLabels, Counter>,
}

impl SwordMetrics {
    pub fn new() -> Self {
        Self {
            sched_switch_total: Family::<SchedSwitchLabels, Counter>::default(),
        }
    }

    pub fn inc_sched_switch_total(&self, labels: &SchedSwitchLabels, value: u64) {
        self.sched_switch_total.get_or_create(labels).inc_by(value);
    }
}

async fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

async fn metrics_handler(State(state): State<Arc<MetricsState>>) -> Response<Body> {
    match state.render().await {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(
                CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            .body(Body::from(body))
            .unwrap(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("failed to render metrics: {err}\n"),
        )
            .into_response(),
    }
}
