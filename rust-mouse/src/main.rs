use tracing::info;
use tracing_subscriber::fmt;

pub mod common;
pub mod cpu;
pub mod io;
pub mod net;

#[tokio::main]
async fn main() {
    fmt()
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_line_number(true)
        .init();
    info!("start rust mouse...");

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("sched-search") => {
            info!("starting sched_search load");
            cpu::sched_search().await;
        }
        Some("sched-switch") => {
            let workers = args.get(2).and_then(|value| value.parse::<usize>().ok());
            let pin_cpu = args.get(3).and_then(|value| value.parse::<usize>().ok());
            info!(workers = ?workers, pin_cpu = ?pin_cpu, "starting sched_switch load");
            cpu::sched_switch(workers, pin_cpu);
        }
        Some("net-request") => {
            let mut config = net::RequestConfig::default();
            if let Some(url) = args.get(2) {
                config.urls = url
                    .split(',')
                    .map(str::trim)
                    .filter(|url| !url.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            if let Some(workers) = args.get(3).and_then(|value| value.parse::<usize>().ok()) {
                config.workers = workers;
            }
            if let Some(interval_ms) = args.get(4).and_then(|value| value.parse::<u64>().ok()) {
                config.interval = std::time::Duration::from_millis(interval_ms);
            }
            if let Some(timeout_ms) = args.get(5).and_then(|value| value.parse::<u64>().ok()) {
                config.timeout = std::time::Duration::from_millis(timeout_ms);
            }
            info!(?config, "starting net_request load");
            net::start_request_load(config);
        }
        _ => {
            //1. cpu相关的探索
            //cpu::sched_search().await;
            //2. 文件系统相关的探索
            io::io_file();
            info!("search task started in background");
        }
    }
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");

    info!("Shutting down...");
}
