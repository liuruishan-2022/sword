use tracing::info;
use tracing_subscriber::fmt;

pub mod common;
pub mod cpu;
pub mod io;

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
