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

    //1. cpu相关的探索
    //cpu::sched_search().await;
    //2. 文件系统相关的探索
    io::io_file();
    info!("search task started in background");
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");

    info!("Shutting down...");
}
