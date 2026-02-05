use tracing::info;
use tracing_subscriber::fmt;

pub mod common;
pub mod cpu;

#[tokio::main]
async fn main() {
    fmt().init();
    info!("start rust mouse...");

    cpu::sched_search().await;
    info!("search task started in background");
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C handler");

    info!("Shutting down...");
}
