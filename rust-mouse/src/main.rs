use tracing_subscriber::fmt;

pub mod cpu;

#[tokio::main]
async fn main() {
    fmt().init();
    tracing::info!("start rust mouse...");
}
