use std::{
    thread,
    time::{Duration, Instant},
};

use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub urls: Vec<String>,
    pub workers: usize,
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            urls: vec![
                "https://www.baidu.com/".to_string(),
                "https://www.json.cn/".to_string(),
            ],
            workers: 1,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(5),
        }
    }
}

pub fn start_request_load(config: RequestConfig) {
    let workers = config.workers.max(1);
    info!(
        urls = ?config.urls,
        workers,
        interval_ms = config.interval.as_millis(),
        timeout_ms = config.timeout.as_millis(),
        "starting blocking http request load"
    );

    for worker_id in 0..workers {
        let worker_config = config.clone();
        let thread_name = format!("net-mouse-{worker_id}");
        thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || run_request_worker(worker_id, worker_config))
            .unwrap_or_else(|err| panic!("failed to spawn {thread_name}: {err}"));
    }
}

fn run_request_worker(worker_id: usize, config: RequestConfig) {
    let client = match reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            error!(worker_id, error = %err, "failed to build http client");
            return;
        }
    };

    loop {
        for url in &config.urls {
            let started = Instant::now();
            match client.get(url).send() {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = started.elapsed();
                    info!(
                        worker_id,
                        url,
                        status,
                        elapsed_ms = elapsed.as_millis(),
                        "http request completed"
                    );
                }
                Err(err) => {
                    let elapsed = started.elapsed();
                    warn!(
                        worker_id,
                        url,
                        elapsed_ms = elapsed.as_millis(),
                        error = %err,
                        error_debug = ?err,
                        "http request failed"
                    );
                }
            }
        }

        if !config.interval.is_zero() {
            thread::sleep(config.interval);
        }
    }
}
