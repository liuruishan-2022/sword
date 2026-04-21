///
/// CPU 相关的性能模拟模块
///
pub mod sched;

pub async fn sched_search() {
    // 在 tokio 异步任务中执行第一个 search
    tokio::spawn(async move {
        sched::search().await;
    });

    // 在主线程中执行第二个 search（会阻塞在这里）
    sched::search().await;
}

pub fn sched_switch(workers: Option<usize>, pin_cpu: Option<usize>) {
    let mut config = sched::SchedSwitchConfig::default();
    if let Some(workers) = workers {
        config.workers = workers;
    }
    config.pin_cpu = pin_cpu;
    sched::start_sched_switch_simulator(config);
}
