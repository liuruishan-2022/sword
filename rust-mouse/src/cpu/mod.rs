///
/// CPU 相关的性能模拟模块
///
pub mod sched;

pub async fn sched_search() {
    sched::search().await;
}
