use tracing::info;
use walkdir::WalkDir;

///
/// 我们这次模拟那种io层次的跟踪需求
///

///
/// 对传入的path做递归读取下面每个文件的行数
/// 我们可能会读取linux操作系统源码的统计
pub(crate) fn line_count(path: &str) {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .for_each(|entry| {
            info!("具体的地址:{}", entry.path().display());
        });
}
