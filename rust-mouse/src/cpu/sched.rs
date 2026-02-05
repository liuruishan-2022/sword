use std::time::Duration;

use tracing::info;

use crate::common::cache;

pub async fn search() {
    let cache = cache::mock_cache(100000, Duration::from_hours(24), 100000).await;
    loop {
        let source = cache::generate_random_phone();
        cache.iter().for_each(|(phone, region)| {
            if source.starts_with(phone.as_str()) {
                info!("命中查找:{phone}");
            }
        });
    }
}
