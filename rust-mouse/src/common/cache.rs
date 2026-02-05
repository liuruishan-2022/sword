use moka::future::Cache;
use std::time::Duration;

/// 手机号和区域ID的数据结构
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PhoneRegion {
    /// 手机号，长度为 7-9
    pub phone: String,
    /// 区域ID
    pub region_id: i32,
}

impl PhoneRegion {
    /// 创建新的 PhoneRegion
    pub fn new(phone: String, region_id: i32) -> Result<Self, String> {
        let phone_len = phone.len();
        if phone_len < 7 || phone_len > 9 {
            return Err(format!("phone length must be 7-9, got: {}", phone_len));
        }
        Ok(Self { phone, region_id })
    }

    /// 验证 phone 长度是否有效
    pub fn is_valid_phone_length(&self) -> bool {
        let len = self.phone.len();
        len >= 7 && len <= 9
    }
}

/// 创建一个 Moka 缓存
///
/// # 参数
/// * `capacity` - 缓存容量
/// * `ttl` - 条目的保留时长
///
/// # 返回
/// 返回 Cache 的所有权
///
/// # 示例
/// ```no_run
/// use rust_mouse::common::cache;
/// use std::time::Duration;
///
/// let cache = cache::create_cache(1000, Duration::from_secs(60));
/// ```
pub fn create_cache(capacity: usize, ttl: Duration) -> Cache<String, PhoneRegion> {
    Cache::builder()
        .max_capacity(capacity as u64)
        .time_to_live(ttl)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phone_region_creation_valid() {
        // 测试有效长度 7
        let pr1 = PhoneRegion::new("1234567".to_string(), 100);
        assert!(pr1.is_ok());
        assert_eq!(pr1.unwrap().phone.len(), 7);

        // 测试有效长度 8
        let pr2 = PhoneRegion::new("12345678".to_string(), 200);
        assert!(pr2.is_ok());

        // 测试有效长度 9
        let pr3 = PhoneRegion::new("123456789".to_string(), 300);
        assert!(pr3.is_ok());
    }

    #[test]
    fn test_phone_region_creation_invalid() {
        // 测试太短
        let pr1 = PhoneRegion::new("123456".to_string(), 100);
        assert!(pr1.is_err());

        // 测试太长
        let pr2 = PhoneRegion::new("1234567890".to_string(), 200);
        assert!(pr2.is_err());
    }

    #[test]
    fn test_is_valid_phone_length() {
        let pr = PhoneRegion::new("1234567".to_string(), 100).unwrap();
        assert!(pr.is_valid_phone_length());
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let cache = create_cache(10, Duration::from_secs(60));

        let phone_region = PhoneRegion::new("1234567".to_string(), 1).unwrap();

        // 插入数据
        cache.insert("key1".to_string(), phone_region.clone());

        // 获取数据
        let retrieved = cache.get(&"key1".to_string()).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().region_id, 1);

        // 测试不存在的键
        let not_found = cache.get(&"key999".to_string()).await;
        assert!(not_found.is_none());
    }
}
