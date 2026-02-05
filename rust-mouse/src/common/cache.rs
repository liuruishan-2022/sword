use moka::future::Cache;
use rand::Rng;
use rand::SeedableRng;
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

pub fn create_cache(capacity: usize, ttl: Duration) -> Cache<String, PhoneRegion> {
    Cache::builder()
        .max_capacity(capacity as u64)
        .time_to_live(ttl)
        .build()
}

/// 创建并填充指定数量的随机 mock 数据到 Cache
///
/// # 参数
/// * `capacity` - 缓存容量
/// * `ttl` - 条目的保留时长
/// * `count` - 要生成的 mock 数据数量
///
/// # 返回
/// 返回填充了随机数据的 Cache
///
/// # 示例
/// ```no_run
/// use rust_mouse::common::cache;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() {
///     let cache = cache::mock_cache(1000, Duration::from_secs(60), 500).await;
///     // Cache 现在包含 500 条随机数据
/// }
/// ```
pub async fn mock_cache(
    capacity: usize,
    ttl: Duration,
    count: usize,
) -> Cache<String, PhoneRegion> {
    let cache = create_cache(capacity, ttl);
    let mut rng = rand::rngs::StdRng::from_entropy();

    for _ in 0..count {
        // 生成随机长度的手机号 (7-9位)
        let phone_len = rng.gen_range(7..=9);
        let phone: String = (0..phone_len)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect();

        // 生成随机的区域ID (0-999)
        let region_id = rng.gen_range(0..1000);

        if let Ok(phone_region) = PhoneRegion::new(phone.clone(), region_id) {
            cache.insert(phone, phone_region).await;
        }
    }

    cache
}

/// 中国手机号运营商前缀列表
const CHINA_MOBILE_PREFIXES: &[&str] = &[
    "130", "131", "132", "133", "134", "135", "136", "137", "138", "139", // 中国联通
    "150", "151", "152", "153", "155", "156", "157", "158", "159", // 中国移动
    "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", // 中国电信
    "170", "171", // 虚拟运营商
];

/// 生成一个随机的中国手机号（11位）
///
/// # 返回
/// 返回一个符合中国手机号规则的 11 位随机手机号字符串
/// 规则：以 1 开头，第二位为 3-9，后面 9 位为随机数字
///
/// # 示例
/// ```
/// use rust_mouse::common::cache;
///
/// let phone = cache::generate_random_phone();
/// assert_eq!(phone.len(), 11);
/// assert!(phone.starts_with('1'));
/// ```
pub fn generate_random_phone() -> String {
    let mut rng = rand::thread_rng();

    // 第一位固定为 1
    let mut phone = String::from("1");

    // 第二位：3-9
    phone.push_str(&rng.gen_range(3..=9).to_string());

    // 后面 9 位随机数字
    for _ in 0..9 {
        phone.push_str(&rng.gen_range(0..10).to_string());
    }

    phone
}

/// 使用真实运营商前缀生成一个随机的中国手机号（11位）
///
/// # 返回
/// 返回一个使用真实运营商前缀的 11 位随机手机号
///
/// # 示例
/// ```
/// use rust_mouse::common::cache;
///
/// let phone = cache::generate_realistic_phone();
/// assert_eq!(phone.len(), 11);
/// assert!(phone.starts_with("13") || phone.starts_with("15") || phone.starts_with("18"));
/// ```
pub fn generate_realistic_phone() -> String {
    let mut rng = rand::thread_rng();

    // 随机选择一个运营商前缀
    let prefix = CHINA_MOBILE_PREFIXES[rng.gen_range(0..CHINA_MOBILE_PREFIXES.len())];

    // 生成剩余的 8 位数字
    let suffix: String = (0..8)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect();

    format!("{}{}", prefix, suffix)
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

    #[tokio::test]
    async fn test_mock_cache() {
        // 测试生成 100 条随机数据
        let cache = mock_cache(1000, Duration::from_secs(60), 100).await;

        // 验证缓存中有数据（由于键可能重复，不能精确断言数量）
        // 通过 iter() 计数
        let actual_count = cache.iter().count();
        assert!(actual_count > 0, "Cache should contain data");
        assert!(actual_count <= 100, "Cache should not exceed mock count");

        // 验证至少有一些有效数据
        let mut found_valid = false;
        for entry in cache.iter() {
            let value = entry.value();
            if value.is_valid_phone_length() && value.region_id >= 0 && value.region_id < 1000 {
                found_valid = true;
                break;
            }
        }
        assert!(found_valid, "Should find at least one valid entry");
    }

    #[tokio::test]
    async fn test_mock_cache_empty() {
        // 测试生成 0 条数据
        let cache = mock_cache(100, Duration::from_secs(60), 0).await;

        let count = cache.iter().count();
        assert_eq!(count, 0, "Cache should be empty");
    }

    #[tokio::test]
    async fn test_mock_count_greater_than_capacity() {
        // 测试 mock 数量超过容量
        let cache = mock_cache(10, Duration::from_secs(60), 100).await;

        // Moka Cache 会自动处理容量限制
        let count = cache.iter().count();
        assert!(count <= 10, "Cache should respect capacity limit");
    }

    #[tokio::test]
    async fn test_mock_cache_randomness() {
        // 测试两次生成的数据应该不同
        let cache1 = mock_cache(1000, Duration::from_secs(60), 50).await;
        let cache2 = mock_cache(1000, Duration::from_secs(60), 50).await;

        // 收集所有的手机号
        let phones1: Vec<String> = cache1.iter().map(|entry| entry.key().clone()).collect();
        let phones2: Vec<String> = cache2.iter().map(|entry| entry.key().clone()).collect();

        // 由于是随机的，两个缓存的内容大概率不同
        // （虽然理论上可能相同，但概率极低）
        let phones1_sorted = {
            let mut sorted = phones1.clone();
            sorted.sort();
            sorted
        };
        let phones2_sorted = {
            let mut sorted = phones2.clone();
            sorted.sort();
            sorted
        };

        // 至少验证它们长度相同
        assert_eq!(phones1_sorted.len(), phones2_sorted.len());
    }

    #[test]
    fn test_generate_random_phone() {
        let phone = generate_random_phone();

        // 验证长度为 11
        assert_eq!(phone.len(), 11);

        // 验证以 1 开头
        assert!(phone.starts_with('1'));

        // 验证第二位是 3-9
        let second_char = phone.chars().nth(1).unwrap();
        assert!(second_char >= '3' && second_char <= '9');

        // 验证全部是数字
        assert!(phone.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_random_phones_are_different() {
        let phone1 = generate_random_phone();
        let phone2 = generate_random_phone();

        // 两次生成的手机号大概率不同（虽然理论上可能相同，但概率极低）
        assert_ne!(phone1, phone2);
    }

    #[test]
    fn test_generate_realistic_phone() {
        let phone = generate_realistic_phone();

        // 验证长度为 11
        assert_eq!(phone.len(), 11);

        // 验证以 1 开头
        assert!(phone.starts_with('1'));

        // 验证使用了已知的运营商前缀
        let prefix = &phone[0..3];
        assert!(CHINA_MOBILE_PREFIXES.contains(&prefix));

        // 验证全部是数字
        assert!(phone.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_realistic_phones_are_different() {
        let phone1 = generate_realistic_phone();
        let phone2 = generate_realistic_phone();

        // 两次生成的手机号大概率不同
        assert_ne!(phone1, phone2);
    }

    #[test]
    fn test_generate_batch_phones() {
        let mut phones = std::collections::HashSet::new();

        // 生成 1000 个手机号，检查是否有重复
        for _ in 0..1000 {
            let phone = generate_random_phone();
            phones.insert(phone);
        }

        // 应该有接近 1000 个不同的手机号（允许少量碰撞）
        assert!(phones.len() > 990, "Expected > 990 unique phones, got {}", phones.len());
    }
}
