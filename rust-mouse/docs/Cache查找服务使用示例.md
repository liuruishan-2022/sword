# Cache 查找服务使用示例

本文档介绍如何使用 `rust-mouse/src/cpu/sched.rs` 中提供的 Cache 查找功能。

## 功能概述

该模块提供了一套完整的缓存查找服务：

1. **初始化缓存**：创建 10 万条测试数据，保留时长 24 小时
2. **前缀查找**：根据前缀字符串（如 "phone"）查找匹配的手机号
3. **持续查找**：死循环执行查找，可设置间隔时间

## 数据结构

### PhoneRegion
```rust
pub struct PhoneRegion {
    pub phone: String,      // 手机号，长度 7-9
    pub region_id: i32,     // 区域ID
}
```

### LookupResult
```rust
pub struct LookupResult {
    pub phone: String,       // 命中的手机号
    pub region_id: i32,      // 区域ID
    pub cache_key: String,   // 缓存键
}
```

## 核心函数

### 1. initialize_phone_cache
初始化一个包含指定数量数据的 Cache。

```rust
pub async fn initialize_phone_cache(
    data_count: usize,      // 数据量，例如：100_000
    ttl_hours: u64,         // 保留时长（小时），例如：24
) -> Cache<String, PhoneRegion>
```

### 2. lookup_by_prefix
根据前缀查找数据。

```rust
pub async fn lookup_by_prefix(
    cache: &Cache<String, PhoneRegion>,
    source: &str,           // 查找的前缀，例如："phone"
) -> Vec<LookupResult>
```

### 3. continuous_lookup
死循环持续查找。

```rust
pub async fn continuous_lookup(
    cache: &Cache<String, PhoneRegion>,
    source: &str,           // 查找的前缀
    interval_ms: u64,       // 每次查找间隔（毫秒）
)
```

### 4. start_phone_lookup_service
一站式启动服务（推荐使用）。

```rust
pub async fn start_phone_lookup_service(
    source: &str,           // 查找的前缀
    data_count: usize,      // 数据量
    ttl_hours: u64,         // 保留时长（小时）
    interval_ms: u64,       // 查找间隔（毫秒）
)
```

## 使用示例

### 示例 1：基本查找

```rust
use rust_mouse::cpu::sched;

#[tokio::main]
async fn main() {
    // 1. 初始化缓存（10 万条数据，24 小时保留）
    let cache = sched::initialize_phone_cache(100_000, 24).await;

    // 2. 查找所有以 "phone_00001" 开头的数据
    let results = sched::lookup_by_prefix(&cache, "phone_00001").await;

    println!("找到 {} 条匹配记录", results.len());
    for result in results {
        println!("  手机号: {}, 区域ID: {}", result.phone, result.region_id);
    }
}
```

### 示例 2：持续查找服务

```rust
use rust_mouse::cpu::sched;

#[tokio::main]
async fn main() {
    // 启动持续查找服务
    // 查找所有以 "phone" 开头的数据
    // 每 100ms 查找一次
    sched::start_phone_lookup_service(
        "phone",      // 查找前缀
        100_000,      // 10 万条数据
        24,           // 24 小时保留
        100,          // 100ms 间隔
    ).await;
}
```

输出示例：
```
正在初始化 Cache...
  - 数据量: 100000 条
  - 保留时长: 24 小时
  - 查找前缀: 'phone'
  - 查找间隔: 100 ms
Cache 初始化完成，开始持续查找...

[查找 #1] 找到 100000 条以 'phone' 开头的数据:
  1. 手机号: phone_000001, 区域ID: 1, 缓存键: phone_000001
  2. 手机号: phone_000002, 区域ID: 2, 缓存键: phone_000002
  ...

[查找 #2] 找到 100000 条以 'phone' 开头的数据:
  1. 手机号: phone_000001, 区域ID: 1, 缓存键: phone_000001
  ...
```

### 示例 3：自定义查找逻辑

```rust
use rust_mouse::cpu::sched;
use tokio::time::{sleep, Duration as TokioDuration};

#[tokio::main]
async fn main() {
    // 初始化缓存
    let cache = sched::initialize_phone_cache(100_000, 24).await;

    let mut lookup_count = 0;

    loop {
        lookup_count += 1;

        // 动态改变查找前缀
        let prefix = if lookup_count % 2 == 0 {
            "phone_00001"
        } else {
            "phone_00002"
        };

        let results = sched::lookup_by_prefix(&cache, prefix).await;

        println!("[第 {} 次查找] 前缀 '{}': 找到 {} 条",
                 lookup_count, prefix, results.len());

        // 等待 1 秒后继续
        sleep(TokioDuration::from_secs(1)).await;
    }
}
```

### 示例 4：精确查找

```rust
use rust_mouse::cpu::sched;

#[tokio::main]
async fn main() {
    let cache = sched::initialize_phone_cache(100_000, 24).await;

    // 查找精确的手机号
    let results = sched::lookup_by_prefix(&cache, "phone_000001").await;

    match results.as_slice() {
        [result] => {
            println!("找到唯一匹配:");
            println!("  手机号: {}", result.phone);
            println!("  区域ID: {}", result.region_id);
        }
        _ => {
            println!("未找到或找到多条记录");
        }
    }
}
```

## 测试

运行单元测试：

```bash
cargo test --lib cpu::sched::tests
```

可用的测试：
- `test_initialize_cache` - 测试缓存初始化
- `test_lookup_by_prefix` - 测试前缀查找
- `test_lookup_exact_match` - 测试精确匹配
- `test_lookup_no_match` - 测试无匹配情况
- `test_lookup_all_phones` - 测试查找全部数据

## 性能说明

- **缓存容量**：10 万条记录
- **数据格式**：`phone_000001` 到 `phone_100000`
- **区域ID**：0-999 循环
- **TTL**：24 小时（可配置）
- **查找算法**：遍历所有条目，检查 `phone` 字段是否以指定前缀开头

## 注意事项

1. **死循环**：`continuous_lookup` 和 `start_phone_lookup_service` 会无限循环，确保你有适当的退出机制
2. **性能考虑**：当前查找算法是遍历全部数据，对于 10 万条数据可能需要优化（如使用索引）
3. **内存占用**：10 万条数据大约占用 XX MB 内存
4. **并发访问**：Moka Cache 是线程安全的，可以多个任务同时访问

## 未来优化方向

1. 使用 BTreeMap 或跳表优化查找性能
2. 添加模糊搜索功能
3. 支持正则表达式匹配
4. 添加统计功能（命中率、查找耗时等）
5. 支持批量操作
