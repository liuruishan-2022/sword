use std::{
    hint::{black_box, spin_loop},
    thread,
    time::Duration,
};

use tracing::{info, warn};

use crate::common::cache;

#[derive(Debug, Clone, Copy)]
pub struct SchedSwitchConfig {
    pub workers: usize,
    pub pin_cpu: Option<usize>,
    pub yield_every: u64,
    pub sleep_every: u64,
    pub sleep_for: Duration,
    pub spin_iters: u32,
}

impl Default for SchedSwitchConfig {
    fn default() -> Self {
        let workers = std::thread::available_parallelism()
            .map(|count| count.get() * 4)
            .unwrap_or(4);
        Self {
            workers,
            pin_cpu: None,
            yield_every: 1,
            sleep_every: 64,
            sleep_for: Duration::from_micros(50),
            spin_iters: 20_000,
        }
    }
}

pub async fn search() {
    let cache = cache::mock_cache(100000, Duration::from_hours(24), 100000).await;
    loop {
        let source = cache::generate_random_phone();
        cache.iter().for_each(|(phone, _region)| {
            if source.starts_with(phone.as_str()) {
                info!("命中查找:{phone}");
            }
        });
    }
}

pub fn start_sched_switch_simulator(config: SchedSwitchConfig) {
    let workers = config.workers.max(2);
    info!(
        workers,
        pin_cpu = ?config.pin_cpu,
        yield_every = config.yield_every,
        sleep_every = config.sleep_every,
        sleep_for_us = config.sleep_for.as_micros(),
        spin_iters = config.spin_iters,
        "starting sched_switch simulator"
    );

    for worker_id in 0..workers {
        let thread_name = format!("sched-mouse-{worker_id}");
        let worker_config = config;
        thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                if let Some(cpu) = worker_config.pin_cpu {
                    match pin_current_thread(cpu) {
                        Ok(()) => info!(worker_id, cpu, "worker pinned to cpu"),
                        Err(errno) => warn!(worker_id, cpu, errno, "failed to pin worker"),
                    }
                }

                let mut rounds = 0_u64;
                let mut state = worker_id as u64 + 1;

                loop {
                    for step in 0..worker_config.spin_iters {
                        state = state
                            .wrapping_mul(1_664_525)
                            .wrapping_add(1_013_904_223)
                            .wrapping_add(step as u64);
                        black_box(state);
                        spin_loop();
                    }

                    rounds = rounds.wrapping_add(1);

                    if rounds % worker_config.yield_every == 0 {
                        thread::yield_now();
                    }

                    if worker_config.sleep_every != 0 && rounds % worker_config.sleep_every == 0 {
                        thread::sleep(worker_config.sleep_for);
                    }
                }
            })
            .unwrap_or_else(|err| panic!("failed to spawn {thread_name}: {err}"));
    }
}

#[cfg(target_os = "linux")]
fn pin_current_thread(cpu: usize) -> Result<(), i32> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err(libc::EINVAL);
    }

    let mut cpu_set = unsafe { core::mem::zeroed::<libc::cpu_set_t>() };
    unsafe {
        libc::CPU_ZERO(&mut cpu_set);
        libc::CPU_SET(cpu, &mut cpu_set);
        let result = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            core::mem::size_of::<libc::cpu_set_t>(),
            &cpu_set,
        );
        if result != 0 {
            return Err(result);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pin_current_thread(_cpu: usize) -> Result<(), i32> {
    Err(libc::ENOSYS)
}
