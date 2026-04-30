use std::{collections::HashSet, env, fs, time::Duration};

use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::TracePoint;
use log::{info, warn};
use sword_common::SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES;
use tokio::time::sleep;

const SCHED_SWITCH_TARGET_TIDS_MAP: &str = "SCHED_SWITCH_TARGET_TIDS";
const SCHED_SWITCH_TARGET_TGID_ENV: &str = "SWORD_SCHED_SWITCH_PID";
const SCHED_SWITCH_TARGET_COMM_ENV: &str = "SWORD_SCHED_SWITCH_COMM";
const SCHED_SWITCH_TARGET_TID_PRESENT: u8 = 1;

#[derive(Clone, Debug)]
enum SchedSwitchTarget {
    Pid(u32),
    Comm(String),
}

impl SchedSwitchTarget {
    fn description(&self) -> String {
        match self {
            Self::Pid(pid) => format!("pid {pid}"),
            Self::Comm(comm) => format!("comm {comm}"),
        }
    }
}

fn configure_sched_switch_target_tids(
    ebpf: &mut aya::Ebpf,
) -> anyhow::Result<Option<(String, usize)>> {
    let Some(target) = read_sched_switch_target()? else {
        return Ok(None);
    };

    let tids = collect_target_thread_ids(&target)?;
    validate_target_tids_capacity(&target, tids.len())?;

    let mut tids_map: AyaHashMap<MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map(SCHED_SWITCH_TARGET_TIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_TIDS_MAP} not found"))?,
    )?;
    for tid in &tids {
        tids_map.insert(*tid, SCHED_SWITCH_TARGET_TID_PRESENT, 0)?;
    }
    spawn_sched_switch_target_tids_refresher(target.clone(), tids_map, tids.clone());

    Ok(Some((target.description(), tids.len())))
}

fn read_sched_switch_target() -> anyhow::Result<Option<SchedSwitchTarget>> {
    let target_tgid = match env::var(SCHED_SWITCH_TARGET_TGID_ENV) {
        Ok(pid) => parse_sched_switch_target_tgid(&pid)?,
        Err(env::VarError::NotPresent) => None,
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to read {SCHED_SWITCH_TARGET_TGID_ENV}: {err}"
            ));
        }
    };
    let target_comm = read_optional_env(SCHED_SWITCH_TARGET_COMM_ENV)?;

    if let Some(target_tgid) = target_tgid {
        if target_comm.is_some() {
            warn!(
                "both {SCHED_SWITCH_TARGET_TGID_ENV} and {SCHED_SWITCH_TARGET_COMM_ENV} are set; using pid filter"
            );
        }
        return Ok(Some(SchedSwitchTarget::Pid(target_tgid)));
    }

    Ok(target_comm.map(SchedSwitchTarget::Comm))
}

fn read_optional_env(name: &str) -> anyhow::Result<Option<String>> {
    match env::var(name) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value.to_string()))
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow::anyhow!("failed to read {name}: {err}")),
    }
}

fn parse_sched_switch_target_tgid(value: &str) -> anyhow::Result<Option<u32>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    value
        .parse::<u32>()
        .map(Some)
        .map_err(|err| anyhow::anyhow!("invalid {SCHED_SWITCH_TARGET_TGID_ENV}: {err}"))
}

fn collect_thread_ids(target_tgid: u32) -> anyhow::Result<Vec<u32>> {
    let task_dir = format!("/proc/{target_tgid}/task");
    let mut tids = Vec::new();

    for entry in fs::read_dir(&task_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let tid = file_name.parse::<u32>().map_err(|err| {
            anyhow::anyhow!("failed to parse tid from {task_dir}/{file_name}: {err}")
        })?;
        tids.push(tid);
    }

    tids.sort_unstable();
    tids.dedup();

    if tids.is_empty() {
        return Err(anyhow::anyhow!("no tids found under {task_dir}"));
    }

    Ok(tids)
}

fn collect_thread_ids_by_comm(target_comm: &str) -> anyhow::Result<Vec<u32>> {
    let mut tids = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let Ok(tgid) = file_name.parse::<u32>() else {
            continue;
        };

        let comm_path = format!("/proc/{tgid}/comm");
        let Ok(comm) = fs::read_to_string(&comm_path) else {
            continue;
        };
        if comm.trim_end() != target_comm {
            continue;
        }

        match collect_thread_ids(tgid) {
            Ok(mut process_tids) => tids.append(&mut process_tids),
            Err(err) => warn!("failed to collect tids for matching process {tgid}: {err}"),
        }
    }

    tids.sort_unstable();
    tids.dedup();
    Ok(tids)
}

fn collect_target_thread_ids(target: &SchedSwitchTarget) -> anyhow::Result<Vec<u32>> {
    match target {
        SchedSwitchTarget::Pid(pid) => collect_thread_ids(*pid),
        SchedSwitchTarget::Comm(comm) => collect_thread_ids_by_comm(comm),
    }
}

fn validate_target_tids_capacity(
    target: &SchedSwitchTarget,
    tid_count: usize,
) -> anyhow::Result<()> {
    if tid_count as u32 > SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES {
        return Err(anyhow::anyhow!(
            "{} has {} tids, exceeds map capacity {}",
            target.description(),
            tid_count,
            SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES
        ));
    }
    Ok(())
}

fn spawn_sched_switch_target_tids_refresher(
    target: SchedSwitchTarget,
    mut tids_map: AyaHashMap<MapData, u32, u8>,
    initial_tids: Vec<u32>,
) {
    tokio::spawn(async move {
        let mut known_tids = initial_tids.into_iter().collect::<HashSet<_>>();

        loop {
            sleep(Duration::from_secs(5)).await;

            let current_tids = match collect_target_thread_ids(&target) {
                Ok(tids) => tids.into_iter().collect::<HashSet<_>>(),
                Err(err) => {
                    warn!(
                        "failed to refresh tids for {}: {}; removing {} known tids from filter",
                        target.description(),
                        err,
                        known_tids.len()
                    );
                    remove_known_tids(&mut tids_map, &mut known_tids);
                    continue;
                }
            };

            if let Err(err) = validate_target_tids_capacity(&target, current_tids.len()) {
                warn!(
                    "{err}; keeping previous sched_switch tid filter for {}",
                    target.description()
                );
                continue;
            }

            for tid in current_tids.difference(&known_tids) {
                if let Err(err) = tids_map.insert(*tid, SCHED_SWITCH_TARGET_TID_PRESENT, 0) {
                    warn!("failed to add tid {} to sched_switch filter: {}", tid, err);
                }
            }

            for tid in known_tids.difference(&current_tids) {
                if let Err(err) = tids_map.remove(tid) {
                    warn!(
                        "failed to remove tid {} from sched_switch filter: {}",
                        tid, err
                    );
                }
            }

            known_tids = current_tids;
        }
    });
}

fn remove_known_tids(tids_map: &mut AyaHashMap<MapData, u32, u8>, known_tids: &mut HashSet<u32>) {
    for tid in known_tids.drain() {
        if let Err(err) = tids_map.remove(&tid) {
            warn!(
                "failed to remove tid {} from sched_switch filter: {}",
                tid, err
            );
        }
    }
}

pub fn load_sched_switch(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let target = configure_sched_switch_target_tids(ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut("sched_switch").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;
    if let Some((target, tid_count)) = target {
        info!(
            "attached sched:sched_switch with target {}; loaded {} tids",
            target, tid_count
        );
    } else {
        info!("attached sched:sched_switch without pid/tid filter");
    }
    Ok(())
}

pub fn load_sched(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    load_sched_switch(ebpf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_sched_switch_target_tgid;

    #[test]
    fn parse_sched_switch_target_tgid_ignores_empty_values() {
        assert_eq!(parse_sched_switch_target_tgid("").unwrap(), None);
        assert_eq!(parse_sched_switch_target_tgid("   ").unwrap(), None);
    }

    #[test]
    fn parse_sched_switch_target_tgid_accepts_pid() {
        assert_eq!(parse_sched_switch_target_tgid("1234").unwrap(), Some(1234));
        assert_eq!(
            parse_sched_switch_target_tgid(" 1234 ").unwrap(),
            Some(1234)
        );
    }

    #[test]
    fn parse_sched_switch_target_tgid_rejects_invalid_pid() {
        let err = parse_sched_switch_target_tgid("abc").unwrap_err();
        assert!(err.to_string().contains("invalid SWORD_SCHED_SWITCH_PID"));
    }
}
