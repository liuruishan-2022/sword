use std::{collections::HashSet, env, fs, time::Duration};

use aya::maps::{HashMap as AyaHashMap, MapData};
use aya::programs::TracePoint;
use log::{info, warn};
use sword_common::SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES;
use tokio::time::sleep;

const SCHED_SWITCH_TARGET_TIDS_MAP: &str = "SCHED_SWITCH_TARGET_TIDS";
const SCHED_SWITCH_TARGET_TGID_ENV: &str = "SWORD_SCHED_SWITCH_PID";
const SCHED_SWITCH_TARGET_TID_PRESENT: u8 = 1;

fn configure_sched_switch_target_tids(
    ebpf: &mut aya::Ebpf,
) -> anyhow::Result<Option<(u32, usize)>> {
    let target_tgid = match env::var(SCHED_SWITCH_TARGET_TGID_ENV) {
        Ok(pid) => parse_sched_switch_target_tgid(&pid)?,
        Err(env::VarError::NotPresent) => None,
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to read {SCHED_SWITCH_TARGET_TGID_ENV}: {err}"
            ));
        }
    };

    if let Some(target_tgid) = target_tgid {
        let tids = collect_thread_ids(target_tgid)?;
        if tids.len() as u32 > SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES {
            return Err(anyhow::anyhow!(
                "process {target_tgid} has {} tids, exceeds map capacity {}",
                tids.len(),
                SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES
            ));
        }

        let mut tids_map: AyaHashMap<MapData, u32, u8> = AyaHashMap::try_from(
            ebpf.take_map(SCHED_SWITCH_TARGET_TIDS_MAP)
                .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_TIDS_MAP} not found"))?,
        )?;
        for tid in &tids {
            tids_map.insert(*tid, SCHED_SWITCH_TARGET_TID_PRESENT, 0)?;
        }
        spawn_sched_switch_target_tids_refresher(target_tgid, tids_map, tids.clone());

        return Ok(Some((target_tgid, tids.len())));
    }

    Ok(None)
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

fn spawn_sched_switch_target_tids_refresher(
    target_tgid: u32,
    mut tids_map: AyaHashMap<MapData, u32, u8>,
    initial_tids: Vec<u32>,
) {
    tokio::spawn(async move {
        let mut known_tids = initial_tids.into_iter().collect::<HashSet<_>>();

        loop {
            sleep(Duration::from_secs(5)).await;

            let current_tids = match collect_thread_ids(target_tgid) {
                Ok(tids) => tids.into_iter().collect::<HashSet<_>>(),
                Err(err) => {
                    warn!(
                        "failed to refresh tids from /proc/{}/task: {}; removing {} known tids from filter",
                        target_tgid,
                        err,
                        known_tids.len()
                    );
                    remove_known_tids(&mut tids_map, &mut known_tids);
                    continue;
                }
            };

            if current_tids.len() as u32 > SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES {
                warn!(
                    "process {} has {} tids, exceeds map capacity {}; keeping previous tid filter",
                    target_tgid,
                    current_tids.len(),
                    SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES
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
    if let Some((target_tgid, tid_count)) = target {
        info!(
            "attached sched:sched_switch with tgid filter {}; loaded {} tids from /proc/{}/task",
            target_tgid, tid_count, target_tgid
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
