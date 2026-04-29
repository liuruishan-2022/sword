use std::{env, fs};

use aya::maps::{Array, HashMap};
use aya::programs::TracePoint;
use log::info;
use sword_common::SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES;

const SCHED_SWITCH_TARGET_TGID_MAP: &str = "SCHED_SWITCH_TARGET_TGID";
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

        let mut tgid_map: Array<_, u32> = Array::try_from(
            ebpf.map_mut(SCHED_SWITCH_TARGET_TGID_MAP)
                .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_TGID_MAP} not found"))?,
        )?;
        tgid_map.set(0, target_tgid, 0)?;

        let mut tids_map: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.map_mut(SCHED_SWITCH_TARGET_TIDS_MAP)
                .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_TIDS_MAP} not found"))?,
        )?;
        for tid in &tids {
            tids_map.insert(*tid, SCHED_SWITCH_TARGET_TID_PRESENT, 0)?;
        }

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
