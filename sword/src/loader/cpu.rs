use std::{collections::HashSet, fs, time::Duration};

use aya::maps::{HashMap as AyaHashMap, MapData};
use log::{info, warn};
use sword_common::{RISK_TARGET_TGIDS_MAX_ENTRIES, SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES};
use tokio::time::sleep;

use crate::loader::{LoaderOptions, TracePointConfig};

const SCHED_SWITCH_TARGET_TIDS_MAP: &str = "SCHED_SWITCH_TARGET_TIDS";
const RISK_TARGET_TGIDS_MAP: &str = "RISK_TARGET_TGIDS";
const SCHED_SWITCH_TARGET_TID_PRESENT: u8 = 1;
const RISK_TARGET_TGID_PRESENT: u8 = 1;

#[derive(Clone, Debug)]
enum SchedSwitchTarget {
    Pid(u32),
    Cmdline(String),
    Comm(String),
}

impl SchedSwitchTarget {
    fn description(&self) -> String {
        match self {
            Self::Pid(pid) => format!("pid {pid}"),
            Self::Cmdline(cmdline) => format!("cmdline contains {cmdline}"),
            Self::Comm(comm) => format!("comm {comm}"),
        }
    }
}

fn cmdline_matches(cmdline: &[u8], marker: &str) -> bool {
    cmdline
        .split(|byte| *byte == 0)
        .filter_map(|arg| std::str::from_utf8(arg).ok())
        .any(|arg| arg.contains(marker))
}

#[derive(Default)]
struct TargetSnapshot {
    tgids: HashSet<u32>,
    tids: HashSet<u32>,
}

fn configure_sched_switch_target_tids(
    ebpf: &mut aya::Ebpf,
    options: &LoaderOptions,
) -> anyhow::Result<Option<(String, usize, usize)>> {
    let Some(target) = read_sched_switch_target(options) else {
        return Ok(None);
    };

    let snapshot = collect_target_snapshot(&target)?;
    validate_target_capacity(&target, &snapshot)?;

    let mut tids_map: AyaHashMap<MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map(SCHED_SWITCH_TARGET_TIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_TIDS_MAP} not found"))?,
    )?;
    let mut tgids_map: AyaHashMap<MapData, u32, u8> = AyaHashMap::try_from(
        ebpf.take_map(RISK_TARGET_TGIDS_MAP)
            .ok_or_else(|| anyhow::anyhow!("map {RISK_TARGET_TGIDS_MAP} not found"))?,
    )?;
    for tid in &snapshot.tids {
        tids_map.insert(*tid, SCHED_SWITCH_TARGET_TID_PRESENT, 0)?;
    }
    for tgid in &snapshot.tgids {
        tgids_map.insert(*tgid, RISK_TARGET_TGID_PRESENT, 0)?;
    }
    let tgid_count = snapshot.tgids.len();
    let tid_count = snapshot.tids.len();
    spawn_target_refresher(target.clone(), tgids_map, tids_map, snapshot);

    Ok(Some((target.description(), tgid_count, tid_count)))
}

fn read_sched_switch_target(options: &LoaderOptions) -> Option<SchedSwitchTarget> {
    if let Some(target_pid) = options.target_pid {
        return Some(SchedSwitchTarget::Pid(target_pid));
    }
    if let Some(target_cmdline) = &options.target_cmdline {
        return Some(SchedSwitchTarget::Cmdline(target_cmdline.clone()));
    }
    options
        .target_comm
        .as_ref()
        .map(|comm| SchedSwitchTarget::Comm(comm.clone()))
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

fn collect_target_process_ids(target: &SchedSwitchTarget) -> anyhow::Result<Vec<u32>> {
    if let SchedSwitchTarget::Pid(pid) = target {
        return Ok(std::path::Path::new("/proc")
            .join(pid.to_string())
            .exists()
            .then_some(*pid)
            .into_iter()
            .collect());
    }

    let mut tgids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let Ok(tgid) = file_name.parse::<u32>() else {
            continue;
        };

        let matches = match target {
            SchedSwitchTarget::Cmdline(marker) => fs::read(format!("/proc/{tgid}/cmdline"))
                .is_ok_and(|cmdline| cmdline_matches(&cmdline, marker)),
            SchedSwitchTarget::Comm(target_comm) => {
                fs::read_to_string(format!("/proc/{tgid}/comm"))
                    .is_ok_and(|comm| comm.trim_end() == target_comm)
            }
            SchedSwitchTarget::Pid(_) => false,
        };
        if matches {
            tgids.push(tgid);
        }
    }
    tgids.sort_unstable();
    tgids.dedup();
    Ok(tgids)
}

fn collect_target_snapshot(target: &SchedSwitchTarget) -> anyhow::Result<TargetSnapshot> {
    let mut snapshot = TargetSnapshot::default();
    for tgid in collect_target_process_ids(target)? {
        snapshot.tgids.insert(tgid);
        match collect_thread_ids(tgid) {
            Ok(process_tids) => snapshot.tids.extend(process_tids),
            Err(err) => warn!("failed to collect tids for matching process {tgid}: {err}"),
        }
    }
    Ok(snapshot)
}

fn validate_target_capacity(
    target: &SchedSwitchTarget,
    snapshot: &TargetSnapshot,
) -> anyhow::Result<()> {
    if snapshot.tgids.len() as u32 > RISK_TARGET_TGIDS_MAX_ENTRIES {
        return Err(anyhow::anyhow!(
            "{} has {} processes, exceeds map capacity {}",
            target.description(),
            snapshot.tgids.len(),
            RISK_TARGET_TGIDS_MAX_ENTRIES
        ));
    }
    if snapshot.tids.len() as u32 > SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES {
        return Err(anyhow::anyhow!(
            "{} has {} tids, exceeds map capacity {}",
            target.description(),
            snapshot.tids.len(),
            SCHED_SWITCH_TARGET_TIDS_MAX_ENTRIES
        ));
    }
    Ok(())
}

fn spawn_target_refresher(
    target: SchedSwitchTarget,
    mut tgids_map: AyaHashMap<MapData, u32, u8>,
    mut tids_map: AyaHashMap<MapData, u32, u8>,
    initial: TargetSnapshot,
) {
    tokio::spawn(async move {
        let mut known_tgids = initial.tgids;
        let mut known_tids = initial.tids;

        loop {
            sleep(Duration::from_secs(5)).await;

            let current = match collect_target_snapshot(&target) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    warn!(
                        "failed to refresh targets for {}: {}",
                        target.description(),
                        err
                    );
                    continue;
                }
            };

            if let Err(err) = validate_target_capacity(&target, &current) {
                warn!(
                    "{err}; keeping previous target filters for {}",
                    target.description()
                );
                continue;
            }

            if current.tgids != known_tgids || current.tids != known_tids {
                info!(
                    "refreshed target {}; found {} tgids and {} tids",
                    target.description(),
                    current.tgids.len(),
                    current.tids.len()
                );
            }
            sync_target_map(
                &mut tgids_map,
                &mut known_tgids,
                &current.tgids,
                RISK_TARGET_TGID_PRESENT,
                "tgid",
            );
            sync_target_map(
                &mut tids_map,
                &mut known_tids,
                &current.tids,
                SCHED_SWITCH_TARGET_TID_PRESENT,
                "tid",
            );
        }
    });
}

fn sync_target_map(
    map: &mut AyaHashMap<MapData, u32, u8>,
    known: &mut HashSet<u32>,
    current: &HashSet<u32>,
    present: u8,
    kind: &str,
) {
    for id in current.difference(known).copied().collect::<Vec<_>>() {
        match map.insert(id, present, 0) {
            Ok(()) => {
                known.insert(id);
            }
            Err(err) => warn!("failed to add {kind} {id} to target filter: {err}"),
        }
    }
    for id in known.difference(current).copied().collect::<Vec<_>>() {
        match map.remove(&id) {
            Ok(()) => {
                known.remove(&id);
            }
            Err(err) => warn!("failed to remove {kind} {id} from target filter: {err}"),
        }
    }
}

pub fn load_sched_switch(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    let target = configure_sched_switch_target_tids(ebpf, options)?;
    if let Some((target, tgid_count, tid_count)) = target {
        if tgid_count == 0 {
            warn!(
                "attached sched:sched_switch with target {}; no matching process yet",
                target
            );
        } else {
            info!(
                "attached sched:sched_switch with target {}; loaded {} tgids and {} tids",
                target, tgid_count, tid_count
            );
        }
    } else {
        info!("attached sched:sched_switch without pid/tid filter");
    }
    Ok(())
}

pub fn load_sched(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    let trace_points = vec![
        TracePointConfig::create_sched("sched_switch", "sched_switch"),
        TracePointConfig::create_sched("sched_wakeup", "sched_wakeup"),
        TracePointConfig::create_sched("sched_wakeup_new", "sched_wakeup_new"),
    ];
    for ele in trace_points {
        ele.load_tracepoint(ebpf)?;
    }
    load_sched_switch(ebpf, options)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SchedSwitchTarget, cmdline_matches};

    #[test]
    fn matches_target_jar_in_nul_separated_cmdline() {
        let cmdline = b"java\0-jar\0content-risk-control-service.jar\0";

        assert!(cmdline_matches(cmdline, "content-risk-control-service.jar"));
        assert!(!cmdline_matches(cmdline, "another-service.jar"));
    }

    #[test]
    fn cmdline_target_description_does_not_include_full_command() {
        let target = SchedSwitchTarget::Cmdline("content-risk-control-service.jar".to_string());

        assert_eq!(
            target.description(),
            "cmdline contains content-risk-control-service.jar"
        );
    }
}
