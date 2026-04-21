use std::env;

use aya::maps::Array;
use aya::programs::TracePoint;
use log::info;

const SCHED_SWITCH_TARGET_PID_MAP: &str = "SCHED_SWITCH_TARGET_PID";
const SCHED_SWITCH_TARGET_PID_ENV: &str = "SWORD_SCHED_SWITCH_PID";

fn configure_sched_switch_target_pid(ebpf: &mut aya::Ebpf) -> anyhow::Result<Option<u32>> {
    let target_pid = match env::var(SCHED_SWITCH_TARGET_PID_ENV) {
        Ok(pid) => Some(
            pid.parse::<u32>()
                .map_err(|err| anyhow::anyhow!("invalid {SCHED_SWITCH_TARGET_PID_ENV}: {err}"))?,
        ),
        Err(env::VarError::NotPresent) => None,
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to read {SCHED_SWITCH_TARGET_PID_ENV}: {err}"
            ));
        }
    };

    if let Some(target_pid) = target_pid {
        let mut map: Array<_, u32> = Array::try_from(
            ebpf.map_mut(SCHED_SWITCH_TARGET_PID_MAP)
                .ok_or_else(|| anyhow::anyhow!("map {SCHED_SWITCH_TARGET_PID_MAP} not found"))?,
        )?;
        map.set(0, target_pid, 0)?;
    }

    Ok(target_pid)
}

pub fn load_sched_switch(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let target_pid = configure_sched_switch_target_pid(ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut("sched_switch").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;
    if let Some(target_pid) = target_pid {
        info!(
            "attached sched:sched_switch with pid filter {}; note: sched_switch matches task pid/tid",
            target_pid
        );
    } else {
        info!("attached sched:sched_switch without pid filter");
    }
    Ok(())
}

pub fn load_sched_wakeup(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_wakeup").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_wakeup")?;
    Ok(())
}

pub fn load_sched_wakeup_new(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_wakeup_new").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_wakeup_new")?;
    Ok(())
}

pub fn load_sched_waking(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_waking").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_waking")?;
    Ok(())
}

pub fn load_sched_wait_task(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_wait_task").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_wait_task")?;
    Ok(())
}

pub fn load_sched(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    load_sched_switch(ebpf)?;
    //load_sched_wakeup(ebpf)?;
    //load_sched_wakeup_new(ebpf)?;
    //load_sched_waking(ebpf)?;
    //load_sched_wait_task(ebpf)?;
    Ok(())
}
