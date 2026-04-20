use aya::programs::TracePoint;

pub fn load_sched_switch(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_switch").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;
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
