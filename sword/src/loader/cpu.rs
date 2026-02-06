use aya::programs::TracePoint;

pub fn load_sched(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sched_switch").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

    let prograo: &mut TracePoint = ebpf.program_mut("sched_wakeup").unwrap().try_into()?;
    prograo.load()?;
    prograo.attach("sched", "sched_wakeup")?;
    Ok(())
}
