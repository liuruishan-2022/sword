pub mod cpu;

pub fn load_tracepoint(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    cpu::load_sched(ebpf)?;
    Ok(())
}
