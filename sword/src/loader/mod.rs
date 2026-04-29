pub mod cpu;
pub mod io;

///
/// 逐步的引入各个模块的tracepoint的跟踪点,按照如下的模块进行引入:
/// 1. cpu
/// 2. io
/// 3. memory
/// 4. network
/// 5. block
///
fn load_tracepoint(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    cpu::load_sched(ebpf)?;
    io::load_io(ebpf)?;
    Ok(())
}

///
/// 加载ebpf的信息模块
///
pub fn load_ebpf(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    load_tracepoint(ebpf)?;
    Ok(())
}
