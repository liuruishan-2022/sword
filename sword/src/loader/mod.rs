pub mod cpu;
pub mod io;
pub mod network;

#[derive(Debug)]
pub struct LoaderOptions {
    pub tcp_sendmsg_pid: Option<u32>,
}

impl LoaderOptions {
    pub fn parse_args() -> anyhow::Result<Self> {
        let mut args = std::env::args().skip(1);
        let mut tcp_sendmsg_pid = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--tcp-sendmsg-pid" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--tcp-sendmsg-pid requires a value"))?;
                    let pid = value.parse::<u32>().map_err(|err| {
                        anyhow::anyhow!("invalid --tcp-sendmsg-pid {value}: {err}")
                    })?;
                    tcp_sendmsg_pid = Some(pid);
                }
                "--help" | "-h" => {
                    println!("Usage: sword [--tcp-sendmsg-pid PID]");
                    std::process::exit(0);
                }
                _ => return Err(anyhow::anyhow!("unknown argument: {arg}")),
            }
        }

        Ok(Self { tcp_sendmsg_pid })
    }
}

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

fn load_kprobe(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    network::load_network_kprobe(ebpf, options)?;
    Ok(())
}

///
/// 加载ebpf的信息模块
///
pub fn load_ebpf(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    load_tracepoint(ebpf)?;
    load_kprobe(ebpf, options)?;
    Ok(())
}
