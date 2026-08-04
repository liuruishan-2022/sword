use crate::args::arguments::LoadOptions;
use aya::{
    Ebpf,
    programs::{KProbe, TracePoint},
};
use log::info;

pub mod cpu;
pub mod io;
pub mod network;

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
    network::load_tracepoint(ebpf)?;
    Ok(())
}

fn load_kprobe(ebpf: &mut aya::Ebpf, options: &LoadOptions) -> anyhow::Result<()> {
    network::load_network_kprobe(ebpf, options)?;
    Ok(())
}

///
/// 加载ebpf的信息模块
///
pub fn load_ebpf(ebpf: &mut aya::Ebpf, options: &LoadOptions) -> anyhow::Result<()> {
    load_tracepoint(ebpf)?;
    load_kprobe(ebpf, options)?;
    Ok(())
}

///
/// 定义一些结构体，方便我们做stream形式的处理
///
/// 如果你定义抓取eBPF的函数名字是uname
///  category,kname是系统给的eBPF的函数的分类和名字,
/// u和k是为了区分是用户的还是内核提供的
///

pub struct TracePointConfig {
    uname: String,
    category: String,
    kname: String,
}

impl TracePointConfig {
    pub fn new(uname: String, category: String, kname: String) -> Self {
        TracePointConfig {
            uname: uname,
            category: category,
            kname: kname,
        }
    }

    pub fn create_syscalls(uname: &str, kname: &str) -> Self {
        Self::new(uname.to_string(), "syscalls".to_string(), kname.to_string())
    }

    pub fn create_sock(uname: &str, kname: &str) -> Self {
        Self::new(uname.to_string(), "sock".to_string(), kname.to_string())
    }

    pub fn create_sched(uname: &str, kname: &str) -> Self {
        Self::new(uname.to_string(), "sched".to_string(), kname.to_string())
    }

    pub fn create_tcp(uname: &str, kname: &str) -> Self {
        Self::new(uname.to_string(), "tcp".to_string(), kname.to_string())
    }

    pub fn uname(&self) -> &str {
        self.uname.as_str()
    }

    pub fn category(&self) -> &str {
        self.category.as_str()
    }

    pub fn kname(&self) -> &str {
        self.kname.as_str()
    }

    pub fn load_tracepoint(&self, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        let program: &mut TracePoint = ebpf.program_mut(self.uname()).unwrap().try_into()?;
        program.load()?;
        program.attach(self.category(), self.kname())?;
        info!("load tracepoint:{}!", self.to_string());
        Ok(())
    }
}

impl ToString for TracePointConfig {
    fn to_string(&self) -> String {
        format!("{}/{}-->{}", self.category(), self.kname(), self.uname())
    }
}

pub struct KProberConfig {
    name: String,
    fn_name: String,
}

impl KProberConfig {
    pub fn new(name: &str, fn_name: &str) -> Self {
        KProberConfig {
            name: name.to_string(),
            fn_name: fn_name.to_string(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fn_name(&self) -> &str {
        &self.fn_name
    }

    pub fn load_kprobe(&self, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        let program: &mut KProbe = ebpf.program_mut(&self.name()).unwrap().try_into()?;
        program.load()?;
        program.attach(self.fn_name(), 0)?;
        info!("load kprobe:{} {}", self.name(), self.fn_name());
        Ok(())
    }
}
