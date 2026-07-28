use aya::{
    Ebpf,
    maps::Array,
    programs::{KProbe, TracePoint},
};
use log::info;
use sword_common::RiskTargetConfig;

pub mod cpu;
pub mod io;
pub mod network;

#[derive(Debug)]
pub struct LoaderOptions {
    pub target_pid: Option<u32>,
    pub target_cmdline: Option<String>,
    pub target_comm: Option<String>,
    pub server_port: u16,
    pub slow_threshold_ms: u64,
}

impl LoaderOptions {
    pub fn parse_args() -> anyhow::Result<Self> {
        Self::parse_with_env(std::env::args().skip(1), |name| std::env::var(name))
    }

    fn parse<I, S>(args: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::parse_with_env(args, |_| Err(std::env::VarError::NotPresent))
    }

    fn parse_with_env<I, S, F>(args: I, read_env: F) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        F: Fn(&str) -> Result<String, std::env::VarError>,
    {
        const DEFAULT_SERVER_PORT: u16 = 8080;
        const DEFAULT_SLOW_THRESHOLD_MS: u64 = 100;

        let mut args = args.into_iter().map(Into::into);
        let mut target_pid = optional_env(&read_env, "SWORD_SCHED_SWITCH_PID")?
            .map(|value| parse_positive_u32("SWORD_SCHED_SWITCH_PID", &value))
            .transpose()?;
        let target_cmdline = optional_env(&read_env, "SWORD_TARGET_CMDLINE")?;
        let target_comm = optional_env(&read_env, "SWORD_SCHED_SWITCH_COMM")?;
        let mut server_port = optional_env(&read_env, "SWORD_TARGET_PORT")?
            .map(|value| parse_positive_u16("SWORD_TARGET_PORT", &value))
            .transpose()?
            .unwrap_or(DEFAULT_SERVER_PORT);
        let mut slow_threshold_ms = optional_env(&read_env, "SWORD_SLOW_THRESHOLD_MS")?
            .map(|value| parse_positive_u64("SWORD_SLOW_THRESHOLD_MS", &value))
            .transpose()?
            .unwrap_or(DEFAULT_SLOW_THRESHOLD_MS);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--target-pid" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--target-pid requires a value"))?;
                    info!("获取到的pid为:{}!", value);
                    let pid = value
                        .parse::<u32>()
                        .map_err(|err| anyhow::anyhow!("invalid --target-pid {value}: {err}"))?;
                    if pid == 0 {
                        return Err(anyhow::anyhow!("--target-pid must be greater than 0"));
                    }
                    target_pid = Some(pid);
                }
                "--server-port" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--server-port requires a value"))?;
                    server_port = value
                        .parse::<u16>()
                        .map_err(|err| anyhow::anyhow!("invalid --server-port {value}: {err}"))?;
                    if server_port == 0 {
                        return Err(anyhow::anyhow!("--server-port must be greater than 0"));
                    }
                }
                "--slow-threshold-ms" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--slow-threshold-ms requires a value"))?;
                    slow_threshold_ms = value.parse::<u64>().map_err(|err| {
                        anyhow::anyhow!("invalid --slow-threshold-ms {value}: {err}")
                    })?;
                    if slow_threshold_ms == 0 {
                        return Err(anyhow::anyhow!(
                            "--slow-threshold-ms must be greater than 0"
                        ));
                    }
                }
                "--help" | "-h" => {
                    println!(
                        "Usage: sword [--target-pid PID] [--server-port PORT] \
                         [--slow-threshold-ms MILLIS]"
                    );
                    std::process::exit(0);
                }
                _ => return Err(anyhow::anyhow!("unknown argument: {arg}")),
            }
        }

        Ok(Self {
            target_pid,
            target_cmdline,
            target_comm,
            server_port,
            slow_threshold_ms,
        })
    }

    pub fn targeting_enabled(&self) -> bool {
        self.target_pid.is_some() || self.target_cmdline.is_some() || self.target_comm.is_some()
    }
}

fn optional_env<F>(read_env: &F, name: &str) -> anyhow::Result<Option<String>>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    match read_env(name) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value.to_string()))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow::anyhow!("failed to read {name}: {err}")),
    }
}

fn parse_positive_u16(name: &str, value: &str) -> anyhow::Result<u16> {
    let value = value
        .parse::<u16>()
        .map_err(|err| anyhow::anyhow!("invalid {name} {value}: {err}"))?;
    if value == 0 {
        return Err(anyhow::anyhow!("{name} must be greater than 0"));
    }
    Ok(value)
}

fn parse_positive_u32(name: &str, value: &str) -> anyhow::Result<u32> {
    let value = value
        .parse::<u32>()
        .map_err(|err| anyhow::anyhow!("invalid {name} {value}: {err}"))?;
    if value == 0 {
        return Err(anyhow::anyhow!("{name} must be greater than 0"));
    }
    Ok(value)
}

fn parse_positive_u64(name: &str, value: &str) -> anyhow::Result<u64> {
    let value = value
        .parse::<u64>()
        .map_err(|err| anyhow::anyhow!("invalid {name} {value}: {err}"))?;
    if value == 0 {
        return Err(anyhow::anyhow!("{name} must be greater than 0"));
    }
    Ok(value)
}

///
/// 逐步的引入各个模块的tracepoint的跟踪点,按照如下的模块进行引入:
/// 1. cpu
/// 2. io
/// 3. memory
/// 4. network
/// 5. block
///
fn load_tracepoint(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    cpu::load_sched(ebpf, options)?;
    io::load_io(ebpf)?;
    network::load_tracepoint(ebpf)?;
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
    configure_risk_target(ebpf, options)?;
    load_tracepoint(ebpf, options)?;
    load_kprobe(ebpf, options)?;
    Ok(())
}

fn configure_risk_target(ebpf: &mut aya::Ebpf, options: &LoaderOptions) -> anyhow::Result<()> {
    if !options.targeting_enabled() {
        return Ok(());
    }

    let map = ebpf
        .map_mut("RISK_TARGET_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("map RISK_TARGET_CONFIG not found"))?;
    let mut config_map = Array::<_, RiskTargetConfig>::try_from(map)?;
    config_map.set(
        0,
        RiskTargetConfig {
            tgid: options.target_pid.unwrap_or(0),
            server_port: options.server_port,
            _pad: 0,
            slow_threshold_ns: options.slow_threshold_ms * 1_000_000,
        },
        0,
    )?;
    info!(
        "configured risk tracing server_port={} slow_threshold_ms={}",
        options.server_port, options.slow_threshold_ms
    );
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, env::VarError};

    use super::LoaderOptions;

    fn env_reader(values: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> + use<> {
        let values = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        move |name| values.get(name).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn parse_risk_target_defaults() {
        let options = LoaderOptions::parse(["--target-pid", "1234"]).unwrap();
        assert_eq!(options.target_pid, Some(1234));
        assert_eq!(options.server_port, 8080);
        assert_eq!(options.slow_threshold_ms, 100);
    }

    #[test]
    fn parse_risk_target_overrides() {
        let options = LoaderOptions::parse([
            "--target-pid",
            "1234",
            "--server-port",
            "9090",
            "--slow-threshold-ms",
            "250",
        ])
        .unwrap();
        assert_eq!(options.target_pid, Some(1234));
        assert_eq!(options.server_port, 9090);
        assert_eq!(options.slow_threshold_ms, 250);
    }

    #[test]
    fn parse_risk_target_rejects_invalid_values() {
        assert!(LoaderOptions::parse(["--target-pid", "abc"]).is_err());
        assert!(LoaderOptions::parse(["--target-pid", "0"]).is_err());
        assert!(LoaderOptions::parse(["--server-port", "70000"]).is_err());
        assert!(LoaderOptions::parse(["--server-port", "0"]).is_err());
        assert!(LoaderOptions::parse(["--slow-threshold-ms", "0"]).is_err());
    }

    #[test]
    fn parses_daemonset_target_from_environment() {
        let options = LoaderOptions::parse_with_env(
            std::iter::empty::<&str>(),
            env_reader(&[
                ("SWORD_TARGET_CMDLINE", "content-risk-control-service.jar"),
                ("SWORD_TARGET_PORT", "8080"),
                ("SWORD_SLOW_THRESHOLD_MS", "100"),
            ]),
        )
        .unwrap();

        assert_eq!(
            options.target_cmdline.as_deref(),
            Some("content-risk-control-service.jar")
        );
        assert_eq!(options.server_port, 8080);
        assert_eq!(options.slow_threshold_ms, 100);
    }

    #[test]
    fn command_line_values_override_daemonset_environment() {
        let options = LoaderOptions::parse_with_env(
            [
                "--target-pid",
                "42",
                "--server-port",
                "9090",
                "--slow-threshold-ms",
                "250",
            ],
            env_reader(&[
                ("SWORD_TARGET_CMDLINE", "content-risk-control-service.jar"),
                ("SWORD_TARGET_PORT", "8080"),
                ("SWORD_SLOW_THRESHOLD_MS", "100"),
            ]),
        )
        .unwrap();

        assert_eq!(options.target_pid, Some(42));
        assert_eq!(options.server_port, 9090);
        assert_eq!(options.slow_threshold_ms, 250);
    }

    #[test]
    fn rejects_invalid_daemonset_environment() {
        assert!(
            LoaderOptions::parse_with_env(
                std::iter::empty::<&str>(),
                env_reader(&[("SWORD_TARGET_PORT", "70000")]),
            )
            .is_err()
        );
        assert!(
            LoaderOptions::parse_with_env(
                std::iter::empty::<&str>(),
                env_reader(&[("SWORD_SLOW_THRESHOLD_MS", "0")]),
            )
            .is_err()
        );
    }
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
