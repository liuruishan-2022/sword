use aya_ebpf::helpers::bpf_get_current_pid_tgid;

///
/// 增加一些工具性质的东西,可以很方便的获取一些数据或者是信息
///

///
/// 获取进程的id和线程的id (进程id,线程id)
pub fn thread_id() -> (u32, u32) {
    let tgid = bpf_get_current_pid_tgid();
    ((tgid >> 32) as u32, tgid as u32)
}
