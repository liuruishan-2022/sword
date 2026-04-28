use aya_ebpf::helpers::bpf_get_current_pid_tgid;

///
/// 增加一些工具性质的东西,可以很方便的获取一些数据或者是信息
///
///BPF_CALL_0(bpf_get_current_pid_tgid)
///{
///	struct task_struct *task = current;
///	if (unlikely(!task))
///		return -EINVAL;
///	return (u64) task->tgid << 32 | task->pid;
///}
///
/// 上面这个就是具体的bpf_get_current_pid_tgid的实现，
/// 可以看到就是 tgid占据高32位，pid占据低32位
///
/// 获取进程的id和线程的id (进程id,线程id)
pub fn thread_id() -> (u32, u32) {
    let tgid = bpf_get_current_pid_tgid();
    ((tgid >> 32) as u32, tgid as u32)
}

///
/// 读取ebpf提供的 u8数组 --> &str
///
pub fn byte_to_str<const N: usize>(bytes: &[u8; N]) -> &str {
    let mut len = 0;

    for i in 0..N {
        if bytes[i] == 0 {
            break;
        }
        len = i + 1;
    }
    unsafe { str::from_utf8_unchecked(&bytes[..len]) }
}
