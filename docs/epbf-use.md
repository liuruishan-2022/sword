# 1. 出现的问题

## 1.1 EBPF加载报错

```bash
Error: the BPF_PROG_LOAD syscall returned Invalid argument (os error 22). Verifier output: last insn is not an exit or jmp
verification time 6 usec
stack depth 0+0+0
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0


Caused by:
    Invalid argument (os error 22)
```

原因解释: 是在Rust代码中使用了:Result的?/unwrap()/except()等可能抛出panic的调用导致的.
因为操作系统不知道这段代码是否会产生panic,所以会拒绝，即使你的这段代码不会产生panic,
所以需要替换成match的使用才行.
