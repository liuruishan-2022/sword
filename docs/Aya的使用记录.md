# 1. 概述

记录aya-rs的使用信息,逐步的丰富自己的eBPF的知识储备.

# 2. 技术文章阅读

## 2.1 技术文章

https://yuki-nakamura.com/2024/07/06/writing-ebpf-tracepoint-program-with-rust-aya-tips-and-example/

这个文章是介绍aya-rs对tracepoint的封装的做法和一些的使用技巧的例子

Kernel space: tracepoint会调用定义的tracepoint跟踪函数,然后在这个跟踪函数中接收跟踪点的数据进行处理，发送到eBPF map events中

User space: 用户空间的代码会检测eBPF map,如果发现有数据变动，则读取数据并且打印出来.
