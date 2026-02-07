# 文件系统相关 Tracepoint

本文档列出了所有与文件系统操作相关的 tracepoint，可用于 eBPF 追踪文件系统行为。

## 目录
- [VFS 层追踪](#vfs-层追踪)
- [EXT4 文件系统](#ext4-文件系统)
- [文件映射](#文件映射)
- [文件锁](#文件锁)
- [写回操作](#写回操作)
- [JBD2 日志层](#jbd2-日志层)
- [内存映射](#内存映射)
- [DAX 文件系统](#dax-文件系统)

---

## VFS 层追踪

> **重要说明**: Linux 内核 tracepoint 中**没有直接以 `vfs:` 命名的类别**。VFS（虚拟文件系统）层的操作主要通过以下方式追踪：

### 1. 系统调用 tracepoint（主要方式）

VFS 层的所有操作最终都通过系统调用进入，这些是追踪 VFS 的主要方式。

#### 文件打开与关闭
- `tracepoint:syscalls:sys_enter_open` / `sys_exit_open` - 打开文件
- `tracepoint:syscalls:sys_enter_openat` / `sys_exit_openat` - 通过目录文件描述���打开
- `tracepoint:syscalls:sys_enter_close` / `sys_exit_close` - 关闭文件
- `tracepoint:syscalls:sys_enter_creat` / `sys_exit_creat` - 创建文件

#### 文件读写
- `tracepoint:syscalls:sys_enter_read` / `sys_exit_read` - 读取文件
- `tracepoint:syscalls:sys_enter_write` / `sys_exit_write` - 写入文件
- `tracepoint:syscalls:sys_enter_pread64` / `sys_exit_pread64` - 带偏移量读取
- `tracepoint:syscalls:sys_enter_pwrite64` / `sys_exit_pwrite64` - 带偏移量写入
- `tracepoint:syscalls:sys_enter_readv` / `sys_exit_readv` - 读取向量
- `tracepoint:syscalls:sys_enter_writev` / `sys_exit_writev` - 写入向量
- `tracepoint:syscalls:sys_enter_preadv2` / `sys_exit_preadv2` - 带偏移量读取向量 v2
- `tracepoint:syscalls:sys_enter_pwritev2` / `sys_exit_pwritev2` - 带偏移量写入向量 v2

#### 文件定位与控制
- `tracepoint:syscalls:sys_enter_lseek` / `sys_exit_lseek` - 移动文件指针
- `tracepoint:syscalls:sys_enter_ioctl` / `sys_exit_ioctl` - I/O 控制
- `tracepoint:syscalls:sys_enter_fcntl` / `sys_exit_fcntl` - 文件控制
- `tracepoint:syscalls:sys_enter_dup` / `sys_exit_dup` - 复制文件描述符
- `tracepoint:syscalls:sys_enter_dup2` / `sys_exit_dup2` - 复制文件描述符到指定位置
- `tracepoint:syscalls:sys_enter_dup3` / `sys_exit_dup3` - 复制文件描述符（带标志）

#### 文件状态与属性
- `tracepoint:syscalls:sys_enter_stat` / `sys_exit_stat` - 获取文件状态
- `tracepoint:syscalls:sys_enter_fstat` / `sys_exit_fstat` - 通过文件描述符获取状态
- `tracepoint:syscalls:sys_enter_lstat` / `sys_exit_lstat` - 获取链接文件状态
- `tracepoint:syscalls:sys_enter_newfstatat` / `sys_exit_newfstatat` - 新版 fstatat
- `tracepoint:syscalls:sys_enter_statx` / `sys_exit_statx` - 扩展文件状态
- `tracepoint:syscalls:sys_enter_chmod` / `sys_exit_chmod` - 修改权限
- `tracepoint:syscalls:sys_enter_fchmod` / `sys_exit_fchmod` - 通过文件描述符修改权限
- `tracepoint:syscalls:sys_enter_fchmodat` / `sys_exit_fchmodat` - 通过目录 fd 修改权限
- `tracepoint:syscalls:sys_enter_chown` / `sys_exit_chown` - 修改所有者
- `tracepoint:syscalls:sys_enter_fchown` / `sys_exit_fchown` - 通过文件描述符修改所有者
- `tracepoint:syscalls:sys_enter_fchownat` / `sys_exit_fchownat` - 通过目录 fd 修改所有者
- `tracepoint:syscalls:sys_enter_lchown` / `sys_exit_lchown` - 修改链接文件所有者
- `tracepoint:syscalls:sys_enter_utime` / `sys_exit_utime` - 修改文件时间
- `tracepoint:syscalls:sys_enter_utimensat` / `sys_exit_utimensat` - 修改文件时间（纳秒精度）
- `tracepoint:syscalls:sys_enter_futimesat` / `sys_exit_futimesat` - 修改文件时间（微秒精度）

#### 目录操作
- `tracepoint:syscalls:sys_enter_mkdir` / `sys_exit_mkdir` - 创建目录
- `tracepoint:syscalls:sys_enter_mkdirat` / `sys_exit_mkdirat` - 通过目录 fd 创建目录
- `tracepoint:syscalls:sys_enter_rmdir` / `sys_exit_rmdir` - 删除目录
- `tracepoint:syscalls:sys_enter_getdents` / `sys_exit_getdents` - 读取目录项
- `tracepoint:syscalls:sys_enter_getdents64` / `sys_exit_getdents64` - 读取目录项（64位）

#### 链接操作
- `tracepoint:syscalls:sys_enter_link` / `sys_exit_link` - 创建硬链接
- `tracepoint:syscalls:sys_enter_linkat` / `sys_exit_linkat` - 通过目录 fd 创建硬链接
- `tracepoint:syscalls:sys_enter_unlink` / `sys_exit_unlink` - 删除链接
- `tracepoint:syscalls:sys_enter_unlinkat` / `sys_exit_unlinkat` - 通过目录 fd 删除链接
- `tracepoint:syscalls:sys_enter_symlink` / `sys_exit_symlink` - 创建符号链接
- `tracepoint:syscalls:sys_enter_symlinkat` / `sys_exit_symlinkat` - 通过目录 fd 创建符号链接
- `tracepoint:syscalls:sys_enter_readlink` / `sys_exit_readlink` - 读取符号链接
- `tracepoint:syscalls:sys_enter_readlinkat` / `sys_exit_readlinkat` - 通过目录 fd 读取符号链接

#### 文件重命名与移动
- `tracepoint:syscalls:sys_enter_rename` / `sys_exit_rename` - 重命名文件
- `tracepoint:syscalls:sys_enter_renameat` / `sys_exit_renameat` - 通过目录 fd 重命名
- `tracepoint:syscalls:sys_enter_renameat2` / `sys_exit_renameat2` - 扩展重命名（带标志）

#### 文件截断与分配
- `tracepoint:syscalls:sys_enter_truncate` / `sys_exit_truncate` - 截断文件
- `tracepoint:syscalls:sys_enter_ftruncate` / `sys_exit_ftruncate` - 通过文件描述符截断
- `tracepoint:syscalls:sys_enter_fallocate` / `sys_exit_fallocate` - 预分配空间

#### 文件同步
- `tracepoint:syscalls:sys_enter_fsync` / `sys_exit_fsync` - 同步文件到磁盘
- `tracepoint:syscalls:sys_enter_fdatasync` / `sys_exit_fdatasync` - 同步数据到磁盘
- `tracepoint:syscalls:sys_enter_sync` / `sys_exit_sync` - 同步所有文件系统
- `tracepoint:syscalls:sys_enter_syncfs` / `sys_exit_syncfs` - 同步指定文件系统
- `tracepoint:syscalls:sys_enter_sync_file_range` / `sys_exit_sync_file_range` - 同步文件范围

#### 文件系统挂载
- `tracepoint:syscalls:sys_enter_mount` / `sys_exit_mount` - 挂载文件系统
- `tracepoint:syscalls:sys_enter_mount_setattr` / `sys_exit_mount_setattr` - 设置挂载属性
- `tracepoint:syscalls:sys_enter_move_mount` / `sys_exit_move_mount` - 移动挂载点
- `tracepoint:syscalls:sys_enter_umount` / `sys_exit_umount` - 卸载文件系统
- `tracepoint:syscalls:sys_enter_pivot_root` / `sys_exit_pivot_root` - 切换根文件系统
- `tracepoint:syscalls:sys_enter_fsopen` / `sys_exit_fsopen` - 打开文件系统上下文
- `tracepoint:syscalls:sys_enter_fspick` / `sys_exit_fspick` - 拾取文件系统
- `tracepoint:syscalls:sys_enter_fsconfig` / `sys_exit_fsconfig` - 配置文件系统
- `tracepoint:syscalls:sys_enter_fsmount` / `sys_exit_fsmount` - 创建挂载
- `tracepoint:syscalls:sys_enter_open_tree` / `sys_exit_open_tree` - 打开文件树
- `tracepoint:syscalls:sys_enter_statfs` / `sys_exit_statfs` - 获取文件系统统计
- `tracepoint:syscalls:sys_enter_fstatfs` / `sys_exit_fstatfs` - 通过 fd 获取文件系统统计
- `tracepoint:syscalls:sys_enter_statmount` / `sys_exit_statmount` - 获取挂载信息
- `tracepoint:syscalls:sys_enter_listmount` / `sys_exit_listmount` - 列出挂载点

#### 扩展属性
- `tracepoint:syscalls:sys_enter_getxattr` / `sys_exit_getxattr` - 获取扩展属性
- `tracepoint:syscalls:sys_enter_lgetxattr` / `sys_exit_lgetxattr` - 获取链接扩展属性
- `tracepoint:syscalls:sys_enter_fgetxattr` / `sys_exit_fgetxattr` - 通过 fd 获取扩展属性
- `tracepoint:syscalls:sys_enter_setxattr` / `sys_exit_setxattr` - 设置扩展属性
- `tracepoint:syscalls:sys_enter_lsetxattr` / `sys_exit_lsetxattr` - 设置链接扩展属性
- `tracepoint:syscalls:sys_enter_fsetxattr` / `sys_exit_fsetxattr` - 通过 fd 设置扩展属性
- `tracepoint:syscalls:sys_enter_listxattr` / `sys_exit_listxattr` - 列出扩展属性
- `tracepoint:syscalls:sys_enter_llistxattr` / `sys_exit_llistxattr` - 列出链接扩展属性
- `tracepoint:syscalls:sys_enter_flistxattr` / `sys_exit_flistxattr` - 通过 fd 列出扩展属性
- `tracepoint:syscalls:sys_enter_removexattr` / `sys_exit_removexattr` - 移除扩展属性
- `tracepoint:syscalls:sys_enter_lremovexattr` / `sys_exit_lremovexattr` - 移除链接扩展属性
- `tracepoint:syscalls:sys_enter_fremovexattr` / `sys_exit_fremovexattr` - 通过 fd 移除扩展属性

#### 文件描述符操作
- `tracepoint:syscalls:sys_enter_pipe` / `sys_exit_pipe` - 创建管道
- `tracepoint:syscalls:sys_enter_pipe2` / `sys_exit_pipe2` - 创建管道（带标志）
- `tracepoint:syscalls:sys_enter_select` / `sys_exit_select` - I/O 多路复用（select）
- `tracepoint:syscalls:sys_enter_pselect6` / `sys_exit_pselect6` - I/O 多路复用（pselect6）
- `tracepoint:syscalls:sys_enter_poll` / `sys_exit_poll` - I/O 多路复用（poll）
- `tracepoint:syscalls:sys_enter_ppoll` / `sys_exit_ppoll` - I/O 多路复用（ppoll）
- `tracepoint:syscalls:sys_enter_epoll_create` / `sys_exit_epoll_create` - 创建 epoll 实例
- `tracepoint:syscalls:sys_enter_epoll_create1` / `sys_exit_epoll_create1` - 创建 epoll 实例（带标志）
- `tracepoint:syscalls:sys_enter_epoll_ctl` / `sys_exit_epoll_ctl` - 控制 epoll
- `tracepoint:syscalls:sys_enter_epoll_wait` / `sys_exit_epoll_wait` - 等待 epoll 事件
- `tracepoint:syscalls:sys_enter_epoll_pwait` / `sys_exit_epoll_pwait` - 等待 epoll 事件（带信号掩码）
- `tracepoint:syscalls:sys_enter_epoll_pwait2` / `sys_exit_epoll_pwait2` - 等待 epoll 事件 v2

### 2. 进程相关 tracepoint（VFS 文件执行）

- `tracepoint:sched:sched_process_exec` - 进程执行（exec）操作
- `tracepoint:sched:sched_process_fork` - 进程创建（fork）
- `tracepoint:sched:sched_process_exit` - 进程退出
- `tracepoint:sched:sched_process_wait` - 进程等待

### 3. VFS 层的间接追踪点

虽然没有直接的 `vfs:` tracepoint，但以下 tracepoint 在 VFS 层操作：

#### 原始系统调用入口
- `tracepoint:raw_syscalls:sys_enter` - 系统调用进入
- `tracepoint:raw_syscalls:sys_exit` - 系统调用退出

#### 文件描述符传递
- `tracepoint:syscalls:sys_enter_sendmsg` / `sys_exit_sendmsg` - 发送消息（可传递 fd）
- `tracepoint:syscalls:sys_enter_recvmsg` / `sys_exit_recvmsg` - 接收消息（可接收 fd）

### 4. 使用 kprobe/kretprobe 追踪 VFS 函数

当 tracepoint 不够用时，可以使用 kprobe 直接追踪 VFS 内部函数：

```rust
// VFS 核心函数（需要使用 kprobe）
// vfs_open
// vfs_read
// vfs_write
// vfs_fsync
// vfs_unlink
// vfs_mkdir
// vfs_rmdir
// vfs_symlink
// vfs_link
// vfs_rename
// vfs_create
// do_filp_open
// path_openat
```

### VFS 层追踪建议

#### 追踪文件打开
- 使用 `sys_enter_openat` / `sys_exit_openat` - 现代推荐方式
- 配合 `filemap:mm_filemap_add_to_page_cache` 追踪页面缓存

#### 追踪文件读写
- 使用 `sys_enter_read` / `sys_exit_read` 和 `sys_enter_write` / `sys_exit_write`
- 配合 `ext4:ext4_read_folio` / `ext4:ext4_write_end` 追踪具体文件系统

#### 追踪文件属性变化
- 使用 `sys_enter_chmod` / `sys_enter_chown` / `sys_enter_utimensat`
- 配合 `ext4:ext4_mark_inode_dirty` 追踪元数据变化

#### 追踪文件系统挂载
- 使用 `sys_enter_mount` / `sys_enter_fsopen` / `sys_enter_fsmount`

---

### 分配相关
- `tracepoint:ext4:ext4_alloc_da_blocks` - 延迟分配块
- `tracepoint:ext4:ext4_allocate_blocks` - 分配块
- `tracepoint:ext4:ext4_allocate_inode` - 分配 inode

### 延迟分配相关
- `tracepoint:ext4:ext4_da_release_space` - 释放延迟分配空间
- `tracepoint:ext4:ext4_da_reserve_space` - 保留延迟分配空间
- `tracepoint:ext4:ext4_da_update_reserve_space` - 更新保留空间
- `tracepoint:ext4:ext4_da_write_begin` - 延迟写入开始
- `tracepoint:ext4:ext4_da_write_end` - 延迟写入结束
- `tracepoint:ext4:ext4_da_write_pages` - 延迟写入页面
- `tracepoint:ext4:ext4_da_write_pages_extent` - 延迟写入范围

### Extent 状态树
- `tracepoint:ext4:ext4_es_cache_extent` - 缓存 extent
- `tracepoint:ext4:ext4_es_find_extent_range_enter` - 查找 extent 范围进入
- `tracepoint:ext4:ext4_es_find_extent_range_exit` - 查找 extent 范围退出
- `tracepoint:ext4:ext4_es_insert_delayed_block` - 插入延迟块
- `tracepoint:ext4:ext4_es_insert_extent` - 插入 extent
- `tracepoint:ext4:ext4_es_lookup_extent_enter` - 查找 extent 进入
- `tracepoint:ext4:ext4_es_lookup_extent_exit` - 查找 extent 退出
- `tracepoint:ext4:ext4_es_remove_extent` - 移除 extent
- `tracepoint:ext4:ext4_es_shrink` - 缩小 extent 状态树
- `tracepoint:ext4:ext4_es_shrink_count` - 统计 shrink 计数
- `tracepoint:ext4:ext4_es_shrink_scan_enter` - shrink 扫描进入
- `tracepoint:ext4:ext4_es_shrink_scan_exit` - shrink 扫描退出

### Extent 操作
- `tracepoint:ext4:ext4_ext_convert_to_initialized_enter` - 转换为已初始化进入
- `tracepoint:ext4:ext4_ext_convert_to_initialized_fastpath` - 转换为已初始化快速路径
- `tracepoint:ext4:ext4_ext_handle_unwritten_extents` - 处理未写入的 extents
- `tracepoint:ext4:ext4_ext_load_extent` - 加载 extent
- `tracepoint:ext4:ext4_ext_map_blocks_enter` - 映射块进入
- `tracepoint:ext4:ext4_ext_map_blocks_exit` - 映射块退出
- `tracepoint:ext4:ext4_ext_remove_space` - 移除空间
- `tracepoint:ext4:ext4_ext_remove_space_done` - 移除空间完成
- `tracepoint:ext4:ext4_ext_rm_idx` - 移除索引
- `tracepoint:ext4:ext4_ext_rm_leaf` - 移除叶子节点
- `tracepoint:ext4:ext4_ext_show_extent` - 显示 extent

### 块操作
- `tracepoint:ext4:ext4_free_blocks` - 释放块
- `tracepoint:ext4:ext4_forget` - 忘记（释放）块
- `tracepoint:ext4:ext4_remove_blocks` - 移除块
- `tracepoint:ext4:ext4_request_blocks` - 请求块
- `tracepoint:ext4:ext4_discard_blocks` - 丢弃块

### Inode 操作
- `tracepoint:ext4:ext4_free_inode` - 释放 inode
- `tracepoint:ext4:ext4_drop_inode` - 丢弃 inode
- `tracepoint:ext4:ext4_load_inode` - 加载 inode
- `tracepoint:ext4:ext4_mark_inode_dirty` - 标记 inode 为脏
- `tracepoint:ext4:ext4_evict_inode` - 驱逐 inode

### 块分配器 (MB Allocator)
- `tracepoint:ext4:ext4_mb_bitmap_load` - 加载位图
- `tracepoint:ext4:ext4_mb_buddy_bitmap_load` - 加载 buddy 位图
- `tracepoint:ext4:ext4_mb_discard_preallocations` - 丢弃预分配
- `tracepoint:ext4:ext4_mb_new_group_pa` - 新建组预分配
- `tracepoint:ext4:ext4_mb_new_inode_pa` - 新建 inode 预分配
- `tracepoint:ext4:ext4_mb_release_group_pa` - 释放组预分配
- `tracepoint:ext4:ext4_mb_release_inode_pa` - 释放 inode 预分配
- `tracepoint:ext4:ext4_mballoc_alloc` - 多块分配分配
- `tracepoint:ext4:ext4_mballoc_discard` - 多块分配丢弃
- `tracepoint:ext4:ext4_mballoc_free` - 多块分配释放
- `tracepoint:ext4:ext4_mballoc_prealloc` - 多块分配预分配

### 文件操作
- `tracepoint:ext4:ext4_fallocate_enter` - fallocate 进入
- `tracepoint:ext4:ext4_fallocate_exit` - fallocate 退出
- `tracepoint:ext4:ext4_punch_hole` - 打孔
- `tracepoint:ext4:ext4_collapse_range` - 折叠范围
- `tracepoint:ext4:ext4_insert_range` - 插入范围
- `tracepoint:ext4:ext4_zero_range` - 零化范围
- `tracepoint:ext4:ext4_truncate_enter` - 截断进入
- `tracepoint:ext4:ext4_truncate_exit` - 截断退出
- `tracepoint:ext4:ext4_unlink_enter` - unlink 进入
- `tracepoint:ext4:ext4_unlink_exit` - unlink 退出
- `tracepoint:ext4:ext4_begin_ordered_truncate` - 开始有序截断

### 读写操作
- `tracepoint:ext4:ext4_write_begin` - 写入开始
- `tracepoint:ext4:ext4_write_end` - 写入结束
- `tracepoint:ext4:ext4_writepages` - 写入页面
- `tracepoint:ext4:ext4_writepages_result` - 写入页面结果
- `tracepoint:ext4:ext4_read_folio` - 读取 folio
- `tracepoint:ext4:ext4_invalidate_folio` - 使 folio 无效
- `tracepoint:ext4:ext4_journalled_invalidate_folio` - 日志模式使 folio 无效
- `tracepoint:ext4:ext4_journalled_write_end` - 日志模式写入结束
- `tracepoint:ext4:ext4_release_folio` - 释放 folio

### 同步与元数据
- `tracepoint:ext4:ext4_sync_file_enter` - 同步文件进入
- `tracepoint:ext4:ext4_sync_file_exit` - 同步文件退出
- `tracepoint:ext4:ext4_sync_fs` - 同步文件系统
- `tracepoint:ext4:ext4_update_sb` - 更新超级块
- `tracepoint:ext4:ext4_nfs_commit_metadata` - NFS 提交元数据
- `tracepoint:ext4:ext4_other_inode_update_time` - 更新其他 inode 时间

### 日志与快照
- `tracepoint:ext4:ext4_journal_start_inode` - inode 日志开始
- `tracepoint:ext4:ext4_journal_start_reserved` - 预留日志开始
- `tracepoint:ext4:ext4_journal_start_sb` - 超级块日志开始
- `tracepoint:ext4:ext4_error` - EXT4 错误
- `tracepoint:ext4:ext4_shutdown` - EXT4 关闭
- `tracepoint:ext4:ext4_lazy_itable_init` - 延迟 inode 表初始化
- `tracepoint:ext4:ext4_load_inode_bitmap` - 加载 inode 位图
- `tracepoint:ext4:ext4_read_block_bitmap_load` - 读取块位图
- `tracepoint:ext4:ext4_prefetch_bitmaps` - 预取位图

### Trim 操作
- `tracepoint:ext4:ext4_trim_all_free` - trim 所有空闲空间
- `tracepoint:ext4:ext4_trim_extent` - trim 范围

### Fast Commit
- `tracepoint:ext4:ext4_fc_cleanup` - fast commit 清理
- `tracepoint:ext4:ext4_fc_commit_start` - fast commit 开始
- `tracepoint:ext4:ext4_fc_commit_stop` - fast commit 停止
- `tracepoint:ext4:ext4_fc_replay` - fast commit 重放
- `tracepoint:ext4:ext4_fc_replay_scan` - fast commit 重放扫描
- `tracepoint:ext4:ext4_fc_stats` - fast commit 统计
- `tracepoint:ext4:ext4_fc_track_create` - 跟踪创建
- `tracepoint:ext4:ext4_fc_track_inode` - 跟踪 inode
- `tracepoint:ext4:ext4_fc_track_link` - 跟踪链接
- `tracepoint:ext4:ext4_fc_track_range` - 跟踪范围
- `tracepoint:ext4:ext4_fc_track_unlink` - 跟踪 unlink

### FSMap
- `tracepoint:ext4:ext4_fsmap_high_key` - fsmap 高键
- `tracepoint:ext4:ext4_fsmap_low_key` - fsmap 低键
- `tracepoint:ext4:ext4_fsmap_mapping` - fsmap 映射
- `tracepoint:ext4:ext4_getfsmap_high_key` - getfsmap 高键
- `tracepoint:ext4:ext4_getfsmap_low_key` - getfsmap 低键
- `tracepoint:ext4:ext4_getfsmap_mapping` - getfsmap 映射

### 间接块映射
- `tracepoint:ext4:ext4_ind_map_blocks_enter` - 间接块映射进入
- `tracepoint:ext4:ext4_ind_map_blocks_exit` - 间接块映射退出
- `tracepoint:ext4:ext4_get_implied_cluster_alloc_exit` - 获取隐含集群分配退出

---

## 文件映射

### 页面缓存操作
- `tracepoint:filemap:mm_filemap_add_to_page_cache` - 添加到页面缓存
- `tracepoint:filemap:mm_filemap_delete_from_page_cache` - 从页面缓存删除

### 错误处理
- `tracepoint:filemap:file_check_and_advance_wb_err` - 检查并推进写回错误
- `tracepoint:filemap:filemap_set_wb_err` - 设置写回错误

---

## 文件锁

### Lease 操作
- `tracepoint:filelock:break_lease_block` - 阻塞断开 lease
- `tracepoint:filelock:break_lease_noblock` - 非阻塞断开 lease
- `tracepoint:filelock:break_lease_unblock` - 解除断开 lease 阻塞
- `tracepoint:filelock:generic_add_lease` - 添加 lease
- `tracepoint:filelock:generic_delete_lease` - 删除 lease
- `tracepoint:filelock:leases_conflict` - lease 冲突
- `tracepoint:filelock:time_out_leases` - lease 超时

### POSIX 锁
- `tracepoint:filelock:fcntl_setlk` - fcntl 设置锁
- `tracepoint:filelock:flock_lock_inode` - flock 锁定 inode
- `tracepoint:filelock:posix_lock_inode` - POSIX 锁定 inode
- `tracepoint:filelock:locks_remove_posix` - 移除 POSIX 锁

### 锁上下文
- `tracepoint:filelock:locks_get_lock_context` - 获取锁上下文

---

## 写回操作

### 写回控制
- `tracepoint:writeback:writeback_start` - 写回开始
- `tracepoint:writeback:writeback_wait` - 等待写回
- `tracepoint:writeback:writeback_written` - 写回完成
- `tracepoint:writeback:writeback_exec` - 执行写回
- `tracepoint:writeback:writeback_queue` - 队列写回
- `tracepoint:writeback:writeback_queue_io` - 队列 IO 写回
- `tracepoint:writeback:writeback_wake_background` - 唤醒后台写回

### Inode 写回
- `tracepoint:writeback:writeback_dirty_inode` - inode 脏标记
- `tracepoint:writeback:writeback_dirty_inode_start` - inode 脏标记开始
- `tracepoint:writeback:writeback_dirty_inode_enqueue` - 入队脏 inode
- `tracepoint:writeback:writeback_mark_inode_dirty` - 标记 inode 为脏
- `tracepoint:writeback:writeback_single_inode` - 单 inode 写回
- `tracepoint:writeback:writeback_single_inode_start` - 单 inode 写回开始
- `tracepoint:writeback:writeback_write_inode` - 写入 inode
- `tracepoint:writeback:writeback_write_inode_start` - 写入 inode 开始

### Folio/Pages 写回
- `tracepoint:writeback:writeback_dirty_folio` - folio 脏标记
- `tracepoint:writeback:wbc_writepage` - 写回控制写入页面
- `tracepoint:writeback:folio_wait_writeback` - 等待 folio 写回
- `tracepoint:writeback:writeback_pages_written` - 写回页面数

### BDI (Backing Device Info)
- `tracepoint:writeback:writeback_bdi_register` - 注册 BDI
- `tracepoint:writeback:bdi_dirty_ratelimit` - BDI 脏速率限制
- `tracepoint:writeback:balance_dirty_pages` - 平衡脏页面
- `tracepoint:writeback:global_dirty_state` - 全局脏状态

### Lazytime
- `tracepoint:writeback:writeback_lazytime` - lazytime 写回
- `tracepoint:writeback:writeback_lazytime_iput` - lazytime iput

### 超级块
- `tracepoint:writeback:sb_mark_inode_writeback` - 超级块标记 inode 写回
- `tracepoint:writeback:sb_clear_inode_writeback` - 超级块清除 inode 写回

### 外部回写
- `tracepoint:writeback:inode_switch_wbs` - inode 切换写回后台
- `tracepoint:writeback:inode_foreign_history` - inode 外部历史
- `tracepoint:writeback:track_foreign_dirty` - 跟踪外部脏
- `tracepoint:writeback:flush_foreign` - 刷新外部

### Requeue
- `tracepoint:writeback:writeback_sb_inodes_requeue` - 超级块 inodes 重新入队

---

## JBD2 日志层 (EXT4 日志)

### 事务操作
- `tracepoint:jbd2:jbd2_start_commit` - 开始提交
- `tracepoint:jbd2:jbd2_commit_locking` - 提交锁定
- `tracepoint:jbd2:jbd2_commit_flushing` - 提交刷新
- `tracepoint:jbd2:jbd2_commit_logging` - 提交日志
- `tracepoint:jbd2:jbd2_end_commit` - 结束提交
- `tracepoint:jbd2:jbd2_drop_transaction` - 丢弃事务
- `tracepoint:jbd2:jbd2_checkpoint` - 检查点
- `tracepoint:jbd2:jbd2_submit_inode_data` - 提交 inode 数据

### Handle 操作
- `tracepoint:jbd2:jbd2_handle_start` - handle 开始
- `tracepoint:jbd2:jbd2_handle_extend` - handle 扩展
- `tracepoint:jbd2:jbd2_handle_restart` - handle 重启
- `tracepoint:jbd2:jbd2_handle_stats` - handle 统计
- `tracepoint:jbd2:jbd2_lock_buffer_stall` - 锁定缓冲区停滞

### 超级块与日志尾部
- `tracepoint:jbd2:jbd2_update_log_tail` - 更新日志尾部
- `tracepoint:jbd2:jbd2_write_superblock` - 写入超级块

### 统计信息
- `tracepoint:jbd2:jbd2_run_stats` - 运行统计
- `tracepoint:jbd2:jbd2_checkpoint_stats` - 检查点统计

### Shrink 操作
- `tracepoint:jbd2:jbd2_shrink_scan_enter` - shrink 扫描进入
- `tracepoint:jbd2:jbd2_shrink_scan_exit` - shrink 扫描退出
- `tracepoint:jbd2:jbd2_shrink_count` - shrink 计数
- `tracepoint:jbd2:jbd2_shrink_checkpoint_list` - shrink 检查点列表

---

## 内存映射

### VMA 操作
- `tracepoint:mmap:vma_store` - 存储 VMA
- `tracepoint:mmap:vma_mas_szero` - VMA 零化搜索

### 映射操作
- `tracepoint:mmap:vm_unmapped_area` - 未映射区域
- `tracepoint:mmap:exit_mmap` - 退出内存映射

### Mmap Lock
- `tracepoint:mmap_lock:mmap_lock_acquire_returned` - 获取 mmap 锁返回
- `tracepoint:mmap_lock:mmap_lock_released` - 释放 mmap 锁
- `tracepoint:mmap_lock:mmap_lock_start_locking` - 开始锁定 mmap

---

## DAX 文件系统

### DAX 故障处理
- `tracepoint:fs_dax:dax_pte_fault` - DAX 页�表项故障
- `tracepoint:fs_dax:dax_pte_fault_done` - DAX 页表项故障完成
- `tracepoint:fs_dax:dax_pmd_fault` - DAX PMD 故障
- `tracepoint:fs_dax:dax_pmd_fault_done` - DAX PMD 故障完成
- `tracepoint:fs_dax:dax_load_hole` - DAX 加载空洞
- `tracepoint:fs_dax:dax_pmd_load_hole` - DAX PMD 加载空洞
- `tracepoint:fs_dax:dax_pmd_load_hole_fallback` - DAX PMD 加载空洞回退

### DAX 映射操作
- `tracepoint:fs_dax:dax_insert_mapping` - DAX 插入映射
- `tracepoint:fs_dax:dax_insert_pfn_mkwrite` - DAX 插入 PFN mkwrite
- `tracepoint:fs_dax:dax_insert_pfn_mkwrite_no_entry` - DAX 插入 PFN mkwrite 无条目
- `tracepoint:fs_dax:dax_pmd_insert_mapping` - DAX PMD 插入映射

### DAX 写回
- `tracepoint:fs_dax:dax_writeback_range` - DAX 写回范围
- `tracepoint:fs_dax:dax_writeback_range_done` - DAX 写回范围完成
- `tracepoint:fs_dax:dax_writeback_one` - DAX 写回一个

---

## IOMAP (通用映射操作)

- `tracepoint:iomap:iomap_iter` - iomap 迭代
- `tracepoint:iomap:iomap_iter_srcmap` - iomap 迭代源映射
- `tracepoint:iomap:iomap_iter_dstmap` - iomap 迭代目标映射
- `tracepoint:iomap:iomap_writepage` - iomap 写入页面
- `tracepoint:iomap:iomap_writepage_map` - iomap 写入页面映射
- `tracepoint:iomap:iomap_readpage` - iomap 读取页面
- `tracepoint:iomap:iomap_readahead` - iomap 预读
- `tracepoint:iomap:iomap_invalidate_folio` - iomap 使 folio 无效
- `tracepoint:iomap:iomap_release_folio` - iomap 释放 folio
- `tracepoint:iomap:iomap_dio_rw_begin` - DIO 读写开始
- `tracepoint:iomap:iomap_dio_rw_queued` - DIO 读写队列
- `tracepoint:iomap:iomap_dio_complete` - DIO 完成
- `tracepoint:iomap:iomap_dio_invalidate_fail` - DIO 使失败

---

## 使用建议

### 追踪文件读写
推荐使用的 tracepoint：
- `ext4:ext4_write_begin` / `ext4:ext4_write_end` - 监控写入操作
- `ext4:ext4_read_folio` - 监控读取操作
- `filemap:mm_filemap_add_to_page_cache` - 监控页面缓存添加

### 追踪延迟分配
推荐使用的 tracepoint：
- `ext4:ext4_da_write_begin` / `ext4:ext4_da_write_end`
- `ext4:ext4_mballoc_alloc` - 监控块分配

### 追踪元数据操作
推荐使用的 tracepoint：
- `ext4:ext4_mark_inode_dirty` - inode 变脏
- `ext4:ext4_sync_file_enter` / `ext4:ext4_sync_file_exit` - 文件同步
- `writeback:writeback_start` / `writeback:writeback_written` - 写回操作

### 追踪日志操作
推荐使用的 tracepoint：
- `jbd2:jbd2_start_commit` / `jbd2:jbd2_end_commit`
- `jbd2:jbd2_handle_start` / `jbd2:jbd2_handle_stats`

### 追踪文件锁
推荐使用的 tracepoint：
- `filelock:posix_lock_inode`
- `filelock:generic_add_lease`
- `filelock:break_lease_block`

---

## 示例 eBPF 程序结构

```rust
// 使用 aya-rs 挂载文件系统 tracepoint
use aya_ebpf::{programs::TracePoint, PtRegs};

// 追踪 ext4 写入操作
#[tracepoint(name = "ext4:ext4_write_end")]
pub fn ext4_write_end(ctx: TracePoint) {
    // 提取文件名、大小、延迟等信息
}

// 追踪页面缓存操作
#[tracepoint(name = "filemap:mm_filemap_add_to_page_cache")]
pub fn page_cache_add(ctx: TracePoint) {
    // 提取 inode、页面索引等信息
}

// 追踪写回操作
#[tracepoint(name = "writeback:writeback_start")]
pub fn writeback_start(ctx: TracePoint) {
    // 提取设备、写入范围等信息
}
```

---

## 相关系统调用追踪

除了文件系统 tracepoint，还可以追踪相关的系统调用：

- `sys_enter_open` / `sys_enter_openat` - 打开文件
- `sys_enter_read` / `sys_enter_write` - 读写文件
- `sys_enter_stat` / `sys_enter_fstat` / `sys_enter_newfstatat` - 获取文件状态
- `sys_enter_readlink` / `sys_enter_readlinkat` - 读取符号链接
- `sys_enter_link` / `sys_enter_linkat` / `sys_enter_unlink` / `sys_enter_unlinkat` - 链接操作
- `sys_enter_rename` / `sys_enter_renameat` - 重命名
- `sys_enter_mkdir` / `sys_enter_mkdirat` / `sys_enter_rmdir` - 目录操作
- `sys_enter_fsync` - 文件同步
- `sys_enter_sync` / `sys_enter_syncfs` - 文件系统同步
