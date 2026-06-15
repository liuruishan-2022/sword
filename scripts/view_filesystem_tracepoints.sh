#!/bin/bash

# 查看所有文件系统相关 tracepoint 的格式

echo "=========================================="
echo "文件状态与属性"
echo "=========================================="

for tp in stat fstat lstat newfstatat statx chmod fchmod fchmodat chown fchown fchownat lchown utime utimensat futimesat; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "目录操作"
echo "=========================================="

for tp in mkdir mkdirat rmdir getdents getdents64; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "链接操作"
echo "=========================================="

for tp in link linkat unlink unlinkat symlink symlinkat readlink readlinkat; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "文件重命名与移动"
echo "=========================================="

for tp in rename renameat renameat2; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "文件截断与分配"
echo "=========================================="

for tp in truncate ftruncate fallocate; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "文件同步"
echo "=========================================="

for tp in fsync fdatasync sync syncfs sync_file_range; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "文件系统挂载"
echo "=========================================="

for tp in mount mount_setattr move_mount umount pivot_root fsopen fspick fsconfig fsmount open_tree statfs fstatfs statmount listmount; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "扩展属性"
echo "=========================================="

for tp in getxattr lgetxattr fgetxattr setxattr lsetxattr fsetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "文件描述符操作"
echo "=========================================="

for tp in pipe pipe2 select pselect6 poll ppoll epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2; do
    for dir in enter exit; do
        echo ">>> sys_${dir}_${tp}"
        sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_${dir}_${tp}/format 2>/dev/null || echo "  Tracepoint not found"
        echo ""
    done
done

echo "=========================================="
echo "完成！"
echo "=========================================="
