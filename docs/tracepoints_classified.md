# Linux Tracepoints 功能分类

总计: 2058 个 tracepoints
已分类: 2058 个
未分类: 0 个

## 功能分类统计

### 系统调用: 714 个 tracepoints

#### raw_syscalls (2 个)

- raw_syscalls:sys_enter
- raw_syscalls:sys_exit

#### syscalls (712 个)

- syscalls:sys_enter_accept
- syscalls:sys_enter_accept4
- syscalls:sys_enter_access
- syscalls:sys_enter_acct
- syscalls:sys_enter_add_key
- syscalls:sys_enter_adjtimex
- syscalls:sys_enter_alarm
- syscalls:sys_enter_arch_prctl
- syscalls:sys_enter_bind
- syscalls:sys_enter_bpf
- syscalls:sys_enter_brk
- syscalls:sys_enter_cachestat
- syscalls:sys_enter_capget
- syscalls:sys_enter_capset
- syscalls:sys_enter_chdir
- syscalls:sys_enter_chmod
- syscalls:sys_enter_chown
- syscalls:sys_enter_chroot
- syscalls:sys_enter_clock_adjtime
- syscalls:sys_enter_clock_getres
- ... 还有 692 个

### 文件系统: 209 个 tracepoints

#### ext4 (113 个)

- ext4:ext4_alloc_da_blocks
- ext4:ext4_allocate_blocks
- ext4:ext4_allocate_inode
- ext4:ext4_begin_ordered_truncate
- ext4:ext4_collapse_range
- ext4:ext4_da_release_space
- ext4:ext4_da_reserve_space
- ext4:ext4_da_update_reserve_space
- ext4:ext4_da_write_begin
- ext4:ext4_da_write_end
- ext4:ext4_da_write_pages
- ext4:ext4_da_write_pages_extent
- ext4:ext4_discard_blocks
- ext4:ext4_discard_preallocations
- ext4:ext4_drop_inode
- ext4:ext4_error
- ext4:ext4_es_cache_extent
- ext4:ext4_es_find_extent_range_enter
- ext4:ext4_es_find_extent_range_exit
- ext4:ext4_es_insert_delayed_block
- ... 还有 93 个

#### filelock (12 个)

- filelock:break_lease_block
- filelock:break_lease_noblock
- filelock:break_lease_unblock
- filelock:fcntl_setlk
- filelock:flock_lock_inode
- filelock:generic_add_lease
- filelock:generic_delete_lease
- filelock:leases_conflict
- filelock:locks_get_lock_context
- filelock:locks_remove_posix
- filelock:posix_lock_inode
- filelock:time_out_leases

#### filemap (4 个)

- filemap:file_check_and_advance_wb_err
- filemap:filemap_set_wb_err
- filemap:mm_filemap_add_to_page_cache
- filemap:mm_filemap_delete_from_page_cache

#### fs_dax (14 个)

- fs_dax:dax_insert_mapping
- fs_dax:dax_insert_pfn_mkwrite
- fs_dax:dax_insert_pfn_mkwrite_no_entry
- fs_dax:dax_load_hole
- fs_dax:dax_pmd_fault
- fs_dax:dax_pmd_fault_done
- fs_dax:dax_pmd_insert_mapping
- fs_dax:dax_pmd_load_hole
- fs_dax:dax_pmd_load_hole_fallback
- fs_dax:dax_pte_fault
- fs_dax:dax_pte_fault_done
- fs_dax:dax_writeback_one
- fs_dax:dax_writeback_range
- fs_dax:dax_writeback_range_done

#### iomap (13 个)

- iomap:iomap_dio_complete
- iomap:iomap_dio_invalidate_fail
- iomap:iomap_dio_rw_begin
- iomap:iomap_dio_rw_queued
- iomap:iomap_invalidate_folio
- iomap:iomap_iter
- iomap:iomap_iter_dstmap
- iomap:iomap_iter_srcmap
- iomap:iomap_readahead
- iomap:iomap_readpage
- iomap:iomap_release_folio
- iomap:iomap_writepage
- iomap:iomap_writepage_map

#### jbd2 (21 个)

- jbd2:jbd2_checkpoint
- jbd2:jbd2_checkpoint_stats
- jbd2:jbd2_commit_flushing
- jbd2:jbd2_commit_locking
- jbd2:jbd2_commit_logging
- jbd2:jbd2_drop_transaction
- jbd2:jbd2_end_commit
- jbd2:jbd2_handle_extend
- jbd2:jbd2_handle_restart
- jbd2:jbd2_handle_start
- jbd2:jbd2_handle_stats
- jbd2:jbd2_lock_buffer_stall
- jbd2:jbd2_run_stats
- jbd2:jbd2_shrink_checkpoint_list
- jbd2:jbd2_shrink_count
- jbd2:jbd2_shrink_scan_enter
- jbd2:jbd2_shrink_scan_exit
- jbd2:jbd2_start_commit
- jbd2:jbd2_submit_inode_data
- jbd2:jbd2_update_log_tail
- ... 还有 1 个

#### writeback (32 个)

- writeback:balance_dirty_pages
- writeback:bdi_dirty_ratelimit
- writeback:flush_foreign
- writeback:folio_wait_writeback
- writeback:global_dirty_state
- writeback:inode_foreign_history
- writeback:inode_switch_wbs
- writeback:sb_clear_inode_writeback
- writeback:sb_mark_inode_writeback
- writeback:track_foreign_dirty
- writeback:wbc_writepage
- writeback:writeback_bdi_register
- writeback:writeback_dirty_folio
- writeback:writeback_dirty_inode
- writeback:writeback_dirty_inode_enqueue
- writeback:writeback_dirty_inode_start
- writeback:writeback_exec
- writeback:writeback_lazytime
- writeback:writeback_lazytime_iput
- writeback:writeback_mark_inode_dirty
- ... 还有 12 个

### 内核功能: 143 个 tracepoints

#### amd_cpu (1 个)

- amd_cpu:amd_pstate_perf

#### dev (1 个)

- dev:devres_log

#### devlink (6 个)

- devlink:devlink_health_recover_aborted
- devlink:devlink_health_report
- devlink:devlink_health_reporter_state_update
- devlink:devlink_hwerr
- devlink:devlink_hwmsg
- devlink:devlink_trap_report

#### dma_fence (7 个)

- dma_fence:dma_fence_destroy
- dma_fence:dma_fence_emit
- dma_fence:dma_fence_enable_signal
- dma_fence:dma_fence_init
- dma_fence:dma_fence_signaled
- dma_fence:dma_fence_wait_end
- dma_fence:dma_fence_wait_start

#### error_report (1 个)

- error_report:error_report_end

#### hwmon (3 个)

- hwmon:hwmon_attr_show
- hwmon:hwmon_attr_show_string
- hwmon:hwmon_attr_store

#### interconnect (2 个)

- interconnect:icc_set_bw
- interconnect:icc_set_bw_end

#### mce (1 个)

- mce:mce_record

#### mctp (2 个)

- mctp:mctp_key_acquire
- mctp:mctp_key_release

#### mdio (1 个)

- mdio:mdio_access

#### mei (3 个)

- mei:mei_pci_cfg_read
- mei:mei_reg_read
- mei:mei_reg_write

#### msr (3 个)

- msr:rdpmc
- msr:read_msr
- msr:write_msr

#### netlink (1 个)

- netlink:netlink_extack

#### notifier (3 个)

- notifier:notifier_register
- notifier:notifier_run
- notifier:notifier_unregister

#### page_pool (4 个)

- page_pool:page_pool_release
- page_pool:page_pool_state_hold
- page_pool:page_pool_state_release
- page_pool:page_pool_update_nid

#### printk (1 个)

- printk:console

#### qdisc (5 个)

- qdisc:qdisc_create
- qdisc:qdisc_dequeue
- qdisc:qdisc_destroy
- qdisc:qdisc_enqueue
- qdisc:qdisc_reset

#### qrtr (4 个)

- qrtr:qrtr_ns_message
- qrtr:qrtr_ns_server_add
- qrtr:qrtr_ns_service_announce_del
- qrtr:qrtr_ns_service_announce_new

#### ras (6 个)

- ras:aer_event
- ras:arm_event
- ras:extlog_mem_event
- ras:mc_event
- ras:memory_failure_event
- ras:non_standard_event

#### regmap (17 个)

- regmap:regcache_drop_region
- regmap:regcache_sync
- regmap:regmap_async_complete_done
- regmap:regmap_async_complete_start
- regmap:regmap_async_io_complete
- regmap:regmap_async_write_start
- regmap:regmap_bulk_read
- regmap:regmap_bulk_write
- regmap:regmap_cache_bypass
- regmap:regmap_cache_only
- regmap:regmap_hw_read_done
- regmap:regmap_hw_read_start
- regmap:regmap_hw_write_done
- regmap:regmap_hw_write_start
- regmap:regmap_reg_read
- regmap:regmap_reg_read_cache
- regmap:regmap_reg_write

#### rseq (2 个)

- rseq:rseq_ip_fixup
- rseq:rseq_update

#### rv (2 个)

- rv:error_wwnr
- rv:event_wwnr

#### sync_trace (1 个)

- sync_trace:sync_timeline

#### vsyscall (1 个)

- vsyscall:emulate_vsyscall

#### watchdog (4 个)

- watchdog:watchdog_ping
- watchdog:watchdog_set_timeout
- watchdog:watchdog_start
- watchdog:watchdog_stop

#### wbt (4 个)

- wbt:wbt_lat
- wbt:wbt_stat
- wbt:wbt_step
- wbt:wbt_timer

#### workqueue (4 个)

- workqueue:workqueue_activate_work
- workqueue:workqueue_execute_end
- workqueue:workqueue_execute_start
- workqueue:workqueue_queue_work

#### xhci-hcd (53 个)

- xhci-hcd:xhci_add_endpoint
- xhci-hcd:xhci_address_ctrl_ctx
- xhci-hcd:xhci_address_ctx
- xhci-hcd:xhci_alloc_dev
- xhci-hcd:xhci_alloc_virt_device
- xhci-hcd:xhci_configure_endpoint
- xhci-hcd:xhci_configure_endpoint_ctrl_ctx
- xhci-hcd:xhci_dbc_alloc_request
- xhci-hcd:xhci_dbc_free_request
- xhci-hcd:xhci_dbc_gadget_ep_queue
- xhci-hcd:xhci_dbc_giveback_request
- xhci-hcd:xhci_dbc_handle_event
- xhci-hcd:xhci_dbc_handle_transfer
- xhci-hcd:xhci_dbc_queue_request
- xhci-hcd:xhci_dbg_address
- xhci-hcd:xhci_dbg_cancel_urb
- xhci-hcd:xhci_dbg_context_change
- xhci-hcd:xhci_dbg_init
- xhci-hcd:xhci_dbg_quirks
- xhci-hcd:xhci_dbg_reset_ep
- ... 还有 33 个

### 设备驱动: 142 个 tracepoints

#### drm (3 个)

- drm:drm_vblank_event
- drm:drm_vblank_event_delivered
- drm:drm_vblank_event_queued

#### gpu_scheduler (4 个)

- gpu_scheduler:drm_run_job
- gpu_scheduler:drm_sched_job
- gpu_scheduler:drm_sched_job_wait_dep
- gpu_scheduler:drm_sched_process_job

#### i915 (44 个)

- i915:g4x_wm
- i915:i915_context_create
- i915:i915_context_free
- i915:i915_gem_evict
- i915:i915_gem_evict_node
- i915:i915_gem_evict_vm
- i915:i915_gem_object_clflush
- i915:i915_gem_object_create
- i915:i915_gem_object_destroy
- i915:i915_gem_object_fault
- i915:i915_gem_object_pread
- i915:i915_gem_object_pwrite
- i915:i915_gem_shrink
- i915:i915_ppgtt_create
- i915:i915_ppgtt_release
- i915:i915_reg_rw
- i915:i915_request_add
- i915:i915_request_queue
- i915:i915_request_retire
- i915:i915_request_wait_begin
- ... 还有 24 个

#### x86_fpu (11 个)

- x86_fpu:x86_fpu_after_restore
- x86_fpu:x86_fpu_after_save
- x86_fpu:x86_fpu_before_restore
- x86_fpu:x86_fpu_before_save
- x86_fpu:x86_fpu_copy_dst
- x86_fpu:x86_fpu_copy_src
- x86_fpu:x86_fpu_dropped
- x86_fpu:x86_fpu_init_state
- x86_fpu:x86_fpu_regs_activated
- x86_fpu:x86_fpu_regs_deactivated
- x86_fpu:x86_fpu_xstate_check_failed

#### xdp (13 个)

- xdp:bpf_xdp_link_attach_failed
- xdp:mem_connect
- xdp:mem_disconnect
- xdp:mem_return_failed
- xdp:xdp_bulk_tx
- xdp:xdp_cpumap_enqueue
- xdp:xdp_cpumap_kthread
- xdp:xdp_devmap_xmit
- xdp:xdp_exception
- xdp:xdp_redirect
- xdp:xdp_redirect_err
- xdp:xdp_redirect_map
- xdp:xdp_redirect_map_err

#### xe (67 个)

- xe:xe_bo_cpu_fault
- xe:xe_bo_move
- xe:xe_exec_queue_cleanup_entity
- xe:xe_exec_queue_close
- xe:xe_exec_queue_create
- xe:xe_exec_queue_deregister
- xe:xe_exec_queue_deregister_done
- xe:xe_exec_queue_destroy
- xe:xe_exec_queue_kill
- xe:xe_exec_queue_lr_cleanup
- xe:xe_exec_queue_memory_cat_error
- xe:xe_exec_queue_register
- xe:xe_exec_queue_reset
- xe:xe_exec_queue_resubmit
- xe:xe_exec_queue_scheduling_disable
- xe:xe_exec_queue_scheduling_done
- xe:xe_exec_queue_scheduling_enable
- xe:xe_exec_queue_stop
- xe:xe_exec_queue_submit
- xe:xe_exec_queue_supress_resume
- ... 还有 47 个

### 虚拟化: 140 个 tracepoints

#### hyperv (5 个)

- hyperv:hyperv_mmu_flush_tlb_multi
- hyperv:hyperv_nested_flush_guest_mapping
- hyperv:hyperv_nested_flush_guest_mapping_range
- hyperv:hyperv_send_ipi_mask
- hyperv:hyperv_send_ipi_one

#### kvm (91 个)

- kvm:kvm_ack_irq
- kvm:kvm_age_hva
- kvm:kvm_apic
- kvm:kvm_apic_accept_irq
- kvm:kvm_apic_ipi
- kvm:kvm_apicv_accept_irq
- kvm:kvm_apicv_inhibit_changed
- kvm:kvm_async_pf_completed
- kvm:kvm_async_pf_not_present
- kvm:kvm_async_pf_ready
- kvm:kvm_async_pf_repeated_fault
- kvm:kvm_avic_doorbell
- kvm:kvm_avic_ga_log
- kvm:kvm_avic_incomplete_ipi
- kvm:kvm_avic_kick_vcpu_slowpath
- kvm:kvm_avic_unaccelerated_access
- kvm:kvm_cpuid
- kvm:kvm_cr
- kvm:kvm_dirty_ring_exit
- kvm:kvm_dirty_ring_push
- ... 还有 71 个

#### kvmmmu (18 个)

- kvmmmu:check_mmio_spte
- kvmmmu:fast_page_fault
- kvmmmu:handle_mmio_page_fault
- kvmmmu:kvm_mmu_get_page
- kvmmmu:kvm_mmu_pagetable_walk
- kvmmmu:kvm_mmu_paging_element
- kvmmmu:kvm_mmu_prepare_zap_page
- kvmmmu:kvm_mmu_set_accessed_bit
- kvmmmu:kvm_mmu_set_dirty_bit
- kvmmmu:kvm_mmu_set_spte
- kvmmmu:kvm_mmu_split_huge_page
- kvmmmu:kvm_mmu_spte_requested
- kvmmmu:kvm_mmu_sync_page
- kvmmmu:kvm_mmu_unsync_page
- kvmmmu:kvm_mmu_walker_error
- kvmmmu:kvm_mmu_zap_all_fast
- kvmmmu:kvm_tdp_mmu_spte_changed
- kvmmmu:mark_mmio_spte

#### xen (26 个)

- xen:xen_cpu_load_idt
- xen:xen_cpu_set_ldt
- xen:xen_cpu_write_gdt_entry
- xen:xen_cpu_write_idt_entry
- xen:xen_cpu_write_ldt_entry
- xen:xen_mc_batch
- xen:xen_mc_callback
- xen:xen_mc_entry
- xen:xen_mc_entry_alloc
- xen:xen_mc_extend_args
- xen:xen_mc_flush
- xen:xen_mc_flush_reason
- xen:xen_mc_issue
- xen:xen_mmu_alloc_ptpage
- xen:xen_mmu_flush_tlb_multi
- xen:xen_mmu_flush_tlb_one_user
- xen:xen_mmu_pgd_pin
- xen:xen_mmu_pgd_unpin
- xen:xen_mmu_ptep_modify_prot_commit
- xen:xen_mmu_ptep_modify_prot_start
- ... 还有 6 个

### 网络文件系统: 136 个 tracepoints

#### sunrpc (136 个)

- sunrpc:cache_entry_expired
- sunrpc:cache_entry_make_negative
- sunrpc:cache_entry_no_listener
- sunrpc:cache_entry_upcall
- sunrpc:cache_entry_update
- sunrpc:pmap_register
- sunrpc:rpc__auth_tooweak
- sunrpc:rpc__bad_creds
- sunrpc:rpc__garbage_args
- sunrpc:rpc__mismatch
- sunrpc:rpc__proc_unavail
- sunrpc:rpc__prog_mismatch
- sunrpc:rpc__prog_unavail
- sunrpc:rpc__stale_creds
- sunrpc:rpc__unparsable
- sunrpc:rpc_bad_callhdr
- sunrpc:rpc_bad_verifier
- sunrpc:rpc_buf_alloc
- sunrpc:rpc_call_rpcerror
- sunrpc:rpc_call_status
- ... 还有 116 个

### 内存管理: 88 个 tracepoints

#### compaction (15 个)

- compaction:mm_compaction_begin
- compaction:mm_compaction_defer_compaction
- compaction:mm_compaction_defer_reset
- compaction:mm_compaction_deferred
- compaction:mm_compaction_end
- compaction:mm_compaction_fast_isolate_freepages
- compaction:mm_compaction_finished
- compaction:mm_compaction_isolate_freepages
- compaction:mm_compaction_isolate_migratepages
- compaction:mm_compaction_kcompactd_sleep
- compaction:mm_compaction_kcompactd_wake
- compaction:mm_compaction_migratepages
- compaction:mm_compaction_suitable
- compaction:mm_compaction_try_to_compact_pages
- compaction:mm_compaction_wakeup_kcompactd

#### huge_memory (6 个)

- huge_memory:mm_collapse_huge_page
- huge_memory:mm_collapse_huge_page_isolate
- huge_memory:mm_collapse_huge_page_swapin
- huge_memory:mm_khugepaged_collapse_file
- huge_memory:mm_khugepaged_scan_file
- huge_memory:mm_khugepaged_scan_pmd

#### kmem (11 个)

- kmem:kfree
- kmem:kmalloc
- kmem:kmem_cache_alloc
- kmem:kmem_cache_free
- kmem:mm_page_alloc
- kmem:mm_page_alloc_extfrag
- kmem:mm_page_alloc_zone_locked
- kmem:mm_page_free
- kmem:mm_page_free_batched
- kmem:mm_page_pcpu_drain
- kmem:rss_stat

#### ksm (9 个)

- ksm:ksm_advisor
- ksm:ksm_enter
- ksm:ksm_exit
- ksm:ksm_merge_one_page
- ksm:ksm_merge_with_ksm_page
- ksm:ksm_remove_ksm_page
- ksm:ksm_remove_rmap_item
- ksm:ksm_start_scan
- ksm:ksm_stop_scan

#### maple_tree (3 个)

- maple_tree:ma_op
- maple_tree:ma_read
- maple_tree:ma_write

#### migrate (4 个)

- migrate:mm_migrate_pages
- migrate:mm_migrate_pages_start
- migrate:remove_migration_pte
- migrate:set_migration_pte

#### oom (8 个)

- oom:compact_retry
- oom:finish_task_reaping
- oom:mark_victim
- oom:oom_score_adj_update
- oom:reclaim_retry_zone
- oom:skip_task_reaping
- oom:start_task_reaping
- oom:wake_reaper

#### page_isolation (1 个)

- page_isolation:test_pages_isolated

#### pagemap (2 个)

- pagemap:mm_lru_activate
- pagemap:mm_lru_insertion

#### percpu (5 个)

- percpu:percpu_alloc_percpu
- percpu:percpu_alloc_percpu_fail
- percpu:percpu_create_chunk
- percpu:percpu_destroy_chunk
- percpu:percpu_free_percpu

#### thp (6 个)

- thp:hugepage_set_pmd
- thp:hugepage_set_pud
- thp:hugepage_update_pmd
- thp:hugepage_update_pud
- thp:remove_migration_pmd
- thp:set_migration_pmd

#### vmscan (18 个)

- vmscan:mm_shrink_slab_end
- vmscan:mm_shrink_slab_start
- vmscan:mm_vmscan_direct_reclaim_begin
- vmscan:mm_vmscan_direct_reclaim_end
- vmscan:mm_vmscan_kswapd_sleep
- vmscan:mm_vmscan_kswapd_wake
- vmscan:mm_vmscan_lru_isolate
- vmscan:mm_vmscan_lru_shrink_active
- vmscan:mm_vmscan_lru_shrink_inactive
- vmscan:mm_vmscan_memcg_reclaim_begin
- vmscan:mm_vmscan_memcg_reclaim_end
- vmscan:mm_vmscan_memcg_softlimit_reclaim_begin
- vmscan:mm_vmscan_memcg_softlimit_reclaim_end
- vmscan:mm_vmscan_node_reclaim_begin
- vmscan:mm_vmscan_node_reclaim_end
- vmscan:mm_vmscan_throttled
- vmscan:mm_vmscan_wakeup_kswapd
- vmscan:mm_vmscan_write_folio

### CPU和调度: 74 个 tracepoints

#### context_tracking (2 个)

- context_tracking:user_enter
- context_tracking:user_exit

#### cpuhp (3 个)

- cpuhp:cpuhp_enter
- cpuhp:cpuhp_exit
- cpuhp:cpuhp_multi_enter

#### cros_ec (2 个)

- cros_ec:cros_ec_request_done
- cros_ec:cros_ec_request_start

#### ipi (5 个)

- ipi:ipi_entry
- ipi:ipi_exit
- ipi:ipi_raise
- ipi:ipi_send_cpu
- ipi:ipi_send_cpumask

#### irq_vectors (34 个)

- irq_vectors:call_function_entry
- irq_vectors:call_function_exit
- irq_vectors:call_function_single_entry
- irq_vectors:call_function_single_exit
- irq_vectors:deferred_error_apic_entry
- irq_vectors:deferred_error_apic_exit
- irq_vectors:error_apic_entry
- irq_vectors:error_apic_exit
- irq_vectors:irq_work_entry
- irq_vectors:irq_work_exit
- irq_vectors:local_timer_entry
- irq_vectors:local_timer_exit
- irq_vectors:reschedule_entry
- irq_vectors:reschedule_exit
- irq_vectors:spurious_apic_entry
- irq_vectors:spurious_apic_exit
- irq_vectors:thermal_apic_entry
- irq_vectors:thermal_apic_exit
- irq_vectors:threshold_apic_entry
- irq_vectors:threshold_apic_exit
- ... 还有 14 个

#### sched (28 个)

- sched:sched_kthread_stop
- sched:sched_kthread_stop_ret
- sched:sched_kthread_work_execute_end
- sched:sched_kthread_work_execute_start
- sched:sched_kthread_work_queue_work
- sched:sched_migrate_task
- sched:sched_move_numa
- sched:sched_pi_setprio
- sched:sched_process_exec
- sched:sched_process_exit
- sched:sched_process_fork
- sched:sched_process_free
- sched:sched_process_hang
- sched:sched_process_wait
- sched:sched_skip_vma_numa
- sched:sched_stat_blocked
- sched:sched_stat_iowait
- sched:sched_stat_runtime
- sched:sched_stat_sleep
- sched:sched_stat_wait
- ... 还有 8 个

### 网络: 72 个 tracepoints

#### bridge (5 个)

- bridge:br_fdb_add
- bridge:br_fdb_external_learn_add
- bridge:br_fdb_update
- bridge:br_mdb_full
- bridge:fdb_delete

#### fib (1 个)

- fib:fib_table_lookup

#### fib6 (1 个)

- fib6:fib6_table_lookup

#### handshake (15 个)

- handshake:handshake_cancel
- handshake:handshake_cancel_busy
- handshake:handshake_cancel_none
- handshake:handshake_cmd_accept
- handshake:handshake_cmd_accept_err
- handshake:handshake_cmd_done
- handshake:handshake_cmd_done_err
- handshake:handshake_complete
- handshake:handshake_destruct
- handshake:handshake_notify_err
- handshake:handshake_submit
- handshake:handshake_submit_err
- handshake:tls_alert_recv
- handshake:tls_alert_send
- handshake:tls_contenttype

#### icmp (1 个)

- icmp:icmp_send

#### mptcp (5 个)

- mptcp:ack_update_msk
- mptcp:get_mapping_status
- mptcp:mptcp_sendmsg_frag
- mptcp:mptcp_subflow_get_send
- mptcp:subflow_check_data_avail

#### napi (1 个)

- napi:napi_poll

#### neigh (7 个)

- neigh:neigh_cleanup_and_release
- neigh:neigh_create
- neigh:neigh_event_send_dead
- neigh:neigh_event_send_done
- neigh:neigh_timer_handler
- neigh:neigh_update
- neigh:neigh_update_done

#### net (16 个)

- net:napi_gro_frags_entry
- net:napi_gro_frags_exit
- net:napi_gro_receive_entry
- net:napi_gro_receive_exit
- net:net_dev_queue
- net:net_dev_start_xmit
- net:net_dev_xmit
- net:net_dev_xmit_timeout
- net:netif_receive_skb
- net:netif_receive_skb_entry
- net:netif_receive_skb_exit
- net:netif_receive_skb_list_entry
- net:netif_receive_skb_list_exit
- net:netif_rx
- net:netif_rx_entry
- net:netif_rx_exit

#### skb (3 个)

- skb:consume_skb
- skb:kfree_skb
- skb:skb_copy_datagram_iovec

#### sock (7 个)

- sock:inet_sk_error_report
- sock:inet_sock_set_state
- sock:sk_data_ready
- sock:sock_exceed_buf_limit
- sock:sock_rcvqueue_full
- sock:sock_recv_length
- sock:sock_send_length

#### tcp (9 个)

- tcp:tcp_bad_csum
- tcp:tcp_cong_state_set
- tcp:tcp_destroy_sock
- tcp:tcp_probe
- tcp:tcp_rcv_space_adjust
- tcp:tcp_receive_reset
- tcp:tcp_retransmit_skb
- tcp:tcp_retransmit_synack
- tcp:tcp_send_reset

#### udp (1 个)

- udp:udp_fail_queue_rcv_skb

### 电源管理: 71 个 tracepoints

#### clk (21 个)

- clk:clk_disable
- clk:clk_disable_complete
- clk:clk_enable
- clk:clk_enable_complete
- clk:clk_prepare
- clk:clk_prepare_complete
- clk:clk_rate_request_done
- clk:clk_rate_request_start
- clk:clk_set_duty_cycle
- clk:clk_set_duty_cycle_complete
- clk:clk_set_max_rate
- clk:clk_set_min_rate
- clk:clk_set_parent
- clk:clk_set_parent_complete
- clk:clk_set_phase
- clk:clk_set_phase_complete
- clk:clk_set_rate
- clk:clk_set_rate_complete
- clk:clk_set_rate_range
- clk:clk_unprepare
- ... 还有 1 个

#### devfreq (2 个)

- devfreq:devfreq_frequency
- devfreq:devfreq_monitor

#### power (24 个)

- power:clock_disable
- power:clock_enable
- power:clock_set_rate
- power:cpu_frequency
- power:cpu_frequency_limits
- power:cpu_idle
- power:cpu_idle_miss
- power:dev_pm_qos_add_request
- power:dev_pm_qos_remove_request
- power:dev_pm_qos_update_request
- power:device_pm_callback_end
- power:device_pm_callback_start
- power:guest_halt_poll_ns
- power:pm_qos_add_request
- power:pm_qos_remove_request
- power:pm_qos_update_flags
- power:pm_qos_update_request
- power:pm_qos_update_target
- power:power_domain_target
- power:powernv_throttle
- ... 还有 4 个

#### regulator (11 个)

- regulator:regulator_bypass_disable
- regulator:regulator_bypass_disable_complete
- regulator:regulator_bypass_enable
- regulator:regulator_bypass_enable_complete
- regulator:regulator_disable
- regulator:regulator_disable_complete
- regulator:regulator_enable
- regulator:regulator_enable_complete
- regulator:regulator_enable_delay
- regulator:regulator_set_voltage
- regulator:regulator_set_voltage_complete

#### rpm (5 个)

- rpm:rpm_idle
- rpm:rpm_resume
- rpm:rpm_return_int
- rpm:rpm_suspend
- rpm:rpm_usage

#### thermal (5 个)

- thermal:cdev_update
- thermal:thermal_power_devfreq_get_power
- thermal:thermal_power_devfreq_limit
- thermal:thermal_temperature
- thermal:thermal_zone_trip

#### thermal_power_allocator (3 个)

- thermal_power_allocator:thermal_power_actor
- thermal_power_allocator:thermal_power_allocator
- thermal_power_allocator:thermal_power_allocator_pid

### 存储: 65 个 tracepoints

#### block (21 个)

- block:block_bio_backmerge
- block:block_bio_bounce
- block:block_bio_complete
- block:block_bio_frontmerge
- block:block_bio_queue
- block:block_bio_remap
- block:block_dirty_buffer
- block:block_getrq
- block:block_io_done
- block:block_io_start
- block:block_plug
- block:block_rq_complete
- block:block_rq_error
- block:block_rq_insert
- block:block_rq_issue
- block:block_rq_merge
- block:block_rq_remap
- block:block_rq_requeue
- block:block_split
- block:block_touch_buffer
- ... 还有 1 个

#### libata (33 个)

- libata:ata_bmdma_setup
- libata:ata_bmdma_start
- libata:ata_bmdma_status
- libata:ata_bmdma_stop
- libata:ata_eh_about_to_do
- libata:ata_eh_done
- libata:ata_eh_link_autopsy
- libata:ata_eh_link_autopsy_qc
- libata:ata_exec_command
- libata:ata_link_hardreset_begin
- libata:ata_link_hardreset_end
- libata:ata_link_postreset
- libata:ata_link_softreset_begin
- libata:ata_link_softreset_end
- libata:ata_port_freeze
- libata:ata_port_thaw
- libata:ata_qc_complete_done
- libata:ata_qc_complete_failed
- libata:ata_qc_complete_internal
- libata:ata_qc_issue
- ... 还有 13 个

#### nvme (4 个)

- nvme:nvme_async_event
- nvme:nvme_complete_rq
- nvme:nvme_setup_cmd
- nvme:nvme_sq

#### scsi (5 个)

- scsi:scsi_dispatch_cmd_done
- scsi:scsi_dispatch_cmd_error
- scsi:scsi_dispatch_cmd_start
- scsi:scsi_dispatch_cmd_timeout
- scsi:scsi_eh_wakeup

#### sd (2 个)

- sd:scsi_prepare_zone_append
- sd:scsi_zone_wp_update

### 音频: 42 个 tracepoints

#### asoc (13 个)

- asoc:snd_soc_bias_level_done
- asoc:snd_soc_bias_level_start
- asoc:snd_soc_dapm_connected
- asoc:snd_soc_dapm_done
- asoc:snd_soc_dapm_path
- asoc:snd_soc_dapm_start
- asoc:snd_soc_dapm_walk_done
- asoc:snd_soc_dapm_widget_event_done
- asoc:snd_soc_dapm_widget_event_start
- asoc:snd_soc_dapm_widget_power
- asoc:snd_soc_jack_irq
- asoc:snd_soc_jack_notify
- asoc:snd_soc_jack_report

#### hda (5 个)

- hda:hda_get_response
- hda:hda_send_cmd
- hda:hda_unsol_event
- hda:snd_hdac_stream_start
- hda:snd_hdac_stream_stop

#### hda_controller (6 个)

- hda_controller:azx_get_position
- hda_controller:azx_pcm_close
- hda_controller:azx_pcm_hw_params
- hda_controller:azx_pcm_open
- hda_controller:azx_pcm_prepare
- hda_controller:azx_pcm_trigger

#### hda_intel (4 个)

- hda_intel:azx_resume
- hda_intel:azx_runtime_resume
- hda_intel:azx_runtime_suspend
- hda_intel:azx_suspend

#### sof (6 个)

- sof:sof_ipc3_period_elapsed_position
- sof:sof_ipc4_fw_config
- sof:sof_pcm_pointer_position
- sof:sof_stream_position_ipc_rx
- sof:sof_widget_free
- sof:sof_widget_setup

#### sof_intel (8 个)

- sof_intel:sof_intel_D0I3C_updated
- sof_intel:sof_intel_hda_dsp_check_stream_irq
- sof_intel:sof_intel_hda_dsp_pcm
- sof_intel:sof_intel_hda_dsp_stream_status
- sof_intel:sof_intel_hda_irq
- sof_intel:sof_intel_hda_irq_ipc_check
- sof_intel:sof_intel_ipc_firmware_initiated
- sof_intel:sof_intel_ipc_firmware_response

### 硬件接口: 35 个 tracepoints

#### gpio (2 个)

- gpio:gpio_direction
- gpio:gpio_value

#### i2c (4 个)

- i2c:i2c_read
- i2c:i2c_reply
- i2c:i2c_result
- i2c:i2c_write

#### mmc (2 个)

- mmc:mmc_request_done
- mmc:mmc_request_start

#### pwm (2 个)

- pwm:pwm_apply
- pwm:pwm_get

#### rtc (12 个)

- rtc:rtc_alarm_irq_enable
- rtc:rtc_irq_set_freq
- rtc:rtc_irq_set_state
- rtc:rtc_read_alarm
- rtc:rtc_read_offset
- rtc:rtc_read_time
- rtc:rtc_set_alarm
- rtc:rtc_set_offset
- rtc:rtc_set_time
- rtc:rtc_timer_dequeue
- rtc:rtc_timer_enqueue
- rtc:rtc_timer_fired

#### smbus (4 个)

- smbus:smbus_read
- smbus:smbus_reply
- smbus:smbus_result
- smbus:smbus_write

#### spi (9 个)

- spi:spi_controller_busy
- spi:spi_controller_idle
- spi:spi_message_done
- spi:spi_message_start
- spi:spi_message_submit
- spi:spi_set_cs
- spi:spi_setup
- spi:spi_transfer_start
- spi:spi_transfer_stop

### 中断和锁: 27 个 tracepoints

#### csd (3 个)

- csd:csd_function_entry
- csd:csd_function_exit
- csd:csd_queue_cpu

#### irq (7 个)

- irq:irq_handler_entry
- irq:irq_handler_exit
- irq:softirq_entry
- irq:softirq_exit
- irq:softirq_raise
- irq:tasklet_entry
- irq:tasklet_exit

#### irq_matrix (12 个)

- irq_matrix:irq_matrix_alloc
- irq_matrix:irq_matrix_alloc_managed
- irq_matrix:irq_matrix_alloc_reserved
- irq_matrix:irq_matrix_assign
- irq_matrix:irq_matrix_assign_system
- irq_matrix:irq_matrix_free
- irq_matrix:irq_matrix_offline
- irq_matrix:irq_matrix_online
- irq_matrix:irq_matrix_remove_managed
- irq_matrix:irq_matrix_remove_reserved
- irq_matrix:irq_matrix_reserve
- irq_matrix:irq_matrix_reserve_managed

#### lock (2 个)

- lock:contention_begin
- lock:contention_end

#### nmi (1 个)

- nmi:nmi_handler

#### rcu (2 个)

- rcu:rcu_stall_warning
- rcu:rcu_utilization

### 容器和资源控制: 23 个 tracepoints

#### cgroup (13 个)

- cgroup:cgroup_attach_task
- cgroup:cgroup_destroy_root
- cgroup:cgroup_freeze
- cgroup:cgroup_mkdir
- cgroup:cgroup_notify_frozen
- cgroup:cgroup_notify_populated
- cgroup:cgroup_release
- cgroup:cgroup_remount
- cgroup:cgroup_rename
- cgroup:cgroup_rmdir
- cgroup:cgroup_setup_root
- cgroup:cgroup_transfer_tasks
- cgroup:cgroup_unfreeze

#### iocost (7 个)

- iocost:iocost_inuse_adjust
- iocost:iocost_inuse_shortage
- iocost:iocost_inuse_transfer
- iocost:iocost_ioc_vrate_adj
- iocost:iocost_iocg_activate
- iocost:iocost_iocg_forgive_debt
- iocost:iocost_iocg_idle

#### resctrl (3 个)

- resctrl:pseudo_lock_l2
- resctrl:pseudo_lock_l3
- resctrl:pseudo_lock_mem_latency

### 进程管理: 21 个 tracepoints

#### exceptions (2 个)

- exceptions:page_fault_kernel
- exceptions:page_fault_user

#### initcall (3 个)

- initcall:initcall_finish
- initcall:initcall_level
- initcall:initcall_start

#### mmap (4 个)

- mmap:exit_mmap
- mmap:vm_unmapped_area
- mmap:vma_mas_szero
- mmap:vma_store

#### mmap_lock (3 个)

- mmap_lock:mmap_lock_acquire_returned
- mmap_lock:mmap_lock_released
- mmap_lock:mmap_lock_start_locking

#### module (5 个)

- module:module_free
- module:module_get
- module:module_load
- module:module_put
- module:module_request

#### signal (2 个)

- signal:signal_deliver
- signal:signal_generate

#### task (2 个)

- task:task_newtask
- task:task_rename

### 定时器: 18 个 tracepoints

#### alarmtimer (4 个)

- alarmtimer:alarmtimer_cancel
- alarmtimer:alarmtimer_fired
- alarmtimer:alarmtimer_start
- alarmtimer:alarmtimer_suspend

#### timer (14 个)

- timer:hrtimer_cancel
- timer:hrtimer_expire_entry
- timer:hrtimer_expire_exit
- timer:hrtimer_init
- timer:hrtimer_start
- timer:itimer_expire
- timer:itimer_state
- timer:tick_stop
- timer:timer_base_idle
- timer:timer_cancel
- timer:timer_expire_entry
- timer:timer_expire_exit
- timer:timer_init
- timer:timer_start

### 异步I/O: 17 个 tracepoints

#### io_uring (17 个)

- io_uring:io_uring_complete
- io_uring:io_uring_cqe_overflow
- io_uring:io_uring_cqring_wait
- io_uring:io_uring_create
- io_uring:io_uring_defer
- io_uring:io_uring_fail_link
- io_uring:io_uring_file_get
- io_uring:io_uring_link
- io_uring:io_uring_local_work_run
- io_uring:io_uring_poll_arm
- io_uring:io_uring_queue_async_work
- io_uring:io_uring_register
- io_uring:io_uring_req_failed
- io_uring:io_uring_short_write
- io_uring:io_uring_submit_req
- io_uring:io_uring_task_add
- io_uring:io_uring_task_work_run

### 内存管理单元: 8 个 tracepoints

#### intel_iommu (2 个)

- intel_iommu:prq_report
- intel_iommu:qi_submit

#### iommu (6 个)

- iommu:add_device_to_group
- iommu:attach_device_to_domain
- iommu:io_page_fault
- iommu:map
- iommu:remove_device_from_group
- iommu:unmap

### 性能分析: 5 个 tracepoints

#### osnoise (5 个)

- osnoise:irq_noise
- osnoise:nmi_noise
- osnoise:sample_threshold
- osnoise:softirq_noise
- osnoise:thread_noise

### 内存分配: 4 个 tracepoints

#### swiotlb (1 个)

- swiotlb:swiotlb_bounced

#### vmalloc (3 个)

- vmalloc:alloc_vmap_area
- vmalloc:free_vmap_area_noflush
- vmalloc:purge_vmap_area_lazy

### BPF: 2 个 tracepoints

#### bpf_test_run (1 个)

- bpf_test_run:bpf_test_finish

#### bpf_trace (1 个)

- bpf_trace:bpf_trace_printk

### 安全: 1 个 tracepoints

#### avc (1 个)

- avc:selinux_audited

### TLB: 1 个 tracepoints

#### tlb (1 个)

- tlb:tlb_flush


## 详细分类清单

```python
# 格式: 功能分类 -> [category:event_name]
tracepoint_classification = {
    'BPF': [
        'bpf_test_run:bpf_test_finish',
        'bpf_trace:bpf_trace_printk',
    ],
    'CPU和调度': [
        'context_tracking:user_enter',
        'context_tracking:user_exit',
        'cpuhp:cpuhp_enter',
        'cpuhp:cpuhp_exit',
        'cpuhp:cpuhp_multi_enter',
        'cros_ec:cros_ec_request_done',
        'cros_ec:cros_ec_request_start',
        'ipi:ipi_entry',
        'ipi:ipi_exit',
        'ipi:ipi_raise',
        'ipi:ipi_send_cpu',
        'ipi:ipi_send_cpumask',
        'irq_vectors:call_function_entry',
        'irq_vectors:call_function_exit',
        'irq_vectors:call_function_single_entry',
        'irq_vectors:call_function_single_exit',
        'irq_vectors:deferred_error_apic_entry',
        # ... 还有 29 个
        'sched:sched_kthread_stop',
        'sched:sched_kthread_stop_ret',
        'sched:sched_kthread_work_execute_end',
        'sched:sched_kthread_work_execute_start',
        'sched:sched_kthread_work_queue_work',
        # ... 还有 23 个
    ],
    'TLB': [
        'tlb:tlb_flush',
    ],
    '中断和锁': [
        'csd:csd_function_entry',
        'csd:csd_function_exit',
        'csd:csd_queue_cpu',
        'irq:irq_handler_entry',
        'irq:irq_handler_exit',
        'irq:softirq_entry',
        'irq:softirq_exit',
        'irq:softirq_raise',
        # ... 还有 2 个
        'irq_matrix:irq_matrix_alloc',
        'irq_matrix:irq_matrix_alloc_managed',
        'irq_matrix:irq_matrix_alloc_reserved',
        'irq_matrix:irq_matrix_assign',
        'irq_matrix:irq_matrix_assign_system',
        # ... 还有 7 个
        'lock:contention_begin',
        'lock:contention_end',
        'nmi:nmi_handler',
        'rcu:rcu_stall_warning',
        'rcu:rcu_utilization',
    ],
    '内存分配': [
        'swiotlb:swiotlb_bounced',
        'vmalloc:alloc_vmap_area',
        'vmalloc:free_vmap_area_noflush',
        'vmalloc:purge_vmap_area_lazy',
    ],
    '内存管理': [
        'compaction:mm_compaction_begin',
        'compaction:mm_compaction_defer_compaction',
        'compaction:mm_compaction_defer_reset',
        'compaction:mm_compaction_deferred',
        'compaction:mm_compaction_end',
        # ... 还有 10 个
        'huge_memory:mm_collapse_huge_page',
        'huge_memory:mm_collapse_huge_page_isolate',
        'huge_memory:mm_collapse_huge_page_swapin',
        'huge_memory:mm_khugepaged_collapse_file',
        'huge_memory:mm_khugepaged_scan_file',
        # ... 还有 1 个
        'kmem:kfree',
        'kmem:kmalloc',
        'kmem:kmem_cache_alloc',
        'kmem:kmem_cache_free',
        'kmem:mm_page_alloc',
        # ... 还有 6 个
        'ksm:ksm_advisor',
        'ksm:ksm_enter',
        'ksm:ksm_exit',
        'ksm:ksm_merge_one_page',
        'ksm:ksm_merge_with_ksm_page',
        # ... 还有 4 个
        'maple_tree:ma_op',
        'maple_tree:ma_read',
        'maple_tree:ma_write',
        'migrate:mm_migrate_pages',
        'migrate:mm_migrate_pages_start',
        'migrate:remove_migration_pte',
        'migrate:set_migration_pte',
        'oom:compact_retry',
        'oom:finish_task_reaping',
        'oom:mark_victim',
        'oom:oom_score_adj_update',
        'oom:reclaim_retry_zone',
        # ... 还有 3 个
        'page_isolation:test_pages_isolated',
        'pagemap:mm_lru_activate',
        'pagemap:mm_lru_insertion',
        'percpu:percpu_alloc_percpu',
        'percpu:percpu_alloc_percpu_fail',
        'percpu:percpu_create_chunk',
        'percpu:percpu_destroy_chunk',
        'percpu:percpu_free_percpu',
        'thp:hugepage_set_pmd',
        'thp:hugepage_set_pud',
        'thp:hugepage_update_pmd',
        'thp:hugepage_update_pud',
        'thp:remove_migration_pmd',
        # ... 还有 1 个
        'vmscan:mm_shrink_slab_end',
        'vmscan:mm_shrink_slab_start',
        'vmscan:mm_vmscan_direct_reclaim_begin',
        'vmscan:mm_vmscan_direct_reclaim_end',
        'vmscan:mm_vmscan_kswapd_sleep',
        # ... 还有 13 个
    ],
    '内存管理单元': [
        'intel_iommu:prq_report',
        'intel_iommu:qi_submit',
        'iommu:add_device_to_group',
        'iommu:attach_device_to_domain',
        'iommu:io_page_fault',
        'iommu:map',
        'iommu:remove_device_from_group',
        # ... 还有 1 个
    ],
    '内核功能': [
        'amd_cpu:amd_pstate_perf',
        'dev:devres_log',
        'devlink:devlink_health_recover_aborted',
        'devlink:devlink_health_report',
        'devlink:devlink_health_reporter_state_update',
        'devlink:devlink_hwerr',
        'devlink:devlink_hwmsg',
        # ... 还有 1 个
        'dma_fence:dma_fence_destroy',
        'dma_fence:dma_fence_emit',
        'dma_fence:dma_fence_enable_signal',
        'dma_fence:dma_fence_init',
        'dma_fence:dma_fence_signaled',
        # ... 还有 2 个
        'error_report:error_report_end',
        'hwmon:hwmon_attr_show',
        'hwmon:hwmon_attr_show_string',
        'hwmon:hwmon_attr_store',
        'interconnect:icc_set_bw',
        'interconnect:icc_set_bw_end',
        'mce:mce_record',
        'mctp:mctp_key_acquire',
        'mctp:mctp_key_release',
        'mdio:mdio_access',
        'mei:mei_pci_cfg_read',
        'mei:mei_reg_read',
        'mei:mei_reg_write',
        'msr:rdpmc',
        'msr:read_msr',
        'msr:write_msr',
        'netlink:netlink_extack',
        'notifier:notifier_register',
        'notifier:notifier_run',
        'notifier:notifier_unregister',
        'page_pool:page_pool_release',
        'page_pool:page_pool_state_hold',
        'page_pool:page_pool_state_release',
        'page_pool:page_pool_update_nid',
        'printk:console',
        'qdisc:qdisc_create',
        'qdisc:qdisc_dequeue',
        'qdisc:qdisc_destroy',
        'qdisc:qdisc_enqueue',
        'qdisc:qdisc_reset',
        'qrtr:qrtr_ns_message',
        'qrtr:qrtr_ns_server_add',
        'qrtr:qrtr_ns_service_announce_del',
        'qrtr:qrtr_ns_service_announce_new',
        'ras:aer_event',
        'ras:arm_event',
        'ras:extlog_mem_event',
        'ras:mc_event',
        'ras:memory_failure_event',
        # ... 还有 1 个
        'regmap:regcache_drop_region',
        'regmap:regcache_sync',
        'regmap:regmap_async_complete_done',
        'regmap:regmap_async_complete_start',
        'regmap:regmap_async_io_complete',
        # ... 还有 12 个
        'rseq:rseq_ip_fixup',
        'rseq:rseq_update',
        'rv:error_wwnr',
        'rv:event_wwnr',
        'sync_trace:sync_timeline',
        'vsyscall:emulate_vsyscall',
        'watchdog:watchdog_ping',
        'watchdog:watchdog_set_timeout',
        'watchdog:watchdog_start',
        'watchdog:watchdog_stop',
        'wbt:wbt_lat',
        'wbt:wbt_stat',
        'wbt:wbt_step',
        'wbt:wbt_timer',
        'workqueue:workqueue_activate_work',
        'workqueue:workqueue_execute_end',
        'workqueue:workqueue_execute_start',
        'workqueue:workqueue_queue_work',
        'xhci-hcd:xhci_add_endpoint',
        'xhci-hcd:xhci_address_ctrl_ctx',
        'xhci-hcd:xhci_address_ctx',
        'xhci-hcd:xhci_alloc_dev',
        'xhci-hcd:xhci_alloc_virt_device',
        # ... 还有 48 个
    ],
    '存储': [
        'block:block_bio_backmerge',
        'block:block_bio_bounce',
        'block:block_bio_complete',
        'block:block_bio_frontmerge',
        'block:block_bio_queue',
        # ... 还有 16 个
        'libata:ata_bmdma_setup',
        'libata:ata_bmdma_start',
        'libata:ata_bmdma_status',
        'libata:ata_bmdma_stop',
        'libata:ata_eh_about_to_do',
        # ... 还有 28 个
        'nvme:nvme_async_event',
        'nvme:nvme_complete_rq',
        'nvme:nvme_setup_cmd',
        'nvme:nvme_sq',
        'scsi:scsi_dispatch_cmd_done',
        'scsi:scsi_dispatch_cmd_error',
        'scsi:scsi_dispatch_cmd_start',
        'scsi:scsi_dispatch_cmd_timeout',
        'scsi:scsi_eh_wakeup',
        'sd:scsi_prepare_zone_append',
        'sd:scsi_zone_wp_update',
    ],
    '安全': [
        'avc:selinux_audited',
    ],
    '定时器': [
        'alarmtimer:alarmtimer_cancel',
        'alarmtimer:alarmtimer_fired',
        'alarmtimer:alarmtimer_start',
        'alarmtimer:alarmtimer_suspend',
        'timer:hrtimer_cancel',
        'timer:hrtimer_expire_entry',
        'timer:hrtimer_expire_exit',
        'timer:hrtimer_init',
        'timer:hrtimer_start',
        # ... 还有 9 个
    ],
    '容器和资源控制': [
        'cgroup:cgroup_attach_task',
        'cgroup:cgroup_destroy_root',
        'cgroup:cgroup_freeze',
        'cgroup:cgroup_mkdir',
        'cgroup:cgroup_notify_frozen',
        # ... 还有 8 个
        'iocost:iocost_inuse_adjust',
        'iocost:iocost_inuse_shortage',
        'iocost:iocost_inuse_transfer',
        'iocost:iocost_ioc_vrate_adj',
        'iocost:iocost_iocg_activate',
        # ... 还有 2 个
        'resctrl:pseudo_lock_l2',
        'resctrl:pseudo_lock_l3',
        'resctrl:pseudo_lock_mem_latency',
    ],
    '异步I/O': [
        'io_uring:io_uring_complete',
        'io_uring:io_uring_cqe_overflow',
        'io_uring:io_uring_cqring_wait',
        'io_uring:io_uring_create',
        'io_uring:io_uring_defer',
        # ... 还有 12 个
    ],
    '性能分析': [
        'osnoise:irq_noise',
        'osnoise:nmi_noise',
        'osnoise:sample_threshold',
        'osnoise:softirq_noise',
        'osnoise:thread_noise',
    ],
    '文件系统': [
        'ext4:ext4_alloc_da_blocks',
        'ext4:ext4_allocate_blocks',
        'ext4:ext4_allocate_inode',
        'ext4:ext4_begin_ordered_truncate',
        'ext4:ext4_collapse_range',
        # ... 还有 108 个
        'filelock:break_lease_block',
        'filelock:break_lease_noblock',
        'filelock:break_lease_unblock',
        'filelock:fcntl_setlk',
        'filelock:flock_lock_inode',
        # ... 还有 7 个
        'filemap:file_check_and_advance_wb_err',
        'filemap:filemap_set_wb_err',
        'filemap:mm_filemap_add_to_page_cache',
        'filemap:mm_filemap_delete_from_page_cache',
        'fs_dax:dax_insert_mapping',
        'fs_dax:dax_insert_pfn_mkwrite',
        'fs_dax:dax_insert_pfn_mkwrite_no_entry',
        'fs_dax:dax_load_hole',
        'fs_dax:dax_pmd_fault',
        # ... 还有 9 个
        'iomap:iomap_dio_complete',
        'iomap:iomap_dio_invalidate_fail',
        'iomap:iomap_dio_rw_begin',
        'iomap:iomap_dio_rw_queued',
        'iomap:iomap_invalidate_folio',
        # ... 还有 8 个
        'jbd2:jbd2_checkpoint',
        'jbd2:jbd2_checkpoint_stats',
        'jbd2:jbd2_commit_flushing',
        'jbd2:jbd2_commit_locking',
        'jbd2:jbd2_commit_logging',
        # ... 还有 16 个
        'writeback:balance_dirty_pages',
        'writeback:bdi_dirty_ratelimit',
        'writeback:flush_foreign',
        'writeback:folio_wait_writeback',
        'writeback:global_dirty_state',
        # ... 还有 27 个
    ],
    '电源管理': [
        'clk:clk_disable',
        'clk:clk_disable_complete',
        'clk:clk_enable',
        'clk:clk_enable_complete',
        'clk:clk_prepare',
        # ... 还有 16 个
        'devfreq:devfreq_frequency',
        'devfreq:devfreq_monitor',
        'power:clock_disable',
        'power:clock_enable',
        'power:clock_set_rate',
        'power:cpu_frequency',
        'power:cpu_frequency_limits',
        # ... 还有 19 个
        'regulator:regulator_bypass_disable',
        'regulator:regulator_bypass_disable_complete',
        'regulator:regulator_bypass_enable',
        'regulator:regulator_bypass_enable_complete',
        'regulator:regulator_disable',
        # ... 还有 6 个
        'rpm:rpm_idle',
        'rpm:rpm_resume',
        'rpm:rpm_return_int',
        'rpm:rpm_suspend',
        'rpm:rpm_usage',
        'thermal:cdev_update',
        'thermal:thermal_power_devfreq_get_power',
        'thermal:thermal_power_devfreq_limit',
        'thermal:thermal_temperature',
        'thermal:thermal_zone_trip',
        'thermal_power_allocator:thermal_power_actor',
        'thermal_power_allocator:thermal_power_allocator',
        'thermal_power_allocator:thermal_power_allocator_pid',
    ],
    '硬件接口': [
        'gpio:gpio_direction',
        'gpio:gpio_value',
        'i2c:i2c_read',
        'i2c:i2c_reply',
        'i2c:i2c_result',
        'i2c:i2c_write',
        'mmc:mmc_request_done',
        'mmc:mmc_request_start',
        'pwm:pwm_apply',
        'pwm:pwm_get',
        'rtc:rtc_alarm_irq_enable',
        'rtc:rtc_irq_set_freq',
        'rtc:rtc_irq_set_state',
        'rtc:rtc_read_alarm',
        'rtc:rtc_read_offset',
        # ... 还有 7 个
        'smbus:smbus_read',
        'smbus:smbus_reply',
        'smbus:smbus_result',
        'smbus:smbus_write',
        'spi:spi_controller_busy',
        'spi:spi_controller_idle',
        'spi:spi_message_done',
        'spi:spi_message_start',
        'spi:spi_message_submit',
        # ... 还有 4 个
    ],
    '系统调用': [
        'raw_syscalls:sys_enter',
        'raw_syscalls:sys_exit',
        'syscalls:sys_enter_accept',
        'syscalls:sys_enter_accept4',
        'syscalls:sys_enter_access',
        'syscalls:sys_enter_acct',
        'syscalls:sys_enter_add_key',
        # ... 还有 707 个
    ],
    '网络': [
        'bridge:br_fdb_add',
        'bridge:br_fdb_external_learn_add',
        'bridge:br_fdb_update',
        'bridge:br_mdb_full',
        'bridge:fdb_delete',
        'fib:fib_table_lookup',
        'fib6:fib6_table_lookup',
        'handshake:handshake_cancel',
        'handshake:handshake_cancel_busy',
        'handshake:handshake_cancel_none',
        'handshake:handshake_cmd_accept',
        'handshake:handshake_cmd_accept_err',
        # ... 还有 10 个
        'icmp:icmp_send',
        'mptcp:ack_update_msk',
        'mptcp:get_mapping_status',
        'mptcp:mptcp_sendmsg_frag',
        'mptcp:mptcp_subflow_get_send',
        'mptcp:subflow_check_data_avail',
        'napi:napi_poll',
        'neigh:neigh_cleanup_and_release',
        'neigh:neigh_create',
        'neigh:neigh_event_send_dead',
        'neigh:neigh_event_send_done',
        'neigh:neigh_timer_handler',
        # ... 还有 2 个
        'net:napi_gro_frags_entry',
        'net:napi_gro_frags_exit',
        'net:napi_gro_receive_entry',
        'net:napi_gro_receive_exit',
        'net:net_dev_queue',
        # ... 还有 11 个
        'skb:consume_skb',
        'skb:kfree_skb',
        'skb:skb_copy_datagram_iovec',
        'sock:inet_sk_error_report',
        'sock:inet_sock_set_state',
        'sock:sk_data_ready',
        'sock:sock_exceed_buf_limit',
        'sock:sock_rcvqueue_full',
        # ... 还有 2 个
        'tcp:tcp_bad_csum',
        'tcp:tcp_cong_state_set',
        'tcp:tcp_destroy_sock',
        'tcp:tcp_probe',
        'tcp:tcp_rcv_space_adjust',
        # ... 还有 4 个
        'udp:udp_fail_queue_rcv_skb',
    ],
    '网络文件系统': [
        'sunrpc:cache_entry_expired',
        'sunrpc:cache_entry_make_negative',
        'sunrpc:cache_entry_no_listener',
        'sunrpc:cache_entry_upcall',
        'sunrpc:cache_entry_update',
        # ... 还有 131 个
    ],
    '虚拟化': [
        'hyperv:hyperv_mmu_flush_tlb_multi',
        'hyperv:hyperv_nested_flush_guest_mapping',
        'hyperv:hyperv_nested_flush_guest_mapping_range',
        'hyperv:hyperv_send_ipi_mask',
        'hyperv:hyperv_send_ipi_one',
        'kvm:kvm_ack_irq',
        'kvm:kvm_age_hva',
        'kvm:kvm_apic',
        'kvm:kvm_apic_accept_irq',
        'kvm:kvm_apic_ipi',
        # ... 还有 86 个
        'kvmmmu:check_mmio_spte',
        'kvmmmu:fast_page_fault',
        'kvmmmu:handle_mmio_page_fault',
        'kvmmmu:kvm_mmu_get_page',
        'kvmmmu:kvm_mmu_pagetable_walk',
        # ... 还有 13 个
        'xen:xen_cpu_load_idt',
        'xen:xen_cpu_set_ldt',
        'xen:xen_cpu_write_gdt_entry',
        'xen:xen_cpu_write_idt_entry',
        'xen:xen_cpu_write_ldt_entry',
        # ... 还有 21 个
    ],
    '设备驱动': [
        'drm:drm_vblank_event',
        'drm:drm_vblank_event_delivered',
        'drm:drm_vblank_event_queued',
        'gpu_scheduler:drm_run_job',
        'gpu_scheduler:drm_sched_job',
        'gpu_scheduler:drm_sched_job_wait_dep',
        'gpu_scheduler:drm_sched_process_job',
        'i915:g4x_wm',
        'i915:i915_context_create',
        'i915:i915_context_free',
        'i915:i915_gem_evict',
        'i915:i915_gem_evict_node',
        # ... 还有 39 个
        'x86_fpu:x86_fpu_after_restore',
        'x86_fpu:x86_fpu_after_save',
        'x86_fpu:x86_fpu_before_restore',
        'x86_fpu:x86_fpu_before_save',
        'x86_fpu:x86_fpu_copy_dst',
        # ... 还有 6 个
        'xdp:bpf_xdp_link_attach_failed',
        'xdp:mem_connect',
        'xdp:mem_disconnect',
        'xdp:mem_return_failed',
        'xdp:xdp_bulk_tx',
        # ... 还有 8 个
        'xe:xe_bo_cpu_fault',
        'xe:xe_bo_move',
        'xe:xe_exec_queue_cleanup_entity',
        'xe:xe_exec_queue_close',
        'xe:xe_exec_queue_create',
        # ... 还有 62 个
    ],
    '进程管理': [
        'exceptions:page_fault_kernel',
        'exceptions:page_fault_user',
        'initcall:initcall_finish',
        'initcall:initcall_level',
        'initcall:initcall_start',
        'mmap:exit_mmap',
        'mmap:vm_unmapped_area',
        'mmap:vma_mas_szero',
        'mmap:vma_store',
        'mmap_lock:mmap_lock_acquire_returned',
        'mmap_lock:mmap_lock_released',
        'mmap_lock:mmap_lock_start_locking',
        'module:module_free',
        'module:module_get',
        'module:module_load',
        'module:module_put',
        'module:module_request',
        'signal:signal_deliver',
        'signal:signal_generate',
        'task:task_newtask',
        'task:task_rename',
    ],
    '音频': [
        'asoc:snd_soc_bias_level_done',
        'asoc:snd_soc_bias_level_start',
        'asoc:snd_soc_dapm_connected',
        'asoc:snd_soc_dapm_done',
        'asoc:snd_soc_dapm_path',
        # ... 还有 8 个
        'hda:hda_get_response',
        'hda:hda_send_cmd',
        'hda:hda_unsol_event',
        'hda:snd_hdac_stream_start',
        'hda:snd_hdac_stream_stop',
        'hda_controller:azx_get_position',
        'hda_controller:azx_pcm_close',
        'hda_controller:azx_pcm_hw_params',
        'hda_controller:azx_pcm_open',
        'hda_controller:azx_pcm_prepare',
        # ... 还有 1 个
        'hda_intel:azx_resume',
        'hda_intel:azx_runtime_resume',
        'hda_intel:azx_runtime_suspend',
        'hda_intel:azx_suspend',
        'sof:sof_ipc3_period_elapsed_position',
        'sof:sof_ipc4_fw_config',
        'sof:sof_pcm_pointer_position',
        'sof:sof_stream_position_ipc_rx',
        'sof:sof_widget_free',
        # ... 还有 1 个
        'sof_intel:sof_intel_D0I3C_updated',
        'sof_intel:sof_intel_hda_dsp_check_stream_irq',
        'sof_intel:sof_intel_hda_dsp_pcm',
        'sof_intel:sof_intel_hda_dsp_stream_status',
        'sof_intel:sof_intel_hda_irq',
        # ... 还有 3 个
    ],
}
```
