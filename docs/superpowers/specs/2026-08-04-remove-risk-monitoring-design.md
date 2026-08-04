# Remove Risk Monitoring Design

**Date:** 2026-08-04

## Goal

Remove the short-term Risk-specific monitoring implementation from Sword while preserving the
general CPU, I/O, socket, and network observability code and the in-progress generic TCP Reset
work in the current working tree.

## Scope

Remove all Risk-specific runtime behavior and repository material:

- Risk target configuration and TGID maps;
- Risk process discovery and refresh logic;
- Risk TCP payload, epoll, HTTP request ID, and latency correlation probes;
- Risk-specific ring buffers, counters, metrics, event structures, and tests;
- Risk-only loader options and environment variables;
- Risk configuration from `deployment.yaml` and the Risk section from `README.md`;
- historical Risk-related plans and specifications under `docs/superpowers`.

## Preserved Behavior

- General CPU scheduling, I/O, connect, socket, accept, and TCP state monitoring;
- generic PID/COMM-based filtering where it existed before Risk monitoring;
- current image and deployment settings unrelated to Risk;
- the user's uncommitted TCP Reset work, including the `tcp_send_active_reset` loader entry;
- unrelated repository history and files.

If the TCP Reset work currently references a Risk-only type or map, it will be separated into a
generic Reset implementation rather than removed.

## Approach

Use commit `4ff99b8` (the parent of the first Risk change) as a read-only baseline. Compare each
Risk-touched source file against that baseline, then manually remove Risk additions from the
current tree. Do not reset or revert the branch because later commits and the user's working-tree
changes are interleaved with Risk work.

For deployment and documentation files, remove only Risk-specific content while preserving the
current image tag and unrelated configuration. Delete Risk-only files that did not exist at the
baseline.

## Resulting Data Flow

After removal, the eBPF program loads only the general probes and maps. The userspace loader no
longer discovers `content-risk-control-service` processes, writes Risk target maps, consumes Risk
ring-buffer events, or exports `sword_target_*` metrics. Generic TCP Reset probes may emit their
own generic events without depending on Risk targeting.

## Failure Handling

- Missing generic maps or probes remain startup errors as before.
- Optional TCP Reset probes must be handled independently from removed Risk configuration.
- No compatibility aliases are retained for removed `SWORD_TARGET_*` or
  `SWORD_HTTP_TRACE_ALL`; they disappear from deployment and argument parsing.

## Verification

1. Confirm no source, deployment, README, test, or historical document references Risk-specific
   symbols or `content-risk-control-service`.
2. Confirm the two pre-existing working-tree files retain the intended generic TCP Reset changes.
3. Run formatting and all available unit tests.
4. Build the userspace and eBPF crates using the repository build workflow.
5. Inspect the final diff to ensure unrelated files and current image settings are preserved.

