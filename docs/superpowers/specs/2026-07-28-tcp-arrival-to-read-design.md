# Sword TCP arrival-to-read tracing design

## Goal

Extend Sword's Risk HTTP diagnostic chain to measure the interval between the
first TCP payload reaching the server socket and the target process completing
its first successful `tcp_recvmsg`.

The complete diagnostic chain becomes:

```text
TCP payload reaches the Risk socket
  -> target process completes the first successful tcp_recvmsg
  -> target process starts its first tcp_sendmsg
```

The implementation targets the current test node kernel
`5.14.0-479.el9.x86_64`. That kernel exposes the `tcp:tcp_probe` tracepoint with
the fields needed by this design: address tuple, ports, `data_len`, and socket
cookie.

## Probe selection

Use `tracepoint/tcp/tcp_probe` instead of a packet-level tracepoint or a receive
path kprobe.

- `data_len > 0` excludes pure ACK packets.
- `sport == SWORD_TARGET_PORT` limits events to traffic received by the target
  server port.
- The tracepoint is available on the current test kernel and does not require
  reading unstable `struct sk_buff` offsets.
- No HTTP headers, bodies, request IDs, phone numbers, or other payload data are
  read.

No compatibility fallback is included for kernels that do not expose this
tracepoint.

## Correlation model

Define a flow key containing:

- address family;
- local and remote IPv4 or IPv6 addresses;
- local server port;
- remote client port.

The same flow key is built from `tcp_probe`, `tcp_recvmsg`, and `tcp_sendmsg`.

Maps:

- `TCP_PAYLOAD_ARRIVAL`: first payload-arrival timestamp for an idle flow;
- `TCP_ACTIVE_FLOW`: marks a flow after its first successful read until its
  first response write.

Processing:

1. `tcp_probe` ignores zero-length payloads and non-target server ports.
2. For an idle flow, it records only the first payload timestamp.
3. A successful `tcp_recvmsg` removes the timestamp and calculates
   `arrival_to_read`.
4. The successful read marks the flow active. Additional payload packets for
   that request are ignored.
5. The first `tcp_sendmsg` clears the active marker.
6. Existing socket-keyed read-to-write measurement remains unchanged.

The maps are bounded LRU maps so abandoned or unexpectedly closed flows cannot
grow memory usage without limit.

## Output

Keep the existing read-to-write event and metrics unchanged.

Add a phase to slow TCP events so user space can emit:

```text
target tcp arrival-to-read slow latency_ms=... pid=... tid=... src=... dst=... family=...
```

Add Prometheus counters:

```text
sword_target_tcp_payload_arrival_total
sword_target_tcp_arrival_to_read_total
sword_target_tcp_arrival_to_read_slow_total
```

The existing `SWORD_SLOW_THRESHOLD_MS` value applies to both
arrival-to-read and read-to-write phases.

## Failure and edge handling

- Failure to update a map or RingBuf increments the existing dropped-event
  counter.
- A read without a matching payload timestamp still increments the existing
  TCP read counter but does not create a fabricated latency sample.
- HTTP pipelining with multiple simultaneously outstanding requests on one
  connection is outside this short-term diagnostic scope.
- Existing IPv4 and IPv6 socket tuple handling is retained.

## Verification

Follow red-green-refactor:

1. Add failing user-space tests for the new metrics and phase-specific log
   formatting.
2. Add failing pure tests for flow normalization and first-arrival state
   decisions where code can be shared outside eBPF helpers.
3. Implement the minimum common types, exporter changes, loader attachment,
   tracepoint program, and map transitions.
4. Run formatting, workspace unit tests, and the project build.
5. On the 5.14 test node, verify that the tracepoint attaches and that a
   controlled HTTP request produces payload-arrival, arrival-to-read, and
   read-to-write observations without exposing payload content.

