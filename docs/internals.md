# How zrk works

- **One request in flight per connection** (like wrk/wrk2). Throughput comes
  from running many connections; the total `-R` rate is split evenly across
  them, and each connection paces its own sends to that schedule.
- **HdrHistogram** records every request's corrected latency (1µs–60s, 3
  significant figures). Connections share one histogram and counter set per
  statistics shard, with up to `--threads` shards. A short lock keeps updates
  safe when coroutines move between threads, and records each response's
  latency and counters together. The dashboard merges the shards at its
  refresh cadence; the final report merges them after the run. Latencies above
  60s are clamped into the top bucket rather than dropped, so the request is still
  counted but the reported tail saturates there. Histogram storage is 136KiB
  per shard, plus a fixed number of reporting histograms: sixteen shards cost
  2.125MiB regardless of connection count. Per-connection transport buffers and
  coroutine stacks still scale with `-c`.
- Connections run as coroutines on a [zio](https://github.com/lalinsky/zio)
  io_uring runtime (`std.Io`-compatible), one connection per coroutine.

## Source layout

| File | Responsibility |
|------|----------------|
| `src/hdr.zig` | Minimal HdrHistogram (record, percentiles, merge). |
| `src/cli.zig` | Argument / URL / duration parsing → `Config`. |
| `src/http.zig` | Request builder (HTTP/1.1 bytes and the HPACK block); response framing is [zurl](https://github.com/zoxy-io/zurl)'s. |
| `src/runner.zig` | The reusable run loop the CLI and library embedders both call. |
| `src/connection.zig` | The per-connection pacing loop (the coordinated-omission core). |
| `src/pace.zig` | Closed-form nanosecond send schedule per connection and send index. |
| `src/tls.zig` | TLS over a stream: the `std.Io` adapter over [zssl](https://github.com/zoxy-io/zssl)'s sans-I/O engine, plus the X.509 chain and hostname verification zssl leaves to its embedder (system CA bundle, `-k`). |
| `src/stats.zig` | Shared statistics shards, transport state ownership, and snapshot/final aggregation. |
| `src/report.zig` | Machine-readable JSON summary + SLO/CI exit-code gates. |
| `src/tui.zig` | Live dashboard and final report. |
| `src/main.zig` | Orchestration: resolve, launch connections, drive the dashboard. |
