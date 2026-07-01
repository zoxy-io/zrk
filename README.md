# zrk

A constant-throughput HTTP load generator — a Zig 0.16 rewrite of
[wrk2](https://github.com/giltene/wrk2), with a **live in-terminal dashboard**
of test progress.

Like wrk2, zrk generates load at a *fixed* request rate and reports latency
**corrected for coordinated omission** via an HdrHistogram, so tail latencies
aren't hidden when the server falls behind. Unlike wrk2, zrk continuously
renders the latency percentile spectrum and a p99 sparkline while the test runs.

## Why constant throughput + coordinated-omission correction?

An open-loop load tester that simply sends "as fast as the server answers"
accidentally *coordinates* with the server: when the server stalls, the tester
stops sending, so the stall never shows up in the latency numbers. zrk instead
paces each connection to a fixed schedule and measures every request's latency
from the time it *should* have been sent. If the server stalls, backlogged
requests accrue latency against their intended send time — the stall is
captured, not smoothed away.

## Build

Requires Zig 0.16.

```sh
zig build                 # produces zig-out/bin/zrk
zig build -Doptimize=ReleaseFast
zig build test            # run the unit + integration tests
```

## Usage

```
zrk [options] <url>

  -t, --threads     <N>     Number of worker threads       (default 2)
  -c, --connections <N>     Total connections to keep open (default 10)
  -d, --duration    <T>     Test duration, e.g. 30s, 2m    (default 10s)
  -R, --rate        <N>     Target requests/second (total) (default 1000)
  -H, --header  <K: V>      Add a request header (repeatable)
  -m, --method      <M>     HTTP method                    (default GET)
  -b, --body        <S>     Request body
      --timeout     <T>     Per-request timeout            (default 2s)
      --interval    <T>     Dashboard refresh interval     (default 1s)
      --latency             Print full latency spectrum in the final report
  -k, --insecure            Skip TLS certificate verification
      --plain               Append-only output instead of a live dashboard
  -h, --help                Show this help
```

Durations accept `us`, `ms`, `s`, `m`, `h` (a bare number is seconds).
Short options may be attached (`-t4`, `-c100`) or separated (`-t 4`).

### Examples

```sh
# 2000 req/s for 30s over 100 connections
zrk -t2 -c100 -d30s -R2000 http://127.0.0.1:8080/

# HTTPS with the full latency spectrum in the final report
zrk -c20 -d1m -R500 --latency https://api.example.com/health

# POST with a body and custom headers
zrk -c10 -R100 -m POST -b '{"ping":1}' \
    -H 'Content-Type: application/json' http://127.0.0.1:8080/echo

# CI-friendly, no redrawing dashboard
zrk -c50 -R1000 -d20s --plain http://127.0.0.1:8080/ | tee run.log
```

The dashboard automatically falls back to append-only lines when stdout is not
a TTY, so piping just works.

## How it works

- **One request in flight per connection** (like wrk/wrk2). Throughput comes
  from running many connections; the total `-R` rate is split evenly across
  them, and each connection paces its own sends to that schedule.
- **HdrHistogram** records every request's corrected latency (1µs–1h, 3
  significant figures). Each connection owns its own histogram (lock-free hot
  path) and publishes a snapshot once per `--interval` for the dashboard; the
  final report aggregates all histograms after the run.
- Connections run concurrently on Zig 0.16's `std.Io` (`Threaded` backend), one
  connection per worker fiber/thread.

## Source layout

| File | Responsibility |
|------|----------------|
| `src/hdr.zig` | Minimal HdrHistogram (record, percentiles, merge). |
| `src/cli.zig` | Argument / URL / duration parsing → `Config`. |
| `src/http.zig` | Request builder and response parser (Content-Length + chunked). |
| `src/connection.zig` | The per-connection pacing loop (the coordinated-omission core). |
| `src/tls.zig` | TLS session setup over a stream (system CA bundle, `-k`). |
| `src/stats.zig` | Per-connection state ownership + snapshot/final aggregation. |
| `src/tui.zig` | Live dashboard and final report. |
| `src/main.zig` | Orchestration: resolve, launch connections, drive the dashboard. |

## Limitations (v1)

- HTTP/1.1 only; a single fixed request per run (no scripting).
- Concurrency is thread-per-connection on the `std.Io.Threaded` backend, since
  the io_uring backend does not compile in the current Zig 0.16 toolchain. This
  is fine for moderate connection counts.
- `--timeout` bounds the **response** (a request whose response doesn't arrive
  in time is abandoned and counted as `Socket errors: ... timeout N`, matching
  wrk2). The *connect* itself still uses the OS default, since
  connect-with-timeout is unimplemented in the std backend and panics.
- `-k` skips certificate verification; with the std TLS client this also omits
  SNI, so name-based virtual hosts may respond differently under `-k`.
