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

  -c, --connections <N>     Total connections to keep open (default 10)
  -d, --duration    <T>     Test duration, e.g. 30s, 2m    (default 10s)
  -R, --rate      <N|A:B>   Target requests/second (total); A:B ramps
                            linearly from A to B over the run (default 1000)
  -H, --header  <K: V>      Add a request header (repeatable)
  -m, --method      <M>     HTTP method                    (default GET)
  -b, --body     <S|@FILE>  Request body; @FILE reads it from a file
                            (@- = stdin, @@x = a literal "@x")
      --timeout     <T>     Per-request timeout            (default 2s)
      --interval    <T>     Dashboard refresh interval     (default 1s)
      --latency             Print full latency spectrum in the final report
  -k, --insecure            Skip TLS certificate verification
      --plain               Append-only output instead of a live dashboard

  Reporting:
      --format  <text|json> Final report format            (default text)
  -o, --output      <FILE>  Write the final report to FILE (default stdout)
      --hdr         <FILE>  Also write the HdrHistogram percentile
                            distribution (.hgrm) to FILE
      --timeseries  <FILE>  Stream per-interval NDJSON (throughput +
                            latency percentiles) to FILE
      --timeseries-histogram  Add each interval's full latency histogram
                            (HdrHistogram base64) to every --timeseries row
      --no-record-timeouts  Drop timed-out requests from the latency histogram
                            (default: record them, so the tail isn't truncated)

  CI gates (exit code 3 on breach):
      --slo-p99     <T>     Fail if final p99 latency exceeds T
      --max-error-rate <F>  Fail if error rate exceeds F (e.g. 0.01 or 1%)

  -h, --help                Show this help
      --version             Show version
```

Durations accept `us`, `ms`, `s`, `m`, `h` (a bare number is seconds).
Short options may be attached (`-c100`) or separated (`-c 100`).

Unlike wrk2 there is no `-t/--threads`: each connection runs on its own
worker, so `-c` alone controls concurrency.

### Examples

```sh
# 2000 req/s for 30s over 100 connections
zrk -c100 -d30s -R2000 http://127.0.0.1:8080/

# Ramp linearly from 100 to 5000 req/s over 60s, capturing the latency-vs-load
# curve as a per-interval NDJSON time series (find the knee where latency breaks)
zrk -c200 -d60s -R100:5000 --timeseries ramp.ndjson http://127.0.0.1:8080/

# HTTPS with the full latency spectrum in the final report
zrk -c20 -d1m -R500 --latency https://api.example.com/health

# POST with a body and custom headers
zrk -c10 -R100 -m POST -b '{"ping":1}' \
    -H 'Content-Type: application/json' http://127.0.0.1:8080/echo

# POST a body read from a file (@- reads stdin instead)
zrk -c10 -R100 -m POST -b @payload.json \
    -H 'Content-Type: application/json' http://127.0.0.1:8080/echo

# CI-friendly, no redrawing dashboard
zrk -c50 -R1000 -d20s --plain http://127.0.0.1:8080/ | tee run.log

# Machine-readable: JSON summary to a file + HdrHistogram .hgrm for plotting
zrk -c50 -R1000 -d20s --format json -o result.json --hdr latency.hgrm \
    http://127.0.0.1:8080/

# CI gate: fail the build (exit 3) if p99 regresses past 250ms or errors climb
zrk -c50 -R1000 -d20s --format json -o result.json \
    --slo-p99 250ms --max-error-rate 1% http://127.0.0.1:8080/
```

The dashboard automatically falls back to append-only lines when stdout is not
a TTY, so piping just works.

## Machine-readable output

For embedding in a benchmark harness or CI, `--format json` emits a single
summary object (the live dashboard is suppressed) to stdout or `--output <file>`:

```json
{
  "zrk_version": "0.1.0",
  "target": { "url": "http://127.0.0.1:8080/", "method": "GET" },
  "config": { "connections": 50, "launched": 50, "duration_s": 20.000, "target_rate": 1000, "timeout_ms": 2000, "record_timeouts": true },
  "duration_s": 20.002,
  "requests": 19998,
  "bytes": 1239876,
  "achieved_rate": 999.80,
  "target_rate": 1000,
  "rate_ratio": 0.9998,
  "bytes_per_sec": 61987.30,
  "error_rate": 0.000000,
  "latency_us": { "min": 106, "mean": 422.0, "stdev": 1222.9, "max": 13991,
                  "p50": 251, "p75": 337, "p90": 471, "p99": 1913, "p99_9": 13364, "p99_99": 13988 },
  "status_codes": { "1xx": 0, "2xx": 19998, "3xx": 0, "4xx": 0, "5xx": 0 },
  "errors": { "connect": 0, "read": 0, "write": 0, "timeout": 0, "non_2xx_3xx": 0 },
  "latency_histogram": "HISTFAAAAUJ4nC1P..."
}
```

`latency_histogram` is the **complete** latency distribution encoded as an
HdrHistogram **V2 compressed** base64 blob — the same interchange format the
Java/Go/JS/Rust HdrHistogram libraries read. It decodes losslessly, so a harness
can store the raw histogram and later re-percentile it, diff two runs, or merge
many runs into one aggregate — none of which the summarized percentiles allow.
`zrk` can round-trip it too (`hdr.decodeBase64`), e.g. to merge prior runs.

`achieved_rate` / `rate_ratio` tell you whether the client actually sustained
the target load. **If `rate_ratio` is well below 1.0, the client was saturated
(one request in flight per connection — see Little's law below) and the latency
numbers reflect client backpressure, not the server: increase `-c`.**

`--hdr <file>` additionally writes the classic HdrHistogram percentile
distribution (values in milliseconds), directly loadable by the
[HdrHistogram plotter](https://hdrhistogram.github.io/HdrHistogram/plotFiles.html)
and format-compatible with wrk2's `--latency` output.

`--timeseries <file>` streams one NDJSON object per `--interval`, each carrying
that window's offered `target_rate`, `achieved_rate`, request/error counts, and
a delta-histogram latency percentile set:

```
{"t":1.006,"target_rate":480.0,"achieved_rate":476.2,"requests":476,"errors":0,"latency_us":{"p50":245,"p90":669,"p99":1745,"p99_9":2401,"max":2401}}
```

This is the artifact a **ramp** (`-R A:B`) exists to produce: a curve of latency
against offered load, so you can find the rate at which the server's tail breaks
down. (The final summary's aggregate percentiles blend the whole ramp together,
so they're less useful for a ramp than the time series is.)

Add `--timeseries-histogram` to append each interval's **full** latency
distribution as an HdrHistogram V2 base64 blob (`latency_histogram`) to every
row. Each blob decodes losslessly, so a harness can re-percentile a single
interval or merge any subset of them — e.g. just the windows above a target
rate. Merging every row reproduces the run's summary histogram exactly, since
the intervals partition the run. (Rows get noticeably larger, so it is opt-in.)

Timed-out requests are recorded into the latency histogram by default (as a
coordinated-omission-corrected sample) so the tail isn't silently truncated;
`--no-record-timeouts` restores wrk2's drop-on-timeout behavior.

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
| `src/report.zig` | Machine-readable JSON summary + SLO/CI exit-code gates. |
| `src/tui.zig` | Live dashboard and final report. |
| `src/main.zig` | Orchestration: resolve, launch connections, drive the dashboard. |

## Limitations (v0)

- HTTP/1.1 only; a single fixed request per run (no scripting).
- Concurrency is thread-per-connection on the `std.Io.Threaded` backend, since
  the io_uring backend does not compile in the current Zig 0.16 toolchain. This
  is fine for moderate connection counts.
- **One request is in flight per connection**, so by Little's law a single
  connection can sustain at most `1 / latency` req/s. To hit a target rate `R`
  against a service with latency `L`, you need at least `R × L` connections
  (e.g. 2000 req/s at 5 ms ⇒ ≥ 10 connections). Below that the client, not the
  server, is the bottleneck; watch `rate_ratio` / `achieved_rate` in the JSON
  report to confirm the offered load was actually delivered.
- `--timeout` bounds the **response** (a request whose response doesn't arrive
  in time is abandoned and counted as `Socket errors: ... timeout N`, matching
  wrk2). The *connect* itself still uses the OS default, since
  connect-with-timeout is unimplemented in the std backend and panics.
- `-k` skips certificate verification; with the std TLS client this also omits
  SNI, so name-based virtual hosts may respond differently under `-k`.
