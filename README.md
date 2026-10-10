<p align="center">
    <img alt="zrk ramping load from 400 to 3400 req/s against a saturating service" src="./zrk.svg" width="880" />
</p>

# zrk

[![CI](https://github.com/zoxy-io/zrk/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zrk/actions/workflows/ci.yml)

A constant-throughput HTTP load generator — a Zig 0.16 rewrite of
[wrk2](https://github.com/giltene/wrk2) with a live in-terminal dashboard.

- **Corrected for coordinated omission.** Latency is measured from the time a
  request *should* have been sent, so a server stall lands in the tail instead
  of being smoothed away.
- **Nanosecond pacing.** The send schedule is a closed-form nanosecond offset,
  not wrk2's millisecond timer wheel — which rounds every wait up and adds
  ~0.5 ms of the tool's own noise to every sample.
  ([why this matters](docs/coordinated-omission.md#why-zrk-is-more-accurate-than-wrk2))
- **Three load models.** Fixed rate (`-R 2000`), linear ramp (`-R 100:5000`),
  or closed loop (`--closed`) to discover a ceiling instead of guessing one.
- **Live dashboard.** Latency percentile spectrum and a p99 sparkline while the
  run is going; falls back to append-only lines when stdout is not a TTY.
- **Machine-readable output.** JSON summary, HdrHistogram (`.hgrm` and V2
  base64), and per-interval NDJSON for streaming plotters.
- **CI gates.** `--slo-p99` and `--max-error-rate` fail the build with exit 3.

## Installation

### Homebrew

```sh
brew install zoxy-io/tap/zrk
```

The tap follows stable releases only. A prerelease — `v3.0.0-alpha.1` and
anything else with a `-` in its version — is published to
[Releases](https://github.com/zoxy-io/zrk/releases) as archives and is
deliberately not written to the tap, because the tap holds one formula and
`brew upgrade` reads it. Take a prerelease from the download below.

### Pre-built binary

Download the latest release binary from the [Releases page](https://github.com/zoxy-io/zrk/releases).
Linux and macOS, x86_64 and aarch64. Windows binaries were dropped after v1.4.3
([#21](https://github.com/zoxy-io/zrk/issues/21)): zrk terminates TLS through
[zssl](https://github.com/zoxy-io/zssl), which is Linux/macOS by design.

### Build from source

Requires Zig 0.16.

```sh
zig build                 # produces zig-out/bin/zrk
zig build -Doptimize=ReleaseFast
zig build test            # run the unit + integration tests
```

## Usage

```
zrk — constant-throughput HTTP load generator

Usage: zrk [options] <url> [script args...]

Options:
  -t, --threads     <N>     Total number of threads to execute load (default 2)
  -c, --connections <N>     Total connections to keep open (default 10)
  -s, --streams     <N>     HTTP/2 or HTTP/3 streams in flight per
                            connection (default 1). A depth knob only:
                            -R still splits across -c, so -c 10 -s 10
                            offers the same rate as -c 10, not as
                            -c 100. Requires --http2 or --http3
  -d, --duration    <T>     Test duration, e.g. 30s, 2m    (default 10s)
  -R, --rate      <N|A:B>   Target requests/second (total); A:B ramps
                            linearly from A to B over the run (default 1000)
      --closed              Closed-loop mode: ignore -R, send each
                            connection's next request the instant its
                            previous response completes (like wrk/ab).
                            No coordinated-omission correction; the rate
                            finds its own ceiling instead of chasing one.
                            Incompatible with a ramp (-R A:B) or --deadline
      --disable-keepalive   Close and reconnect after every response: one
                            connection per request, like ab. Enforced
                            client-side, so it also covers servers that
                            ignore the Connection: close it sends.
                            Not available with --http2 or --http3
  -H, --header  <K: V>      Add a request header (repeatable)
  -m, --method      <M>     HTTP method                    (default GET)
  -b, --body     <S|@FILE>  Request body; @FILE reads it from a file
                            (@- = stdin, @@x = a literal "@x")
      --script    <FILE>  Run a wrk Lua script (LuaJIT): its wrk table
                            and init(args)/request() hooks shape each
                            request. Arguments after <url> go to init
      --timeout     <T>     Wire timeout per attempt, from the actual
                            send (default 2s); does not bound CO latency
      --deadline    <T>     Max coordinated-omission latency, from the
                            scheduled send: a too-stale request is shed
                            (failed as a `deadline` error, not sent or
                            recorded) before sending (0 = off)
      --deadline-abort      Also abort in-flight requests past the
                            deadline. Resets the connection per miss and
                            churns under saturation; off by default
      --interval    <T>     Stats window: --timeseries rows and --plain
                            lines                          (default 1s)
      --refresh     <T>     Live dashboard redraw rate     (default 80ms)
      --latency             Print full latency spectrum in the final report
      --http2               Speak HTTP/2. Cleartext uses prior knowledge
                            (h2c); https negotiates it over ALPN and
                            fails the connection if the server declines
      --http3               Speak HTTP/3 over QUIC (https only)
  -k, --insecure            Skip TLS certificate verification
      --plain               Append-only output instead of a live dashboard

Reporting:
      --format  <text|json> Final report format            (default text)
  -o, --output      <FILE>  Write the final report to FILE (default stdout)
      --hdr         <FILE>  Also write the HdrHistogram percentile
                            distribution (.hgrm) to FILE
      --timeseries  <FILE>  Stream per-interval NDJSON (throughput +
                            latency percentiles) to FILE. "-" streams to
                            stdout for piping into a live plotter; the
                            dashboard is then suppressed and the final
                            report goes to stderr unless -o is given
      --timeseries-histogram  Add each interval's full latency histogram
                            (HdrHistogram base64) to every --timeseries row
      --no-record-timeouts  Drop wire-timed-out requests from the latency
                            histogram (default: record them). Independent
                            of --deadline misses, which are never recorded.

CI gates (exit code 3 on breach):
      --slo-p99     <T>     Fail if final p99 latency exceeds T
      --max-error-rate <F>  Fail if error rate exceeds F (0..1)

  -h, --help                Show this help
      --version             Show version
```

Durations accept `us`, `ms`, `s`, `m`, `h` (a bare number is seconds).
Short options may be attached (`-c100`) or separated (`-c 100`).

### Examples

```sh
# 2000 req/s for 30s over 100 connections
zrk -c100 -d30s -R2000 http://127.0.0.1:8080/

# Ramp linearly from 100 to 5000 req/s over 60s, capturing the latency-vs-load
# curve as a per-interval NDJSON time series (find the knee where latency breaks)
zrk -c200 -d60s -R100:5000 --timeseries ramp.ndjson http://127.0.0.1:8080/

# Closed-loop: what's the real max throughput at 100 connections? No -R to
# guess — achieved_rate finds its own ceiling instead of chasing one.
zrk -c100 -d20s --closed http://127.0.0.1:8080/

# HTTPS with the full latency spectrum in the final report
zrk -c20 -d1m -R500 --latency https://api.example.com/health

# POST with a body and custom headers (-b @payload.json reads a file, @- stdin)
zrk -c10 -R100 -m POST -b '{"ping":1}' \
    -H 'Content-Type: application/json' http://127.0.0.1:8080/echo

# A wrk script: a fresh user id on every request, ids 1..1000 (see "Scripting")
zrk -c50 -R2000 -d30s --script users.lua http://127.0.0.1:8080/ /user/ 1000

# HTTP/3 over QUIC (experimental — see "HTTP/3" below for what that costs you)
zrk --http3 -k -c10 -R500 -d30s https://127.0.0.1:4433/

# CI-friendly, no redrawing dashboard
zrk -c50 -R1000 -d20s --plain http://127.0.0.1:8080/ | tee run.log

# Machine-readable: JSON summary to a file + HdrHistogram .hgrm for plotting
zrk -c50 -R1000 -d20s --format json -o result.json --hdr latency.hgrm \
    http://127.0.0.1:8080/

# CI gate: fail the build (exit 3) if p99 regresses past 250ms or errors climb
zrk -c50 -R1000 -d20s --format json -o result.json \
    --slo-p99 250ms --max-error-rate 1% http://127.0.0.1:8080/

# Live terminal plot: stream the per-interval rows into jplot
zrk -c50 -R1000 -d5m --timeseries - http://127.0.0.1:8080/ \
  | jplot achieved_rate+target_rate latency_us.p50+latency_us.p90+latency_us.p99 error_rate
```

### Scripting

`--script FILE` runs a [wrk](https://github.com/wg/wrk) Lua script, so scripts
written for wrk and wrk2 carry over. The interpreter is LuaJIT, as in wrk:
Lua 5.1 with `bit`, `unpack` and the standard libraries.

```lua
-- users.lua: a different path on every request, so no cache can answer it
local base, max
function init(args)            -- args[0] is the URL, args[1..] what follows it
  base, max = args[1] or "/user/", tonumber(args[2] or "1000")
end
function request()
  return wrk.format("GET", base .. math.random(1, max))
end
```

What carries over from wrk:

- **The `wrk` table.** `scheme`, `host`, `port`, `method`, `path`, `headers`,
  `body`, and `wrk.format(method, path, headers, body)`. `-m`, `-H` and `-b`
  set the starting values.
- **`init(args)`.** Runs once per thread at startup, or once in all for a
  script without `request()`, `response()` or `setup()`, which has no thread
  states (see below). Arguments after the URL reach it, and `--` passes ones
  that start with a dash.
- **`request()`.** Runs once per request, with one Lua state per `-t` thread
  shared by that thread's connections, as in wrk.
- **`response(status, headers, body)`.** Runs once per response, in the same
  state. zrk keeps response headers and bodies only for a script that
  defines it.
- **`setup(thread)` and `done(summary, latency, requests)`.** `setup` runs once
  per thread before `init`, with `thread:get` and `thread:set` to reach that
  thread's globals. `done` runs after the report, with wrk's summary and
  stats objects, so `latency:percentile(99)` works as in wrk.

What is different:

- **A script without `request()`, `response()` or `setup()` costs nothing
  per request.** It only edits `wrk.method`, `wrk.path`, `wrk.headers` or
  `wrk.body`, so its request becomes the fixed one, exactly as if `-m`, `-H`
  and `-b` had described it.
- **Scripts work over `--http2` and `--http3`.** zrk reads the text that
  `request()` returns back into a method, path, headers and body, then sends
  it on whichever transport the run speaks. A `Host` header the script sets
  becomes the request's authority.
- **One request per `request()` call.** wrk's trick of returning several
  requests back to back to pipeline them is refused. `--streams` is zrk's
  way to keep several requests in flight.
- **The script's time is not the server's, and it is reported.** `request()`
  runs before the pacing wait, and before the clock starts in `--closed`
  mode. `response()` runs after the latency is recorded. The report shows
  what both cost and their share of the client's threads; see
  [output.md](docs/output.md#workload-what-a-script-cost).
- **`done`'s `requests` is per `--interval`.** wrk samples requests per second
  per thread every 100 ms; zrk samples the whole run once per `--interval`.
  `summary.errors` gains `deadline` for `--deadline` misses.
- **`delay()` is refused.** `-R` paces requests, and `--closed` sends them back
  to back, so a script that sets its own delay is refused at startup rather
  than run without it. `thread:stop()` and `wrk.lookup` raise an error, and
  `thread.addr` is not provided.

A Lua error stops the run, and zrk reports the file and line.

### HTTP/3

`--http3` speaks HTTP/3 over QUIC through
[h3](https://github.com/zoxy-io/h3), and is **experimental**
([#74](https://github.com/zoxy-io/zrk/issues/74)). It works, and the latency it
reports means what every other transport's does — the coordinated-omission
correction, `--deadline` shedding and the backlog gauge are the same code
reading the same clock. Certificates are verified the same way too: `tls.Trust`
builds the chain to a system anchor and matches the name for all three
transports, so `-k/--insecure` is an opt-out here exactly as it is elsewhere.

Three things are worth knowing before quoting a number from it:

- **Large responses over a real network measure zrk, not the server.** Each
  stream's receive window is 16 KiB, so one stream moves at most 16 KiB per
  round trip. Over loopback that is invisible; at a 62 ms round trip a 126 KB
  page takes about 700 ms against HTTP/2's 110 ms, and a 1.3 MB one runs past
  the default `--timeout`. For responses beyond a few tens of KiB across a
  network, compare against `--http2` before trusting the figure;
  [#89](https://github.com/zoxy-io/zrk/issues/89) tracks raising it.
- **A connection quiet for twice `--timeout` is replaced.** zrk sends no
  keepalive, and a QUIC server forgets an idle connection without a word, so a
  connection that has heard nothing for that long is not trusted with the next
  request. At a rate low enough to leave each connection idle that long — a
  large `-c` at a small `-R`, or the bottom of a ramp — requests carry a fresh
  handshake in their latency.
- **One datagram per syscall on the way out.** Reads are batched — Linux
  generic receive offload collapses a burst into one read, worth about 40%
  against a server that segments — but sends are not. That was measured rather
  than assumed, and the measurement said not to bother: batching them is worth
  around 2% on a send-heavy workload and slightly negative on a receive-heavy
  one, because a QUIC client's egress is 60-to-70-octet packets and send
  syscalls are not what bounds this.
  [#83](https://github.com/zoxy-io/zrk/issues/83) revisits it for a path with
  real latency, which is the one case that could change the answer.

Everything else carries over: `--closed`, ramps, `--timeseries`, the JSON
summary and the CI gates all work unchanged.

`--streams` works here as it does under `--http2`, and getting it there found a
defect in h3: a multiplexed connection ran at full rate for about a second and
then went to zero req/s, reporting no errors, because acknowledged packet
contexts were truncated at thirty-two and the streams past that were never
settled. It is fixed, and `build.zig.zon` pins the commit that fixes it —
`src/h3conn.zig`'s module comment has the diagnosis. A `-c 16 -s 16 --closed`
soak now runs 296,866 requests at 14.8k req/s where it previously managed
1,642 before stalling.

### Exit codes

| code | meaning |
|------|---------|
| 0 | run completed; any configured gates passed |
| 1 | the run failed to start or complete, no request completed, or a `--script` failed (see the message on stderr). Any response counts as completed, a 5xx included: gate on those with `--max-error-rate` |
| 2 | bad arguments, or a `--body` or `--script` file that could not be read or loaded |
| 3 | run completed but a `--slo-p99` / `--max-error-rate` gate was breached |
| 130 | interrupted by SIGINT (`Ctrl-C`); a partial report was still written |
| 143 | interrupted by SIGTERM; a partial report was still written |

## Documentation

| | |
|---|---|
| [Coordinated omission](docs/coordinated-omission.md) | Why the correction exists, when `--closed` is the right tool, and how zrk's clock differs from wrk2's. |
| [HTTP/2 multiplexing](docs/multiplexing.md) | What `-c` and `-s` mean once a connection carries several requests, and why `-c 10 -s 10` is not `-c 100`. |
| [`--timeout` vs `--deadline`](docs/deadlines.md) | Bounding the latency tail under overload, and the backlog gauge. |
| [Machine-readable output](docs/output.md) | The JSON summary, `--hdr`, `--timeseries` NDJSON, and piping rows into a live plotter. |
| [Interrupting a run](docs/signals.md) | What SIGINT/SIGTERM report, and what supervisors should know. |
| [Library usage](docs/library.md) | Driving `runner.run` from Zig instead of the CLI. |
| [How it works](docs/internals.md) | Concurrency model, histogram/memory budget, source layout. |

## License

[MIT](LICENSE)

zrk binaries statically link [LuaJIT](https://luajit.org/) for `--script`,
which is MIT-licensed, Copyright (C) 2005-2026 Mike Pall. Its build script
adapts [ziglua](https://github.com/natecraddock/ziglua)'s, MIT-licensed,
Copyright (c) 2022 Nathan Craddock.
