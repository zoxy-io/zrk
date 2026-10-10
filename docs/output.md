# Machine-readable output

## `--format json` — the final summary

For embedding in a benchmark harness or CI, `--format json` emits a single
summary object (the live dashboard is suppressed) to stdout or `--output <file>`:

```json
{
  "zrk_version": "0.1.0",
  "target": { "url": "http://127.0.0.1:8080/", "method": "GET" },
  "config": { "connections": 50, "streams": 1, "launched": 50, "duration_s": 20.000, "interval_s": 1.000, "closed": false, "disable_keepalive": false, "target_rate": 1000, "target_rate_end": 1000, "timeout_ms": 2000, "deadline_ms": 0, "deadline_abort": false, "record_timeouts": true },
  "duration_s": 20.002,
  "requests": 19998,
  "bytes": 1239876,
  "achieved_rate": 999.80,
  "target_rate": 1000,
  "target_rate_end": 1000,
  "rate_ratio": 0.9998,
  "achieved_rate_end": 999.91,
  "rate_ratio_end": 0.9999,
  "end_window_s": 1.000,
  "bytes_per_sec": 61987.30,
  "error_rate": 0.000000,
  "max_schedule_lag_us": 84,
  "latency_us": { "min": 106, "mean": 422.0, "stdev": 1222.9, "max": 13991,
                  "p50": 251, "p75": 337, "p90": 471, "p99": 1913, "p99_9": 13364, "p99_99": 13988 },
  "status_codes": { "1xx": 0, "2xx": 19998, "3xx": 0, "4xx": 0, "5xx": 0 },
  "errors": { "connect": 0, "read": 0, "write": 0, "timeout": 0, "deadline": 0, "non_2xx_3xx": 0 },
  "latency_histogram": "HISTFAAAAUJ4nC1P..."
}
```

`latency_histogram` is the **complete** latency distribution encoded as an
HdrHistogram **V2 compressed** base64 blob — the same interchange format the
Java/Go/JS/Rust HdrHistogram libraries read. It decodes losslessly, so a harness
can store the raw histogram and later re-percentile it, diff two runs, or merge
many runs into one aggregate — none of which the summarized percentiles allow.
`zrk` can round-trip it too (`hdr.decodeBase64`), e.g. to merge prior runs.

### `workload`: what a script cost

A run whose `--script` defines `request()`, `response()` or `setup()` gets one
more key. So does a library run with a `Workload`. Runs without one have no
`workload` key at all.

```json
  "workload": {
    "thread_share": 0.004967,
    "next":     { "calls": 1604, "total_ms": 19.872, "mean_us": 12.389, "p50_us": 8.928, "p99_us": 57.984, "max_us": 346.111 },
    "response": { "calls": 0, "total_ms": 0.000, "mean_us": 0.000, "p50_us": 0.000, "p99_us": 0.000, "max_us": 0.000 }
  },
```

- **`next`** times `request()` calls. **`response`** times `response()` calls.
  A request held from an earlier call is not a call, so `calls` can be lower
  than `requests`.
- **`thread_share`** is the time in both kinds of call over `duration_s × -t`:
  the fraction of the client's threads the script used. A share near 1 means
  the script, not the server, is what limits the run.
- **Times are wall time.** A call that waited for its thread's Lua state,
  shared by that thread's connections, counts the wait.

The text report prints the same as one line, under the latency percentiles:

```
  script: request() 1604 calls, p50 6.6us p99 67.3us, response() 1600 calls, p50 5.5us p99 46.7us  ·  0.74% of client thread time
```

`achieved_rate` / `rate_ratio` tell you whether the client actually sustained
the target load. **If `rate_ratio` is well below 1.0, the client was saturated
(one request in flight per connection) and the latency numbers reflect client
backpressure, not the server: increase `-c`.** For a ramp, that same pair reads
as "how far up the ramp did the target actually get" — see below.

### Constant load vs. a ramp

Under **constant** load `achieved_rate` is the whole run averaged —
`requests / duration_s` — and `rate_ratio` holds it against `-R`.

Under a **ramp** (`-R A:B`) that average is the midpoint of the offered range
and describes no part of the run: `-R100:1000` reports ~550 whether the server
held 1000 all the way up or fell over at 200. So a ramp's `achieved_rate` is its
**tail** instead — the rate served over the last `end_window_s` (one
`config.interval_s`, give or take), which is the max sustained rate the ramp was
run to find. `bytes_per_sec` covers the same window, so the two stay
proportional. The whole-run average is still `requests / duration_s` if you want
it.

`rate_ratio` divides by the load *offered during that same window*, never by
`target_rate_end`. `achieved_rate` is an average across a window in which the
ramp keeps climbing, while `target_rate_end` is the schedule's value at the
final instant; dividing one by the other would book a perfectly kept ramp as
short by half a window of slope. A ramp that kept its schedule to the top
reports `rate_ratio` ~1.0; one that saturated reports the fraction it managed.

| field | what it is |
| --- | --- |
| `achieved_rate` | the run's throughput: the tail under a ramp, the whole-run average otherwise |
| `rate_ratio` | `achieved_rate` over the load offered across the same span |
| `achieved_rate_end` | **always** the tail, so a harness can read one key without knowing whether a ramp was configured |
| `rate_ratio_end` | `achieved_rate_end` over the load offered during that window |
| `target_rate_end` | the offered rate the ramp climbed to (`B`), or `target_rate` for constant load |
| `end_window_s` | how long the tail window was |

Under a ramp the `*_end` pair is identical to the top-level pair. Under constant
load it is the last window rather than the whole run — which is how a server
that degraded partway through a run shows up at all. It is normally the number
the last `--timeseries` row reports, available without asking for the series —
but don't assert equality: a duration that isn't a whole number of intervals
ends on a sliver of a row that zrk deliberately reaches past, and an interrupted
run raises no row at the signal at all. A run shorter than a single window has
no tail to measure and falls back to the whole-run average.

`end_window_s` is the window's length, and it closes at the last progress row —
which on an interrupted run can be most of an `--interval` before `duration_s`.
Both ratios account for that, so a ramp cut short by Ctrl-C is still judged
against the load offered where its window actually sat.

Under `--closed` (`config.closed: true`) there is no offered rate to compare
against, and `--closed` cannot ramp, so `achieved_rate` is the whole-run
average, `target_rate` mirrors it, `target_rate_end` mirrors
`achieved_rate_end`, and both ratios are always 1.0 — a consumer that doesn't
special-case `--closed` still gets coherent numbers instead of the unrelated
default `-R`.

Note that `config.target_rate` / `config.target_rate_end` are the `-R` endpoints
**as given** (equal for a constant run), while the top-level pair is the
*offered schedule*, which `--closed` redefines as above.

Timed-out requests are recorded into the latency histogram by default (as a
coordinated-omission-corrected sample) so the tail isn't silently truncated;
`--no-record-timeouts` restores wrk2's drop-on-timeout behavior.

## `--hdr` — HdrHistogram percentile distribution

`--hdr <file>` writes the classic HdrHistogram percentile distribution (values
in milliseconds), directly loadable by the
[HdrHistogram plotter](https://hdrhistogram.github.io/HdrHistogram/plotFiles.html)
and format-compatible with wrk2's `--latency` output.

## `--timeseries` — per-interval NDJSON

`--timeseries <file>` streams one NDJSON object per `--interval`, each carrying
that window's offered `target_rate` (the ramp's schedule averaged *across* the
window, so it is directly comparable to the `achieved_rate` beside it rather
than sitting half a window of slope above it), `achieved_rate`, request/error counts,
transfer (`bytes`, `bytes_per_sec`), the backlog gauge, and a delta-histogram
latency percentile set:

```
{"t":1.006,"target_rate":480.0,"achieved_rate":476.2,"requests":476,"errors":3,"error_rate":0.006263,"errors_by_kind":{"connect":0,"read":0,"write":0,"timeout":1,"deadline":2,"non_2xx_3xx":0},"bytes":58852,"bytes_per_sec":58501.0,"max_schedule_lag_us":18524,"latency_us":{"p50":245,"p90":669,"p99":1745,"p99_9":2401,"max":2401}}
```

This is the artifact a **ramp** (`-R A:B`) exists to produce: a curve of latency
against offered load, so you can find the rate at which the server's tail breaks
down. (The final summary's aggregate percentiles blend the whole ramp together,
so they're less useful for a ramp than the time series is. Its throughput is not
blended, though: the summary's `achieved_rate` is this file's last
`achieved_rate`, so a harness that only wants the rate the ramp reached does not
need the series at all.)

Every count in a row is that **interval's** delta, so the rows sum to the run.
`errors_by_kind` splits the `errors` scalar the same way the final summary's
`errors` object does — worth plotting stacked, because a tail that broke into
`deadline` misses and one that broke into `connect` failures are different
findings that the single number cannot tell apart.

`error_rate` is that window's failure fraction, computed exactly like the
summary's top-level `error_rate` (and so directly comparable to it and to the
`--max-error-rate` gate). Plot this rather than the raw `errors` count: it sits
on a fixed 0..1 axis regardless of what `--interval` is set to, whereas the
count silently rescales with the window. Over a single interval the two
definitions coincide, so a one-window run's row reports the summary's number.

`max_schedule_lag_us` is the one exception: it is the **cumulative** peak
`now − scheduled` the fleet has reached *as of* that row, the same running gauge
the summary reports, not the interval's own peak. It is aggregated by max rather
than summed, so there is nothing to difference — an interval-local peak would
mean resetting the gauge on the row cadence and costing the final report its
true high-water mark. Read the series as a staircase: each riser marks the
window in which the client fell further behind its schedule than it ever had
before, which is what dates the onset of a backlog against the latency it
explains.

Add `--timeseries-histogram` to append each interval's **full** latency
distribution as an HdrHistogram V2 base64 blob (`latency_histogram`) to every
row. Each blob decodes losslessly, so a harness can re-percentile a single
interval or merge any subset of them — e.g. just the windows above a target
rate. Merging every row reproduces the run's summary histogram exactly, since
the intervals partition the run. (Rows get noticeably larger, so it is opt-in.)

## Streaming to a live plotter

`--timeseries -` sends the rows to **stdout** instead of a file, so they can be
piped straight into a streaming plotter such as
[jplot](https://github.com/rs/jplot), which reads newline-delimited JSON and
addresses fields by dotted path:

```sh
zrk -c50 -R1000 -d5m --timeseries - http://127.0.0.1:8080/ \
  | jplot achieved_rate+target_rate \
          latency_us.p50+latency_us.p90+latency_us.p99 \
          error_rate
```

Each space-separated spec is its own graph, so keep `error_rate` off the
throughput one — it is a 0..1 fraction, not a req/s figure. Do **not** prefix
zrk's fields with jplot's `counter:`: that option exists to difference
monotonic counters, and these rows are already per-interval deltas. There is no
`jaggr` stage either: aggregating raw samples into per-interval percentiles is
what zrk already does in-process, with real HdrHistograms.

Because stdout then belongs to the row stream, `--timeseries -` suppresses the
live dashboard and sends the final report to `--output` if given, else to
**stderr** — so the summary still lands in your terminal without corrupting the
pipe.

Pair it with `-o` when the report is machine-read: `--format json --timeseries -`
puts the JSON summary on stderr *alongside* the human notices (an SLO breach, a
sink warning), so a parser reading stderr whole can trip over the trailing line.
`--format json -o result.json --timeseries -` keeps all three streams apart —
rows on stdout, report in the file, notices on stderr.
