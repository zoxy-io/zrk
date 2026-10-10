//! Machine-readable reporting: a single JSON summary of a completed run, and
//! the SLO gates that decide the process exit code. The human-facing live
//! dashboard and wrk2-style text report live in `tui.zig`; this module is what
//! an embedding benchmark harness (or CI) parses.

const std = @import("std");
const Io = std.Io;

const cli = @import("cli.zig");
const stats = @import("stats.zig");
const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const workload = @import("workload.zig");

/// Fraction of outcomes that were failures: non-2xx/3xx responses, socket
/// errors (connect/read/write/timeout), and `--deadline` misses, over all
/// attempts. Deadline misses count as both a failure and an attempt, so under
/// overload the rate reflects the fraction of the offered schedule that could
/// not be served within the deadline. 0 when idle.
pub fn errorRate(c: connection.Counters) f64 {
    return failureFraction(c.completed, c.status_errors, c.socketErrors() + c.deadline_errors);
}

/// The arithmetic behind both `errorRate` and the per-interval `error_rate` row
/// field, factored out so the summary and the time series cannot drift apart.
/// `failures` are the attempts that never produced a response (socket errors and
/// deadline misses); each counts as an error *and* as an attempt, so a window
/// spent shedding a backlog reports a rate near 1 rather than dividing by the
/// handful of requests that got through.
fn failureFraction(completed: u64, status_errs: u64, failures: u64) f64 {
    const errs = status_errs + failures;
    const total = completed + failures;
    if (total == 0) return 0;
    return @as(f64, @floatFromInt(errs)) / @as(f64, @floatFromInt(total));
}

/// Outcome of the CI gates. `passed()` is the AND of every configured gate;
/// gates that were not requested are considered passing.
pub const SloResult = struct {
    p99_ok: bool = true,
    error_rate_ok: bool = true,

    pub fn passed(self: SloResult) bool {
        return self.p99_ok and self.error_rate_ok;
    }
};

/// Evaluate the `--slo-p99` / `--max-error-rate` gates against the final snapshot.
pub fn checkSlo(cfg: *const cli.Config, snap: *const stats.Snapshot) SloResult {
    var r: SloResult = .{};
    if (cfg.slo_p99_ns) |limit_ns| {
        const p99_ns = snap.hist.valueAtPercentile(99) * std.time.ns_per_us;
        r.p99_ok = p99_ns <= limit_ns;
    }
    if (cfg.max_error_rate) |limit| {
        r.error_rate_ok = errorRate(snap.counters) <= limit;
    }
    return r;
}

/// Offered *total* target rate (req/s) at elapsed `t_s`, honoring a ramp — the
/// schedule `pace` is driving, sampled for reporting. Constant when `-R` has no
/// end, and clamped to the ramp's endpoints outside the configured duration.
/// `--closed` has no offered rate at all; callers substitute the achieved one
/// there (which is what makes its rate ratios 1).
pub fn offeredRate(cfg: *const cli.Config, t_s: f64) f64 {
    const start: f64 = @floatFromInt(cfg.rate);
    const end_rate = cfg.rate_end orelse return start;
    const end: f64 = @floatFromInt(end_rate);
    const dur = @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s;
    if (dur <= 0) return end;
    const frac = std.math.clamp(t_s / dur, 0, 1);
    return start + (end - start) * frac;
}

/// The run-level facts the summary reports alongside the merged snapshot —
/// `runner.Report` minus the snapshot itself. A struct rather than a tail of
/// positional parameters so that adding a measurement doesn't reshuffle every
/// call site.
pub const Run = struct {
    elapsed_s: f64,
    launched: u32,
    interrupted: bool = false,
    /// Throughput over the run's final `--interval` window, and when that
    /// window closed; see `runner.Report.end_rate`. A caller with no window to
    /// report leaves `end_window_s` at 0, and the whole run stands in for it.
    end_rate: f64 = 0,
    end_bytes_per_sec: f64 = 0,
    end_window_s: f64 = 0,
    end_window_at_s: f64 = 0,
    /// What a workload's calls cost — a `--script`'s, for one — when the run
    /// had one; see `workload.Timing`.
    workload: ?workload.TimingSummary = null,
};

/// The share of the client's thread time a workload's calls took: their total
/// over `elapsed × threads`. For a script, that total is Lua time measured
/// inside each thread state's lock, so the share cannot exceed 1. For a
/// library workload zrk times from outside, it is wall time including any
/// wait inside the calls, and can.
pub fn workloadShare(run: Run, threads: u8) f64 {
    const timing = run.workload orelse return 0;
    const capacity = run.elapsed_s * @as(f64, @floatFromInt(@max(threads, 1))) * std.time.ns_per_s;
    if (capacity <= 0) return 0;
    const spent: f64 = @floatFromInt(timing.next.total_ns + timing.response.total_ns);
    return spent / capacity;
}

/// Write the JSON run summary. Latencies are microseconds (the histogram's
/// native unit); `duration_s`/`*_rate` are derived from the measured elapsed
/// time. `latency_histogram` is the full distribution as an HdrHistogram V2
/// compressed base64 blob, so the run can be losslessly re-percentiled or merged
/// later. `gpa` is used only for that transient encoding. All strings are
/// JSON-escaped.
pub fn writeJson(
    gpa: std.mem.Allocator,
    w: *Io.Writer,
    cfg: *const cli.Config,
    snap: *const stats.Snapshot,
    run: Run,
) !void {
    const c = snap.counters;
    const h = &snap.hist;
    const elapsed_s = run.elapsed_s;
    const ramping = cfg.rate_end != null;
    const rate_end = cfg.rate_end orelse cfg.rate;
    const mean_rate: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.completed)) / elapsed_s else 0;
    const mean_bps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.bytes)) / elapsed_s else 0;

    // An embedder driving `runner.run` gets a measured window; one building a
    // `Run` by hand (the library docs show only `elapsed_s`/`launched`) may
    // report none. The whole run is then the only window there is — without
    // this a ramp's `achieved_rate` would come out 0.00 rather than merely
    // coarse, and --closed's ratios would contradict their documented 1.0.
    const measured = run.end_window_s > 0;
    const end_rate: f64 = if (measured) run.end_rate else mean_rate;
    const end_bps: f64 = if (measured) run.end_bytes_per_sec else mean_bps;
    const end_window_s: f64 = if (measured) run.end_window_s else elapsed_s;
    // Judged on its own, so a caller that reported a window but not when it
    // closed lands where `runner.run` puts it bar the fleet join, rather than
    // at second zero — where a ramp's schedule would read as its start rate.
    const end_window_at_s: f64 = if (run.end_window_at_s > 0) run.end_window_at_s else elapsed_s;

    // Headline throughput. Averaging the whole run is right under constant load
    // and wrong under a ramp, where the average is the midpoint of the offered
    // range and describes no part of the run: `-R100:1000` reports ~550 whether
    // the target held 1000 to the top or fell over at 200. So a ramp reports
    // its *tail* — the last `end_window_s`, the rate the target was actually
    // serving when the run ended, which is the number the ramp was run to find.
    // The average is still `requests / duration_s` for anyone who wants it.
    const achieved: f64 = if (ramping) end_rate else mean_rate;
    const bps: f64 = if (ramping) end_bps else mean_bps;

    // The offered load to hold `achieved` against, over the span it was actually
    // measured over: the ramp's schedule at the tail window's midpoint, or the
    // flat rate. In --closed mode there is no offered rate at all — report
    // target == achieved (rate_ratio == 1) so a consumer that doesn't
    // special-case --closed still gets coherent numbers instead of the
    // unrelated default `rate`. (--closed and a ramp are mutually exclusive,
    // so `achieved` is the average in every --closed branch here.)
    // Anchored on when the window *closed*, not on `elapsed_s`: the two differ
    // by the fleet join, and by most of an `--interval` when a signal cut the
    // run short between rows. Reading the schedule that far further up a ramp
    // overstates the offered load and books a kept ramp as short.
    const window_mid_s = end_window_at_s - end_window_s / 2.0;
    const offered_end: f64 = if (cfg.closed) end_rate else offeredRate(cfg, window_mid_s);
    const target_rate: u64 = if (cfg.closed) @intFromFloat(@round(mean_rate)) else cfg.rate;
    const target_rate_end: u64 = if (cfg.closed) @intFromFloat(@round(end_rate)) else rate_end;
    const offered: f64 = if (cfg.closed)
        mean_rate
    else if (ramping)
        offered_end
    else
        @as(f64, @floatFromInt(cfg.rate));

    try w.writeAll("{\n");
    try w.print("  \"zrk_version\": \"{s}\",\n", .{cli.version});

    try w.writeAll("  \"target\": { \"url\": ");
    try writeUrl(w, cfg);
    try w.writeAll(", \"method\": ");
    try writeJsonString(w, cfg.method);
    try w.writeAll(" },\n");

    // The configuration as given, not as interpreted: `target_rate`/
    // `target_rate_end` here are the `-R` endpoints verbatim (equal for a
    // constant run), while the top-level pair below is the *offered* schedule,
    // which --closed redefines. `interval_s` is the stats window, and so the
    // window `achieved_rate_end` is measured over.
    try w.writeAll("  \"config\": {");
    try w.print(
        " \"connections\": {d}, \"streams\": {d}, \"launched\": {d}, \"duration_s\": {d:.3}, \"interval_s\": {d:.3}, \"closed\": {}, \"disable_keepalive\": {}, \"target_rate\": {d}, \"target_rate_end\": {d}, \"timeout_ms\": {d}, \"deadline_ms\": {d}, \"deadline_abort\": {}, \"record_timeouts\": {} }},\n",
        .{
            cfg.connections,
            cfg.streams,
            run.launched,
            @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s,
            @as(f64, @floatFromInt(cfg.interval_ns)) / std.time.ns_per_s,
            cfg.closed,
            cfg.disable_keepalive,
            cfg.rate,
            rate_end,
            cfg.timeout_ns / std.time.ns_per_ms,
            cfg.deadline_ns / std.time.ns_per_ms,
            cfg.deadline_abort,
            cfg.record_timeouts,
        },
    );

    try w.print("  \"duration_s\": {d:.3},\n", .{elapsed_s});
    // Explicit rather than leaving a consumer to infer it from duration_s being
    // short of config.duration_s: an interrupted run is not a completed one, and
    // whatever reads this (a CI gate, a regression baseline) needs to say so.
    if (run.interrupted) try w.print("  \"interrupted\": true,\n", .{});
    try w.print("  \"requests\": {d},\n", .{c.completed});
    try w.print("  \"bytes\": {d},\n", .{c.bytes});
    try w.print("  \"achieved_rate\": {d:.2},\n", .{achieved});
    try w.print("  \"target_rate\": {d},\n", .{target_rate});
    try w.print("  \"target_rate_end\": {d},\n", .{target_rate_end});
    try w.print("  \"rate_ratio\": {d:.4},\n", .{if (offered > 0) achieved / offered else 0});
    // The tail, unconditionally — so a harness can read one key without first
    // working out whether a ramp was configured. Under a ramp these are the
    // same two numbers as above; under constant load they are the last window
    // rather than the whole run, which is how a target that degraded partway
    // through shows up at all.
    //
    // Both ratios divide by the offered load averaged over the window the rate
    // was measured across, never by `target_rate_end`. `achieved_rate_end` is
    // an average over a window during which a ramp keeps climbing, while
    // `target_rate_end` is the schedule's value at the final instant; dividing
    // one by the other would book a perfectly kept ramp as short by half a
    // window of slope.
    try w.print("  \"achieved_rate_end\": {d:.2},\n", .{end_rate});
    try w.print("  \"rate_ratio_end\": {d:.4},\n", .{
        if (offered_end > 0) end_rate / offered_end else 0,
    });
    try w.print("  \"end_window_s\": {d:.3},\n", .{end_window_s});
    try w.print("  \"bytes_per_sec\": {d:.2},\n", .{bps});
    try w.print("  \"error_rate\": {d:.6},\n", .{errorRate(c)});
    // Peak schedule lag (µs): how far behind its intended send the fleet ever
    // fell — the backlog gauge. Large values mean the client couldn't sustain
    // the offered schedule (see also achieved_rate / rate_ratio).
    try w.print("  \"max_schedule_lag_us\": {d},\n", .{c.max_behind_ns / std.time.ns_per_us});

    try w.writeAll("  \"latency_us\": {\n");
    try w.print("    \"min\": {d}, \"mean\": {d:.1}, \"stdev\": {d:.1}, \"max\": {d},\n", .{
        h.min(), h.mean(), h.stdDev(), h.max(),
    });
    try w.print("    \"p50\": {d}, \"p75\": {d}, \"p90\": {d}, \"p99\": {d}, \"p99_9\": {d}, \"p99_99\": {d}\n", .{
        h.valueAtPercentile(50), h.valueAtPercentile(75),   h.valueAtPercentile(90),
        h.valueAtPercentile(99), h.valueAtPercentile(99.9), h.valueAtPercentile(99.99),
    });
    try w.writeAll("  },\n");

    try w.writeAll("  \"status_codes\": {");
    try w.print(" \"1xx\": {d}, \"2xx\": {d}, \"3xx\": {d}, \"4xx\": {d}, \"5xx\": {d} }},\n", .{
        c.status_class[1], c.status_class[2], c.status_class[3], c.status_class[4], c.status_class[5],
    });

    try w.writeAll("  \"errors\": {");
    try w.print(" \"connect\": {d}, \"read\": {d}, \"write\": {d}, \"timeout\": {d}, \"deadline\": {d}, \"non_2xx_3xx\": {d} }},\n", .{
        c.connect_errors, c.read_errors, c.write_errors, c.timeouts, c.deadline_errors, c.status_errors,
    });

    // Present only for a run with a workload: absent and all-zero would say
    // different things.
    if (run.workload) |timing| {
        try w.writeAll("  \"workload\": {\n");
        try w.print("    \"thread_share\": {d:.6},\n", .{workloadShare(run, cfg.threads)});
        try writeCallStats(w, "next", timing.next, ",");
        try writeCallStats(w, "response", timing.response, "");
        try w.writeAll("  },\n");
    }

    // Full distribution, losslessly re-decodable by any HdrHistogram library.
    const b64 = try h.encodeBase64(gpa);
    defer gpa.free(b64);
    try w.print("  \"latency_histogram\": \"{s}\"\n", .{b64});

    try w.writeAll("}\n");
}

fn writeCallStats(w: *Io.Writer, name: []const u8, s: workload.CallStats, comma: []const u8) !void {
    try w.print(
        "    \"{s}\": {{ \"calls\": {d}, \"total_ms\": {d:.3}, \"mean_us\": {d:.3}, \"p50_us\": {d:.3}, \"p99_us\": {d:.3}, \"max_us\": {d:.3} }}{s}\n",
        .{
            name,
            s.calls,
            @as(f64, @floatFromInt(s.total_ns)) / std.time.ns_per_ms,
            s.mean_ns / std.time.ns_per_us,
            @as(f64, @floatFromInt(s.p50_ns)) / std.time.ns_per_us,
            @as(f64, @floatFromInt(s.p99_ns)) / std.time.ns_per_us,
            @as(f64, @floatFromInt(s.max_ns)) / std.time.ns_per_us,
            comma,
        },
    );
}

/// Streams one NDJSON line per progress interval: the *interval's* throughput
/// and latency percentiles (from a delta histogram), plus the offered target
/// rate — the artifact a ramp needs to show latency vs. offered load. Driven by
/// the runner's progress callback with successive cumulative snapshots.
pub const TimeSeries = struct {
    w: *Io.Writer,
    cfg: *const cli.Config,
    /// Previous cumulative histogram; `snap.hist - prev_cum` is the interval.
    prev_cum: hdr.Histogram,
    /// Scratch histogram holding the current interval's delta.
    delta: hdr.Histogram,
    /// Reset (retaining capacity) after each row's base64 encoding, so the
    /// transient encode buffers never accumulate in the caller's arena when
    /// `--timeseries-histogram` is on. Backed by the page allocator.
    scratch: std.heap.ArenaAllocator,
    /// Previous cumulative counters: every count in a row is `snap - prev`.
    /// `max_behind_ns` is the exception — it is a running peak, not a tally,
    /// so it is reported as-is rather than differenced (see `record`).
    prev_counters: connection.Counters = .{},
    prev_elapsed_s: f64 = 0,

    pub fn init(arena: std.mem.Allocator, w: *Io.Writer, cfg: *const cli.Config) !TimeSeries {
        return .{
            .w = w,
            .cfg = cfg,
            .prev_cum = try stats.newHistogram(arena),
            .delta = try stats.newHistogram(arena),
            .scratch = .init(std.heap.page_allocator),
        };
    }

    pub fn deinit(self: *TimeSeries) void {
        self.prev_cum.deinit();
        self.delta.deinit();
        self.scratch.deinit();
    }

    /// Emit the line for the interval ending at `elapsed_s` and advance state.
    pub fn record(self: *TimeSeries, snap: *const stats.Snapshot, elapsed_s: f64) !void {
        self.delta.setToDifference(&snap.hist, &self.prev_cum);
        const h = &self.delta;

        const c = snap.counters;
        const p = self.prev_counters;
        const interval_s = elapsed_s - self.prev_elapsed_s;
        const d_completed = c.completed -| p.completed;
        const d_bytes = c.bytes -| p.bytes;
        // Per-kind, so a consumer can plot *how* a window failed — a tail that
        // broke into deadline misses is a different story from one that broke
        // into connect errors, and the scalar `errors` cannot tell them apart.
        const d_connect = c.connect_errors -| p.connect_errors;
        const d_read = c.read_errors -| p.read_errors;
        const d_write = c.write_errors -| p.write_errors;
        const d_timeout = c.timeouts -| p.timeouts;
        const d_deadline = c.deadline_errors -| p.deadline_errors;
        const d_status = c.status_errors -| p.status_errors;
        const d_failures = d_connect + d_read + d_write + d_timeout + d_deadline;
        const d_errors = d_failures + d_status;
        const achieved: f64 = if (interval_s > 0) @as(f64, @floatFromInt(d_completed)) / interval_s else 0;
        const bps: f64 = if (interval_s > 0) @as(f64, @floatFromInt(d_bytes)) / interval_s else 0;

        // `target_rate` is the load offered *across* this window — the ramp's
        // schedule at its midpoint — not the schedule at the instant the window
        // closes. `achieved_rate` beside it is a window average, and a ramp
        // climbs while the window runs, so the endpoint would sit half a window
        // of slope above it: plotted together (the README's jplot pipeline), a
        // target that kept its schedule perfectly would draw a permanent gap.
        //
        // `error_rate` is this window's failure fraction, computed exactly like
        // the summary's — so a row is directly comparable to the final number
        // and to the `--max-error-rate` gate, and stays on one 0..1 axis no
        // matter what `--interval` is set to (the raw `errors` count does not).
        try self.w.print(
            "{{\"t\":{d:.3},\"target_rate\":{d:.1},\"achieved_rate\":{d:.1},\"requests\":{d}," ++
                "\"errors\":{d},\"error_rate\":{d:.6},",
            .{
                elapsed_s, if (self.cfg.closed) achieved else offeredRate(self.cfg, elapsed_s - interval_s / 2),
                achieved,  d_completed,
                d_errors,  failureFraction(d_completed, d_status, d_failures),
            },
        );
        try self.w.print(
            "\"errors_by_kind\":{{\"connect\":{d},\"read\":{d},\"write\":{d}," ++
                "\"timeout\":{d},\"deadline\":{d},\"non_2xx_3xx\":{d}}},",
            .{ d_connect, d_read, d_write, d_timeout, d_deadline, d_status },
        );
        // The backlog gauge, in the row so it can be read against the same time
        // axis as the latency it explains. Unlike every other count here it is
        // *cumulative*: `max_behind_ns` is a running peak that is aggregated by
        // max, not summed, so there is nothing to difference — an interval-local
        // peak would need the connections to reset the gauge on the row cadence,
        // which would cost the final report its true peak. Read the series as a
        // staircase: each riser marks the window in which the fleet fell further
        // behind its schedule than it ever had before.
        try self.w.print(
            "\"bytes\":{d},\"bytes_per_sec\":{d:.1},\"max_schedule_lag_us\":{d}," ++
                "\"latency_us\":{{\"p50\":{d},\"p90\":{d},\"p99\":{d},\"p99_9\":{d},\"max\":{d}}}",
            .{
                d_bytes,                              bps,
                c.max_behind_ns / std.time.ns_per_us, h.valueAtPercentile(50),
                h.valueAtPercentile(90),              h.valueAtPercentile(99),
                h.valueAtPercentile(99.9),            h.max(),
            },
        );

        // Optional: the interval's full distribution, losslessly mergeable.
        // Encoded into the scratch arena, which we reset once the bytes have
        // been copied into the writer by `print`.
        if (self.cfg.timeseries_histogram) {
            const b64 = try h.encodeBase64(self.scratch.allocator());
            try self.w.print(",\"latency_histogram\":\"{s}\"", .{b64});
            _ = self.scratch.reset(.retain_capacity);
        }

        // Flush every line so the series is durable even if a later SLO gate
        // exits the process (which skips deferred cleanup).
        try self.w.writeAll("}\n");
        try self.w.flush();

        snap.hist.copyInto(&self.prev_cum);
        self.prev_counters = c;
        self.prev_elapsed_s = elapsed_s;
    }
};

/// Emit the reconstructed `scheme://host:port/target` as a JSON string.
fn writeUrl(w: *Io.Writer, cfg: *const cli.Config) !void {
    try w.writeByte('"');
    try w.print("{s}://", .{@tagName(cfg.url.scheme)});
    try writeEscaped(w, cfg.url.host);
    try w.print(":{d}", .{cfg.url.port});
    try writeEscaped(w, cfg.url.target);
    try w.writeByte('"');
}

fn writeJsonString(w: *Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    try writeEscaped(w, s);
    try w.writeByte('"');
}

/// Write `s` with JSON string escaping, without the surrounding quotes.
fn writeEscaped(w: *Io.Writer, s: []const u8) !void {
    for (s) |ch| switch (ch) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (ch < 0x20) {
            try w.print("\\u{x:0>4}", .{ch});
        } else {
            try w.writeByte(ch);
        },
    };
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn testConfig() cli.Config {
    return .{
        .connections = 4,
        .rate = 1000,
        .url = cli.parseUrl("http://127.0.0.1:8080/health") catch unreachable,
    };
}

test "writeJson emits parseable, well-formed summary" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    var i: u64 = 0;
    while (i < 100) : (i += 1) snap.hist.record(1000 + i);
    snap.counters.completed = 100;
    snap.counters.bytes = 4200;
    snap.counters.recordStatus(200);
    snap.counters.recordStatus(500);
    snap.counters.deadline_errors = 7;
    snap.counters.max_behind_ns = 12_000; // 12ms peak lag

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig();
    cfg.deadline_ns = 250 * std.time.ns_per_ms;
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{ .elapsed_s = 1.0, .launched = 4, .end_rate = 100, .end_window_s = 1.0 });
    const out = alloc.written();

    // Spot-check structure and key fields.
    try testing.expect(std.mem.startsWith(u8, out, "{\n"));
    try testing.expect(std.mem.endsWith(u8, out, "}\n"));
    try testing.expect(std.mem.indexOf(u8, out, "\"zrk_version\": \"" ++ cli.version ++ "\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"url\": \"http://127.0.0.1:8080/health\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"requests\": 100") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"target_rate\": 1000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"5xx\": 1") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"latency_us\"") != null);
    // Deadline mode surfaces in config, the errors object, and the backlog gauge.
    try testing.expect(std.mem.indexOf(u8, out, "\"deadline_ms\": 250") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"deadline_abort\": false") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"deadline\": 7") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"max_schedule_lag_us\": 12") != null);
    // The embedded HdrHistogram blob is present and decodes back to 100 samples.
    try testing.expect(std.mem.indexOf(u8, out, "\"latency_histogram\": \"HIST") != null);
}

test "writeJson reports target_rate as achieved under --closed" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    snap.counters.completed = 500; // 500 requests / 1.0s => achieved_rate 500
    snap.counters.recordStatus(200);

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig();
    cfg.closed = true; // cfg.rate is still the unrelated default 1000
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{ .elapsed_s = 1.0, .launched = 4, .end_rate = 500, .end_window_s = 1.0 });
    // --closed cannot ramp, so achieved_rate stays the whole-run average here.
    const out = alloc.written();

    try testing.expect(std.mem.indexOf(u8, out, "\"closed\": true") != null);
    // Both the top-level target_rate/target_rate_end and rate_ratio track the
    // achieved rate, not the ignored `-R` default -- a consumer that doesn't
    // know about --closed still sees a coherent 1.0 ratio instead of a
    // meaningless comparison against 1000.
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 500.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"target_rate\": 500,") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"target_rate_end\": 500,") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate_end\": 500.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio_end\": 1.0000") != null);
}

test "a ramp's achieved_rate is its tail, not its whole-run average" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    // A 10s -R100:1000 ramp that kept its schedule exactly: 5500 requests, so
    // the whole run averages 550 — the midpoint of the offered range, and a
    // number the target never served for a moment.
    snap.counters.completed = 5500;
    snap.counters.bytes = 220_000;
    snap.counters.recordStatus(200);

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig();
    cfg.rate = 100;
    cfg.rate_end = 1000;
    cfg.duration_ns = 10 * std.time.ns_per_s;
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{
        .elapsed_s = 10.0,
        .launched = 4,
        // The final second of that ramp offers 910..1000, averaging 955 — so a
        // target that held the schedule to the top reports 955, not 1000.
        .end_rate = 955,
        .end_bytes_per_sec = 38_200,
        .end_window_s = 1.0,
    });
    const out = alloc.written();

    // The config section carries both ends of `-R`, so a consumer can see what
    // was asked for without re-parsing the command line.
    try testing.expect(std.mem.indexOf(u8, out, "\"target_rate\": 100, \"target_rate_end\": 1000,") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"interval_s\": 1.000") != null);

    // The headline throughput is the tail. `rate_ratio` holds it against the
    // load offered over that same second (955), not against the ramp's endpoint
    // (1000) — an endpoint comparison would report 0.955 for a run that missed
    // nothing.
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 955.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"bytes_per_sec\": 38200.00") != null);
    // The average is emphatically not the headline, but stays recoverable from
    // the two fields it is the quotient of.
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 550") == null);
    try testing.expect(std.mem.indexOf(u8, out, "\"requests\": 5500") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"duration_s\": 10.000") != null);

    // The unconditional tail keys mirror them under a ramp.
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate_end\": 955.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio_end\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"end_window_s\": 1.000") != null);
}

test "an interrupted ramp is judged where its window actually sat" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();
    snap.counters.completed = 1000;
    snap.counters.recordStatus(200);

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig();
    cfg.rate = 100;
    cfg.rate_end = 1000;
    cfg.duration_ns = 60 * std.time.ns_per_s;
    cfg.interval_ns = 5 * std.time.ns_per_s;

    // Ctrl-C at t=24s, 4s after the last progress row: a signal raises no row
    // of its own, so the tail window is [15s, 20s] while `elapsed_s` is 24.
    // Over that window the ramp offered 325..400, averaging 362.5 — which the
    // client served exactly. Anchoring on `elapsed_s` instead would read the
    // schedule at 21.5s (~423) and book a kept ramp at 0.857.
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{
        .elapsed_s = 24.0,
        .launched = 4,
        .interrupted = true,
        .end_rate = 362.5,
        .end_bytes_per_sec = 14_500,
        .end_window_s = 5.0,
        .end_window_at_s = 20.0,
    });
    const out = alloc.written();

    try testing.expect(std.mem.indexOf(u8, out, "\"interrupted\": true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 362.50") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio_end\": 1.0000") != null);
}

test "writeJson stands the whole run in for a Run that reports no window" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();
    snap.counters.completed = 5500;
    snap.counters.bytes = 220_000;
    snap.counters.recordStatus(200);

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig();
    cfg.rate = 100;
    cfg.rate_end = 1000;
    cfg.duration_ns = 10 * std.time.ns_per_s;

    // What an embedder building `Run` by hand gets — the library docs show only
    // `elapsed_s` and `launched`. Without the fallback a ramp's headline rate
    // would be the zero default rather than merely coarse.
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{
        .elapsed_s = 10.0,
        .launched = 4,
    });
    const out = alloc.written();
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 550.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"bytes_per_sec\": 22000.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"end_window_s\": 10.000") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 0.00") == null);

    // Same for --closed, whose documented ratios are unconditionally 1.0.
    var closed_out = Io.Writer.Allocating.init(testing.allocator);
    defer closed_out.deinit();
    var closed = testConfig();
    closed.closed = true;
    try writeJson(testing.allocator, &closed_out.writer, &closed, &snap, .{
        .elapsed_s = 10.0,
        .launched = 4,
    });
    try testing.expect(std.mem.indexOf(u8, closed_out.written(), "\"rate_ratio\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, closed_out.written(), "\"rate_ratio_end\": 1.0000") != null);
    try testing.expect(std.mem.indexOf(u8, closed_out.written(), "\"target_rate_end\": 550,") != null);
}

test "a ramp's time-series rows offer the load averaged across each window" {
    var cfg = testConfig();
    cfg.rate = 100;
    cfg.rate_end = 1000;
    cfg.duration_ns = 10 * std.time.ns_per_s;

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var ts = try TimeSeries.init(testing.allocator, &alloc.writer, &cfg);
    defer ts.deinit();

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    // A client keeping the schedule exactly: the second ending at t=2 is
    // offered 190..280, so it serves 235. `target_rate` has to be that same
    // 235 average, not the 280 the schedule reads at the closing instant —
    // otherwise `jplot achieved_rate+target_rate` draws a standing gap for a
    // run that missed nothing.
    snap.hist.record(1000);
    snap.counters.completed = 145;
    try ts.record(&snap, 1.0);
    snap.counters.completed = 145 + 235;
    try ts.record(&snap, 2.0);

    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, alloc.written(), "\n"), '\n');
    try testing.expect(std.mem.indexOf(u8, it.next().?, "\"target_rate\":145.0,\"achieved_rate\":145.0,") != null);
    try testing.expect(std.mem.indexOf(u8, it.next().?, "\"target_rate\":235.0,\"achieved_rate\":235.0,") != null);
}

test "constant load keeps the whole-run average as achieved_rate" {
    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    // 10s at a flat 1000 req/s, but the last second only managed 400: the run
    // average stays the headline (there is no ramp to make it misleading),
    // while the tail keys are what expose the late collapse.
    snap.counters.completed = 9400;
    snap.counters.bytes = 376_000;
    snap.counters.recordStatus(200);

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var cfg = testConfig(); // constant -R 1000
    cfg.duration_ns = 10 * std.time.ns_per_s;
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, .{
        .elapsed_s = 10.0,
        .launched = 4,
        .end_rate = 400,
        .end_bytes_per_sec = 16_000,
        .end_window_s = 1.0,
    });
    const out = alloc.written();

    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate\": 940.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio\": 0.9400") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"bytes_per_sec\": 37600.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"achieved_rate_end\": 400.00") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"rate_ratio_end\": 0.4000") != null);
}

test "time series row carries the interval HDR blob when enabled" {
    var cfg = testConfig();
    cfg.timeseries_histogram = true;

    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var ts = try TimeSeries.init(testing.allocator, &alloc.writer, &cfg);
    defer ts.deinit();

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();
    var i: u64 = 0;
    while (i < 50) : (i += 1) snap.hist.record(1000 + i);
    snap.counters.completed = 50;
    snap.counters.bytes = 4200;

    try ts.record(&snap, 1.0);
    const out = alloc.written();
    try testing.expect(std.mem.indexOf(u8, out, "\"latency_us\":{") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"latency_histogram\":\"HIST") != null);
    // The interval's transfer: byte delta and rate over the 1s window.
    try testing.expect(std.mem.indexOf(u8, out, "\"bytes\":4200,\"bytes_per_sec\":4200.0") != null);
    try testing.expect(std.mem.endsWith(u8, out, "}\n"));

    // The blob decodes back to this interval's 50 samples.
    const start = std.mem.indexOf(u8, out, "HIST").?;
    const end = std.mem.indexOfScalarPos(u8, out, start, '"').?;
    var decoded = try hdr.decodeBase64(testing.allocator, out[start..end]);
    defer decoded.deinit();
    try testing.expectEqual(@as(u64, 50), decoded.count());
}

test "time series rows break errors out by kind, as interval deltas" {
    const cfg = testConfig();
    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var ts = try TimeSeries.init(testing.allocator, &alloc.writer, &cfg);
    defer ts.deinit();

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();

    // First window: two deadline misses and a 500.
    snap.hist.record(1000);
    snap.counters.completed = 1;
    snap.counters.recordStatus(500);
    snap.counters.deadline_errors = 2;
    snap.counters.max_behind_ns = 5_000; // 5ms peak so far
    try ts.record(&snap, 1.0);

    // Second window, against the same *cumulative* counters: one more deadline
    // miss, one timeout, no new 500 — so the row must show 1/1/0, not 3/1/1.
    snap.hist.record(2000);
    snap.counters.completed = 2;
    snap.counters.deadline_errors = 3;
    snap.counters.timeouts = 1;
    snap.counters.max_behind_ns = 40_000; // the peak stepped up to 40ms
    try ts.record(&snap, 2.0);

    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, alloc.written(), "\n"), '\n');
    const first = it.next().?;
    const second = it.next().?;
    try testing.expect(it.next() == null);

    try testing.expect(std.mem.indexOf(u8, first, "\"errors\":3,") != null);
    // 1 completed + 2 deadline misses = 3 attempts, all 3 outcomes errors
    // (the 500 plus the two misses): the same arithmetic the summary uses.
    try testing.expect(std.mem.indexOf(u8, first, "\"error_rate\":1.000000,") != null);
    try testing.expect(std.mem.indexOf(u8, first, "\"deadline\":2,\"non_2xx_3xx\":1}") != null);
    try testing.expect(std.mem.indexOf(u8, first, "\"max_schedule_lag_us\":5,") != null);

    try testing.expect(std.mem.indexOf(u8, second, "\"errors\":2,") != null);
    // Second window: 1 completed + 1 deadline + 1 timeout = 3 attempts, 2 errors.
    try testing.expect(std.mem.indexOf(u8, second, "\"error_rate\":0.666667,") != null);
    try testing.expect(std.mem.indexOf(u8, second, "\"timeout\":1,\"deadline\":1,\"non_2xx_3xx\":0}") != null);
    try testing.expect(std.mem.indexOf(u8, second, "\"connect\":0,\"read\":0,\"write\":0,") != null);
    // The lag gauge is a running peak, not a per-interval delta: it carries the
    // new high water mark rather than the 35ms difference.
    try testing.expect(std.mem.indexOf(u8, second, "\"max_schedule_lag_us\":40,") != null);
}

test "row error_rate agrees with the summary's over a single window" {
    const cfg = testConfig();
    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var ts = try TimeSeries.init(testing.allocator, &alloc.writer, &cfg);
    defer ts.deinit();

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 97;
    snap.counters.recordStatus(500); // one non-2xx/3xx
    snap.counters.timeouts = 2;
    snap.counters.deadline_errors = 1;

    // Over one interval the row's delta *is* the cumulative total, so the row's
    // rate must be the number the final summary would report.
    try ts.record(&snap, 1.0);
    var buf: [32]u8 = undefined;
    const expected = try std.fmt.bufPrint(&buf, "\"error_rate\":{d:.6},", .{errorRate(snap.counters)});
    try testing.expect(std.mem.indexOf(u8, alloc.written(), expected) != null);
}

test "time series omits the HDR blob by default" {
    const cfg = testConfig(); // timeseries_histogram defaults false
    var alloc = Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    var ts = try TimeSeries.init(testing.allocator, &alloc.writer, &cfg);
    defer ts.deinit();

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = .{},
    };
    defer snap.deinit();
    snap.hist.record(1234);
    snap.counters.completed = 1;

    try ts.record(&snap, 1.0);
    try testing.expect(std.mem.indexOf(u8, alloc.written(), "latency_histogram") == null);
}

test "errorRate and checkSlo gates" {
    var c: connection.Counters = .{};
    c.completed = 98;
    c.recordStatus(200);
    c.recordStatus(500); // one non-2xx/3xx
    c.timeouts = 1; // one socket error
    // errors = status_errors(1) + socketErrors(1) = 2; total = completed(98)+socket(1)=99
    try testing.expectApproxEqAbs(@as(f64, 2.0 / 99.0), errorRate(c), 1e-9);

    // Deadline misses count as both a failure and an attempt: adding one moves
    // the rate to 3/100, so --max-error-rate can see overload-driven misses.
    c.deadline_errors = 1;
    try testing.expectApproxEqAbs(@as(f64, 3.0 / 100.0), errorRate(c), 1e-9);
    c.deadline_errors = 0;

    var snap: stats.Snapshot = .{
        .hist = try stats.newHistogram(testing.allocator),
        .counters = c,
    };
    defer snap.deinit();
    snap.hist.record(5000); // 5ms

    var cfg = testConfig();
    cfg.slo_p99_ns = 10 * std.time.ns_per_ms; // 10ms, p99=5ms -> ok
    cfg.max_error_rate = 0.01; // 1%, actual ~2% -> breach
    const r = checkSlo(&cfg, &snap);
    try testing.expect(r.p99_ok);
    try testing.expect(!r.error_rate_ok);
    try testing.expect(!r.passed());
}

test "writeJson reports a workload's cost only for a run that had one" {
    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 1;
    var cfg = testConfig();
    cfg.threads = 2;

    var without = Io.Writer.Allocating.init(testing.allocator);
    defer without.deinit();
    try writeJson(testing.allocator, &without.writer, &cfg, &snap, .{ .elapsed_s = 1.0, .launched = 1 });
    try testing.expect(std.mem.indexOf(u8, without.written(), "\"workload\"") == null);

    var with = Io.Writer.Allocating.init(testing.allocator);
    defer with.deinit();
    const run: Run = .{
        .elapsed_s = 1.0,
        .launched = 1,
        .workload = .{
            .next = .{ .calls = 4, .total_ns = 20_000_000, .mean_ns = 5_000_000, .p50_ns = 4_000_000, .p99_ns = 9_000_000, .max_ns = 9_500_000 },
            .response = .{},
        },
    };
    try writeJson(testing.allocator, &with.writer, &cfg, &snap, run);

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, with.written(), .{});
    defer parsed.deinit();
    const w = parsed.value.object.get("workload").?.object;
    // 20 ms of calls over 1 s on 2 threads.
    try testing.expectApproxEqAbs(@as(f64, 0.01), w.get("thread_share").?.float, 1e-9);
    const next = w.get("next").?.object;
    try testing.expectEqual(@as(i64, 4), next.get("calls").?.integer);
    try testing.expectApproxEqAbs(@as(f64, 20), next.get("total_ms").?.float, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 9000), next.get("p99_us").?.float, 1e-9);
    try testing.expectEqual(@as(i64, 0), w.get("response").?.object.get("calls").?.integer);
}
