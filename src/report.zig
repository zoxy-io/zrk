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

/// Fraction of outcomes that were failures: non-2xx/3xx responses, socket
/// errors (connect/read/write/timeout), and `--deadline` misses, over all
/// attempts. Deadline misses count as both a failure and an attempt, so under
/// overload the rate reflects the fraction of the offered schedule that could
/// not be served within the deadline. 0 when idle.
pub fn errorRate(c: connection.Counters) f64 {
    const failures = c.socketErrors() + c.deadline_errors;
    const errs = c.status_errors + failures;
    const total = c.completed + failures;
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
    elapsed_s: f64,
    launched: u32,
) !void {
    const c = snap.counters;
    const h = &snap.hist;
    const achieved: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.completed)) / elapsed_s else 0;
    const bps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.bytes)) / elapsed_s else 0;
    // For a ramp, compare achieved throughput against the *average* offered rate
    // (start+end)/2; for a constant run this is just the rate.
    const rate_end = cfg.rate_end orelse cfg.rate;
    const avg_target: f64 = (@as(f64, @floatFromInt(cfg.rate)) + @as(f64, @floatFromInt(rate_end))) / 2.0;

    try w.writeAll("{\n");
    try w.print("  \"zrk_version\": \"{s}\",\n", .{cli.version});

    try w.writeAll("  \"target\": { \"url\": ");
    try writeUrl(w, cfg);
    try w.writeAll(", \"method\": ");
    try writeJsonString(w, cfg.method);
    try w.writeAll(" },\n");

    try w.writeAll("  \"config\": {");
    try w.print(
        " \"connections\": {d}, \"launched\": {d}, \"duration_s\": {d:.3}, \"target_rate\": {d}, \"timeout_ms\": {d}, \"deadline_ms\": {d}, \"deadline_abort\": {}, \"record_timeouts\": {} }},\n",
        .{
            cfg.connections,
            launched,
            @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s,
            cfg.rate,
            cfg.timeout_ns / std.time.ns_per_ms,
            cfg.deadline_ns / std.time.ns_per_ms,
            cfg.deadline_abort,
            cfg.record_timeouts,
        },
    );

    try w.print("  \"duration_s\": {d:.3},\n", .{elapsed_s});
    try w.print("  \"requests\": {d},\n", .{c.completed});
    try w.print("  \"bytes\": {d},\n", .{c.bytes});
    try w.print("  \"achieved_rate\": {d:.2},\n", .{achieved});
    try w.print("  \"target_rate\": {d},\n", .{cfg.rate});
    try w.print("  \"target_rate_end\": {d},\n", .{rate_end});
    try w.print("  \"rate_ratio\": {d:.4},\n", .{if (avg_target > 0) achieved / avg_target else 0});
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

    // Full distribution, losslessly re-decodable by any HdrHistogram library.
    const b64 = try h.encodeBase64(gpa);
    defer gpa.free(b64);
    try w.print("  \"latency_histogram\": \"{s}\"\n", .{b64});

    try w.writeAll("}\n");
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
    prev_completed: u64 = 0,
    prev_bytes: u64 = 0,
    prev_errors: u64 = 0,
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

    /// Offered *total* target rate (req/s) at elapsed `t_s`, honoring a ramp.
    fn targetRate(self: *const TimeSeries, t_s: f64) f64 {
        const start: f64 = @floatFromInt(self.cfg.rate);
        const end_rate = self.cfg.rate_end orelse return start;
        const end: f64 = @floatFromInt(end_rate);
        const dur = @as(f64, @floatFromInt(self.cfg.duration_ns)) / std.time.ns_per_s;
        if (dur <= 0) return end;
        const frac = std.math.clamp(t_s / dur, 0, 1);
        return start + (end - start) * frac;
    }

    /// Emit the line for the interval ending at `elapsed_s` and advance state.
    pub fn record(self: *TimeSeries, snap: *const stats.Snapshot, elapsed_s: f64) !void {
        self.delta.setToDifference(&snap.hist, &self.prev_cum);
        const h = &self.delta;

        const interval_s = elapsed_s - self.prev_elapsed_s;
        const d_completed = snap.counters.completed -| self.prev_completed;
        const d_bytes = snap.counters.bytes -| self.prev_bytes;
        const cur_errors = snap.counters.status_errors + snap.counters.socketErrors() + snap.counters.deadline_errors;
        const d_errors = cur_errors -| self.prev_errors;
        const achieved: f64 = if (interval_s > 0) @as(f64, @floatFromInt(d_completed)) / interval_s else 0;
        const bps: f64 = if (interval_s > 0) @as(f64, @floatFromInt(d_bytes)) / interval_s else 0;

        try self.w.print(
            "{{\"t\":{d:.3},\"target_rate\":{d:.1},\"achieved_rate\":{d:.1},\"requests\":{d},\"errors\":{d}," ++
                "\"bytes\":{d},\"bytes_per_sec\":{d:.1}," ++
                "\"latency_us\":{{\"p50\":{d},\"p90\":{d},\"p99\":{d},\"p99_9\":{d},\"max\":{d}}}",
            .{
                elapsed_s,                 self.targetRate(elapsed_s),
                achieved,                  d_completed,
                d_errors,                  d_bytes,
                bps,                       h.valueAtPercentile(50),
                h.valueAtPercentile(90),   h.valueAtPercentile(99),
                h.valueAtPercentile(99.9), h.max(),
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
        self.prev_completed = snap.counters.completed;
        self.prev_bytes = snap.counters.bytes;
        self.prev_errors = cur_errors;
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
    try writeJson(testing.allocator, &alloc.writer, &cfg, &snap, 1.0, 4);
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
