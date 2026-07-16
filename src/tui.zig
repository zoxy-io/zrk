//! Terminal output: a live redrawing dashboard during the run and a wrk2-style
//! final report afterwards. Falls back to append-only lines when stdout is not
//! a TTY or `--plain` is set.

const std = @import("std");
const Io = std.Io;

const cli = @import("cli.zig");
const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const stats = @import("stats.zig");

const spark = [_][]const u8{ "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█" };
const history_len = 60;

pub const Dashboard = struct {
    io: Io,
    cfg: *const cli.Config,
    /// Redrawing TUI when true; append-only lines when false.
    tui: bool,

    file: Io.File,
    fw: Io.File.Writer,

    // Rate tracking between frames.
    have_prev: bool = false,
    prev_completed: u64 = 0,
    prev_ns: i128 = 0,

    // p99 history (microseconds) for the sparkline.
    p99_hist: [history_len]u64 = [_]u64{0} ** history_len,
    p99_count: usize = 0,

    pub fn init(io: Io, cfg: *const cli.Config, buffer: []u8) Dashboard {
        const file = Io.File.stdout();
        const is_tty = file.isTty(io) catch false;
        return .{
            .io = io,
            .cfg = cfg,
            .tui = is_tty and !cfg.plain,
            .file = file,
            .fw = Io.File.Writer.init(file, io, buffer),
        };
    }

    fn writer(self: *Dashboard) *Io.Writer {
        return &self.fw.interface;
    }

    /// Render one live frame from an aggregated snapshot.
    pub fn frame(self: *Dashboard, snap: *const stats.Snapshot, now_ns: i128, elapsed_s: f64, total_s: f64) !void {
        const w = self.writer();

        // Interval request rate from the delta since the previous frame.
        var rate: f64 = 0;
        if (self.have_prev and now_ns > self.prev_ns) {
            const d_req: f64 = @floatFromInt(snap.counters.completed -| self.prev_completed);
            const d_s: f64 = @as(f64, @floatFromInt(now_ns - self.prev_ns)) / std.time.ns_per_s;
            if (d_s > 0) rate = d_req / d_s;
        }
        self.have_prev = true;
        self.prev_completed = snap.counters.completed;
        self.prev_ns = now_ns;

        const p99 = snap.hist.valueAtPercentile(99);
        self.p99_hist[self.p99_count % history_len] = p99;
        self.p99_count += 1;

        if (self.tui) {
            try w.writeAll("\x1b[H\x1b[2J"); // home + clear
            try self.drawPanel(w, snap, rate, elapsed_s, total_s, p99);
        } else {
            try w.print("[{d:6.1}s] {d:8.0} req/s  p50={f} p99={f} p99.9={f} max={f}  errs={d}\n", .{
                elapsed_s,             rate,
                Dur.of(snap.hist.valueAtPercentile(50)), Dur.of(p99),
                Dur.of(snap.hist.valueAtPercentile(99.9)), Dur.of(snap.hist.max()),
                snap.counters.socketErrors() + snap.counters.status_errors,
            });
        }
        try self.fw.interface.flush();
    }

    fn drawPanel(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, rate: f64, elapsed_s: f64, total_s: f64, p99: u64) !void {
        const c = snap.counters;
        try w.print("  zrk  →  {s}://{s}:{d}{s}\n", .{
            @tagName(self.cfg.url.scheme), self.cfg.url.host, self.cfg.url.port, self.cfg.url.target,
        });
        try w.print("  elapsed {d:.0}s / {d:.0}s      connections {d}      target {d} req/s\n\n", .{
            elapsed_s, total_s, self.cfg.connections, self.cfg.rate,
        });

        try w.print("  requests {d}      rate {d:.0} req/s      transfer ", .{ c.completed, rate });
        try writeBytes(w, @floatFromInt(c.bytes));
        try w.writeAll("\n");

        const errs = c.socketErrors();
        if (errs > 0 or c.status_errors > 0) {
            try w.print("  socket errors {d}      non-2xx/3xx {d}\n", .{ errs, c.status_errors });
        }
        try w.writeAll("\n");

        try w.writeAll("  latency (corrected)\n");
        try self.line(w, "50%", snap.hist.valueAtPercentile(50));
        try self.line(w, "75%", snap.hist.valueAtPercentile(75));
        try self.line(w, "90%", snap.hist.valueAtPercentile(90));
        try self.line(w, "99%", p99);
        try self.line(w, "99.9%", snap.hist.valueAtPercentile(99.9));
        try self.line(w, "max", snap.hist.max());

        try w.writeAll("\n  p99 ");
        try self.drawSparkline(w);
        try w.writeAll("\n");
    }

    fn line(_: *Dashboard, w: *Io.Writer, label: []const u8, micros: u64) !void {
        try w.print("    {s:<7}", .{label});
        try Dur.write(w, @floatFromInt(micros));
        try w.writeAll("\n");
    }

    fn drawSparkline(self: *Dashboard, w: *Io.Writer) !void {
        const n = @min(self.p99_count, history_len);
        if (n == 0) return;

        // Find max over the visible window to scale the bars.
        var max_v: u64 = 1;
        {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const v = self.p99_hist[(self.p99_count - n + i) % history_len];
                if (v > max_v) max_v = v;
            }
        }
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const v = self.p99_hist[(self.p99_count - n + i) % history_len];
            const idx = (v * (spark.len - 1)) / max_v;
            try w.writeAll(spark[@min(idx, spark.len - 1)]);
        }
    }

    /// Print the wrk2-style final report to stdout. Aggregates should come
    /// from `Fleet.readFinal` (post-join).
    pub fn final(self: *Dashboard, snap: *const stats.Snapshot, elapsed_s: f64) !void {
        if (self.tui) try self.writer().writeAll("\x1b[H\x1b[2J");
        try self.writeReport(self.writer(), snap, elapsed_s);
        try self.fw.interface.flush();
    }

    /// Settle the terminal when the final report went to `--output` instead of
    /// stdout: clear the live TUI (if any) and leave a pointer to the file.
    pub fn finalRedirected(self: *Dashboard, path: []const u8) !void {
        const w = self.writer();
        if (self.tui) try w.writeAll("\x1b[H\x1b[2J");
        try w.print("Report written to {s}\n", .{path});
        try self.fw.interface.flush();
    }

    /// Render the wrk2-style final report to any writer (stdout, or the
    /// `--output` file in text mode). Does not flush.
    pub fn writeReport(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, elapsed_s: f64) !void {
        const c = snap.counters;
        const rps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.completed)) / elapsed_s else 0;
        const bps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.bytes)) / elapsed_s else 0;

        try w.print("\nRunning {d:.0}s test @ {s}://{s}:{d}{s}\n", .{
            elapsed_s, @tagName(self.cfg.url.scheme), self.cfg.url.host, self.cfg.url.port, self.cfg.url.target,
        });
        try w.print("  {d} connections, target rate {d} req/s\n\n", .{ self.cfg.connections, self.cfg.rate });

        try w.writeAll("  Latency (corrected for coordinated omission)\n");
        try self.line(w, "50%", snap.hist.valueAtPercentile(50));
        try self.line(w, "75%", snap.hist.valueAtPercentile(75));
        try self.line(w, "90%", snap.hist.valueAtPercentile(90));
        try self.line(w, "99%", snap.hist.valueAtPercentile(99));
        try self.line(w, "99.9%", snap.hist.valueAtPercentile(99.9));
        try self.line(w, "99.99%", snap.hist.valueAtPercentile(99.99));
        try self.line(w, "max", snap.hist.max());

        if (self.cfg.latency) try self.fullSpectrum(w, &snap.hist);

        try w.print("\n  {d} requests in {d:.2}s, ", .{ c.completed, elapsed_s });
        try writeBytes(w, @floatFromInt(c.bytes));
        try w.writeAll(" read\n");
        if (c.status_errors > 0) try w.print("  Non-2xx or 3xx responses: {d}\n", .{c.status_errors});
        if (c.socketErrors() > 0) {
            try w.print("  Socket errors: connect {d}, read {d}, write {d}, timeout {d}\n", .{
                c.connect_errors, c.read_errors, c.write_errors, c.timeouts,
            });
        }
        try w.print("Requests/sec: {d:.2}\n", .{rps});
        try w.writeAll("Transfer/sec: ");
        try writeBytes(w, bps);
        try w.writeAll("\n");
    }

    /// The `--latency` detailed percentile spectrum.
    fn fullSpectrum(self: *Dashboard, w: *Io.Writer, h: *const hdr.Histogram) !void {
        _ = self;
        try w.writeAll("\n  Detailed Percentile spectrum:\n");
        const points = [_]f64{ 0, 50, 75, 90, 99, 99.9, 99.99, 99.999, 100 };
        for (points) |pct| {
            const v = h.valueAtPercentile(pct);
            try w.print("    {d:9.4}%  ", .{pct});
            try Dur.write(w, @floatFromInt(v));
            try w.writeAll("\n");
        }
    }
};

/// Duration formatting helper for latency values expressed in microseconds.
const Dur = struct {
    micros: u64,

    fn of(micros: u64) Dur {
        return .{ .micros = micros };
    }

    fn write(w: *Io.Writer, micros: f64) !void {
        const m = micros;
        if (m < 1000) {
            try w.print("{d:.0}us", .{m});
        } else if (m < 1_000_000) {
            try w.print("{d:.2}ms", .{m / 1000.0});
        } else {
            try w.print("{d:.2}s", .{m / 1_000_000.0});
        }
    }

    pub fn format(self: Dur, w: *Io.Writer) Io.Writer.Error!void {
        try write(w, @floatFromInt(self.micros));
    }
};

fn writeBytes(w: *Io.Writer, bytes: f64) !void {
    const units = [_][]const u8{ "B", "KiB", "MiB", "GiB", "TiB" };
    var v = bytes;
    var i: usize = 0;
    while (v >= 1024.0 and i + 1 < units.len) : (i += 1) v /= 1024.0;
    if (i == 0) {
        try w.print("{d:.0}{s}", .{ v, units[i] });
    } else {
        try w.print("{d:.2}{s}", .{ v, units[i] });
    }
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "writeReport renders the wrk2-style summary to any writer" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1:8080/") };
    var dash_buf: [1024]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, &dash_buf);

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 100;
    snap.counters.bytes = 5000;
    snap.counters.recordStatus(200);

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    try dash.writeReport(&out.writer, &snap, 2.0);
    const text = out.written();

    try testing.expect(std.mem.indexOf(u8, text, "Latency (corrected for coordinated omission)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "100 requests in 2.00s") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Requests/sec: 50.00") != null);
    // No terminal control sequences in the redirectable report.
    try testing.expect(std.mem.indexOf(u8, text, "\x1b") == null);
}
