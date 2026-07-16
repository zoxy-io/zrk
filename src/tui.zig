//! Terminal output: a live redrawing dashboard during the run and a wrk2-style
//! final report afterwards. Falls back to append-only lines when stdout is not
//! a TTY or `--plain` is set.
//!
//! The dashboard repaints in place (cursor-up + erase-below) instead of
//! clearing the terminal, so the command that launched the run stays visible
//! in scrollback and the final report simply replaces the panel. Color is
//! TTY-only by construction and disabled by NO_COLOR or TERM=dumb; the
//! redirectable final report never carries escape sequences.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const cli = @import("cli.zig");
const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const stats = @import("stats.zig");

const spark = [_][]const u8{ "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█" };
const eighths = [_][]const u8{ "", "▏", "▎", "▍", "▌", "▋", "▊", "▉" };
const history_len = 60;

/// SGR fragments interpolated into every panel print. The disabled value is
/// all empty strings, so color never costs a branch at the call sites — and
/// never reaches a pipe, a --plain run, or the final report.
const Colors = struct {
    reset: []const u8 = "",
    dim: []const u8 = "",
    amber: []const u8 = "",
    amber_hi: []const u8 = "",
    red: []const u8 = "",

    const enabled: Colors = .{
        .reset = "\x1b[0m",
        .dim = "\x1b[90m",
        .amber = "\x1b[38;5;214m", // the zoxy signal orange
        .amber_hi = "\x1b[38;5;222m",
        .red = "\x1b[38;5;203m",
    };

    fn detect(tui_on: bool, environ: std.process.Environ) Colors {
        if (!tui_on) return .{};
        if (builtin.os.tag != .windows) {
            if (environ.getPosix("NO_COLOR")) |v| if (v.len > 0) return .{};
            if (environ.getPosix("TERM")) |t| if (std.mem.eql(u8, t, "dumb")) return .{};
        }
        return .enabled;
    }
};

pub const Dashboard = struct {
    io: Io,
    cfg: *const cli.Config,
    /// Redrawing TUI when true; append-only lines when false.
    tui: bool,

    file: Io.File,
    fw: Io.File.Writer,

    colors: Colors = .{},
    /// Terminal width, re-read each frame so a live resize reflows the panel.
    term_cols: usize = 80,
    /// Lines the previous frame drew — how far to move up before repainting.
    prev_lines: usize = 0,

    // Counter samples per frame, so displayed rates are measured over the
    // --interval stats window regardless of how fast --refresh redraws. A
    // per-frame delta at a 10ms refresh holds ~a handful of requests and
    // oscillates between zero and bursts; the window keeps it steady.
    samples: [rate_ring_len]Sample = undefined,
    sample_count: usize = 0,

    // p99 history (microseconds) for the sparkline — one point per
    // --interval, not per frame, so the scroll speed doesn't follow --refresh.
    p99_hist: [history_len]u64 = [_]u64{0} ** history_len,
    p99_count: usize = 0,
    last_spark_ns: i128 = 0,

    const Sample = struct { ns: i128, completed: u64, bytes: u64 };
    const rate_ring_len = 128;

    pub fn init(io: Io, cfg: *const cli.Config, environ: std.process.Environ, buffer: []u8) Dashboard {
        const file = Io.File.stdout();
        const is_tty = file.isTty(io) catch false;
        const tui_on = is_tty and !cfg.plain;
        return .{
            .io = io,
            .cfg = cfg,
            .tui = tui_on,
            .file = file,
            .fw = Io.File.Writer.init(file, io, buffer),
            .colors = Colors.detect(tui_on, environ),
        };
    }

    fn writer(self: *Dashboard) *Io.Writer {
        return &self.fw.interface;
    }

    /// Newest ring sample at least one --interval older than `now` — the base
    /// for the displayed rates. While the ring is younger than the window
    /// (warm-up, or an --interval longer than the ring covers) the oldest
    /// sample serves; null only before the first sample lands.
    fn windowSample(self: *const Dashboard, now_ns: i128) ?Sample {
        if (self.sample_count == 0) return null;
        const first = self.sample_count -| rate_ring_len;
        var best: Sample = self.samples[first % rate_ring_len];
        var i: usize = first;
        while (i < self.sample_count) : (i += 1) {
            const s = self.samples[i % rate_ring_len];
            if (now_ns - s.ns >= self.cfg.interval_ns) best = s else break;
        }
        return best;
    }

    /// Render one live frame from an aggregated snapshot.
    pub fn frame(self: *Dashboard, snap: *const stats.Snapshot, now_ns: i128, elapsed_s: f64, total_s: f64) !void {
        const w = self.writer();

        // Request/transfer rates measured over (at least) one --interval, by
        // diffing against the newest ring sample that old. The measurement
        // window is thus independent of the redraw cadence; the first frames
        // fall back to the whole run so far (otherwise a run with a single
        // frame reports 0 despite traffic).
        var rate: f64 = 0;
        var bps: f64 = 0;
        if (self.windowSample(now_ns)) |base| {
            const d_s: f64 = @as(f64, @floatFromInt(now_ns - base.ns)) / std.time.ns_per_s;
            if (d_s > 0) {
                rate = @as(f64, @floatFromInt(snap.counters.completed -| base.completed)) / d_s;
                bps = @as(f64, @floatFromInt(snap.counters.bytes -| base.bytes)) / d_s;
            }
        } else if (elapsed_s > 0) {
            rate = @as(f64, @floatFromInt(snap.counters.completed)) / elapsed_s;
            bps = @as(f64, @floatFromInt(snap.counters.bytes)) / elapsed_s;
        }
        self.samples[self.sample_count % rate_ring_len] = .{
            .ns = now_ns,
            .completed = snap.counters.completed,
            .bytes = snap.counters.bytes,
        };
        self.sample_count += 1;

        const p99 = snap.hist.valueAtPercentile(99);
        if (self.p99_count == 0 or now_ns - self.last_spark_ns >= self.cfg.interval_ns) {
            self.p99_hist[self.p99_count % history_len] = p99;
            self.p99_count += 1;
            self.last_spark_ns = now_ns;
        }

        if (self.tui) {
            // Repaint in place: move to the first panel line and erase below.
            // The command that launched the run stays in scrollback. (A resize
            // that rewraps old lines can leave artifacts for one frame; the
            // next repaint absorbs them.)
            self.term_cols = termWidth(self.file);
            if (self.prev_lines > 0) try w.print("\x1b[{d}F\x1b[J", .{self.prev_lines});
            self.prev_lines = try self.drawPanel(w, snap, rate, bps, elapsed_s, total_s, p99);
        } else {
            try w.print("[{d:6.1}s] {d:8.0} req/s {f}/s  p50={f} p99={f} p99.9={f} max={f}  errs={d}\n", .{
                elapsed_s,             rate,
                Bytes.of(bps),
                Dur.of(snap.hist.valueAtPercentile(50)), Dur.of(p99),
                Dur.of(snap.hist.valueAtPercentile(99.9)), Dur.of(snap.hist.max()),
                snap.counters.socketErrors() + snap.counters.status_errors,
            });
        }
        try self.fw.interface.flush();
    }

    /// One status segment: a dim label, a (possibly colored) value, and an
    /// optional dim suffix (`12s` + ` / 60s`).
    const Seg = struct {
        label: []const u8,
        text: []const u8,
        color: []const u8 = "",
        suffix: []const u8 = "",
    };

    /// Draw one live frame; returns the number of terminal lines written so
    /// the next frame knows how far to repaint. Config the launching command
    /// already shows (URL, -c, a ramp's A:B) is not repeated here — it sits
    /// right above in scrollback.
    fn drawPanel(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, rate: f64, bps: f64, elapsed_s: f64, total_s: f64, p99: u64) !usize {
        const c = snap.counters;
        const k = self.colors;
        var lines: usize = 0;

        // Breathing room between the command line and the panel.
        try w.writeAll("\n");
        lines += 1;

        // --- status segments -------------------------------------------------
        var vbuf: [10][48]u8 = undefined;
        const v_time = std.fmt.bufPrint(&vbuf[0], "{d:.0}s", .{elapsed_s}) catch "?";
        const v_total = std.fmt.bufPrint(&vbuf[1], " / {d:.0}s", .{total_s}) catch "?";

        // Offered load right now — for a ramp, the interpolated schedule.
        const r0: f64 = @floatFromInt(self.cfg.rate);
        const offered_now: f64 = if (self.cfg.rate_end) |e| blk: {
            const frac = if (total_s > 0) @min(elapsed_s / total_s, 1.0) else 1.0;
            break :blk r0 + (@as(f64, @floatFromInt(e)) - r0) * frac;
        } else r0;
        const v_offered = std.fmt.bufPrint(&vbuf[2], "{d:.0} req/s", .{offered_now}) catch "?";
        const v_achieved = std.fmt.bufPrint(&vbuf[3], "{d:.0} req/s", .{rate}) catch "?";
        const v_transfer = std.fmt.bufPrint(&vbuf[4], "{f} ({f}/s)", .{
            Bytes.of(@floatFromInt(c.bytes)), Bytes.of(bps),
        }) catch "?";
        const v_2xx = std.fmt.bufPrint(&vbuf[5], "{d}", .{c.status_class[2]}) catch "?";

        // The client failing to hold the schedule is zrk's #1 diagnostic
        // (rate_ratio / Little's law): paint the achieved rate red. Skip the
        // first seconds while the fleet is still connecting.
        const behind = elapsed_s >= 2 and rate < 0.95 * offered_now;

        // A fixed three-line status — no width-dependent wrapping. Rates on
        // the first line; transfer alone on the second (its width wiggles as
        // units climb); status-class counters on the third. Lines two and
        // three indent to sit under "offered".
        const indent = v_time.len + v_total.len + 3;

        try self.segLine(w, &.{
            .{ .label = "", .text = v_time, .suffix = v_total },
            .{ .label = "offered ", .text = v_offered },
            .{ .label = "achieved ", .text = v_achieved, .color = if (behind) k.red else "" },
        });
        try padTo(w, indent);
        try self.segLine(w, &.{.{ .label = "transfer ", .text = v_transfer }});
        lines += 2;

        // Only nonzero classes beyond 2xx appear — by wrk convention 3xx is
        // not an error, so a redirecting target would otherwise show "2xx 0"
        // and nothing else. 3xx is attention (you're probably load-testing a
        // redirect); 1xx/4xx/5xx are failure.
        var cls_buf: [5]Seg = undefined;
        var ncls: usize = 0;
        cls_buf[ncls] = .{ .label = "2xx ", .text = v_2xx };
        ncls += 1;
        const classes = [_]struct { idx: usize, label: []const u8 }{
            .{ .idx = 1, .label = "1xx " },
            .{ .idx = 3, .label = "3xx " },
            .{ .idx = 4, .label = "4xx " },
            .{ .idx = 5, .label = "5xx " },
        };
        for (classes) |cl| {
            if (c.status_class[cl.idx] == 0) continue;
            const v = std.fmt.bufPrint(&vbuf[5 + ncls], "{d}", .{c.status_class[cl.idx]}) catch "?";
            cls_buf[ncls] = .{
                .label = cl.label,
                .text = v,
                .color = if (cl.idx == 3) k.amber else k.red,
            };
            ncls += 1;
        }
        try padTo(w, indent);
        try self.segLine(w, cls_buf[0..ncls]);
        lines += 1;

        const errs = c.socketErrors();
        if (errs > 0 or c.status_errors > 0) {
            try w.print("{s}socket errors {d}   non-2xx/3xx {d}{s}\n", .{
                k.red, errs, c.status_errors, k.reset,
            });
            lines += 1;
        }
        try w.writeAll("\n");
        lines += 1;

        // --- latency spectrum (labels say it: p50…p99.9, CO-corrected) -------
        const rows = [_]struct { label: []const u8, v: u64, slo: bool = false }{
            .{ .label = "p50", .v = snap.hist.valueAtPercentile(50) },
            .{ .label = "p75", .v = snap.hist.valueAtPercentile(75) },
            .{ .label = "p90", .v = snap.hist.valueAtPercentile(90) },
            .{ .label = "p99", .v = p99, .slo = true },
            .{ .label = "p99.9", .v = snap.hist.valueAtPercentile(99.9) },
            .{ .label = "max", .v = snap.hist.max() },
        };
        // Log scale from p50/2 up to max: latency spans decades, and a linear
        // bar crushes everything but the tail. Anchoring at p50 keeps healthy
        // spectra readable at any absolute latency (LAN µs or WAN seconds).
        const lo: f64 = @floatFromInt(@max(rows[0].v / 2, 1));
        const hi: f64 = @max(@as(f64, @floatFromInt(rows[rows.len - 1].v)), lo * 8);
        const bar_w: usize = @min(@max(self.term_cols -| 19, 10), 44);
        for (rows) |row| {
            // Live SLO signal: the gated p99 row turns red past --slo-p99.
            const alarm = row.slo and self.cfg.slo_p99_ns != null and
                row.v * std.time.ns_per_us > self.cfg.slo_p99_ns.?;
            try self.barLine(w, row.label, row.v, lo, hi, bar_w, alarm);
            lines += 1;
        }

        try w.writeAll("\n");
        lines += 1;
        try w.print("{s}p99{s} {s}", .{ k.dim, k.reset, k.amber_hi });
        try self.drawSparkline(w, self.term_cols -| 16);
        var pbuf: [16]u8 = undefined;
        const pval = std.fmt.bufPrint(&pbuf, "{f}", .{Dur.of(p99)}) catch "?";
        try w.print("{s} {s}{s}{s}\n", .{ k.reset, k.dim, pval, k.reset });
        lines += 1;

        return lines;
    }

    fn segLine(self: *Dashboard, w: *Io.Writer, segs: []const Seg) !void {
        const k = self.colors;
        for (segs, 0..) |s, i| {
            if (i > 0) try w.writeAll("   ");
            try w.print("{s}{s}{s}{s}{s}{s}{s}{s}{s}", .{
                k.dim,  s.label, k.reset,
                s.color, s.text, k.reset,
                k.dim,  s.suffix, k.reset,
            });
        }
        try w.writeAll("\n");
    }

    /// `p99      8.91ms  ████████▍·····` — flush left, value right-aligned,
    /// bar on a log scale between lo..hi, eighth-block precision, dim dots
    /// for the rest.
    fn barLine(self: *Dashboard, w: *Io.Writer, label: []const u8, micros: u64, lo: f64, hi: f64, bar_w: usize, alarm: bool) !void {
        const k = self.colors;
        var dbuf: [16]u8 = undefined;
        const val = std.fmt.bufPrint(&dbuf, "{f}", .{Dur.of(micros)}) catch "?";
        try w.print("{s}{s:<6}{s}{s}{s:>9}{s}  ", .{
            k.dim, label, k.reset, if (alarm) k.red else "", val, k.reset,
        });

        const v: f64 = @floatFromInt(@max(micros, 1));
        const frac: f64 = if (hi > lo and v > lo)
            @min(@log(v / lo) / @log(hi / lo), 1.0)
        else
            0;
        const cells8: usize = @intFromFloat(@round(frac * @as(f64, @floatFromInt(bar_w)) * 8));
        const whole = cells8 / 8;
        const part = cells8 % 8;

        try w.writeAll(if (alarm) k.red else k.amber);
        var i: usize = 0;
        while (i < whole) : (i += 1) try w.writeAll("█");
        if (part > 0) try w.writeAll(eighths[part]);
        try w.writeAll(k.reset);

        try w.writeAll(k.dim);
        var rest = bar_w - whole - @intFromBool(part > 0);
        while (rest > 0) : (rest -= 1) try w.writeAll("·");
        try w.print("{s}\n", .{k.reset});
    }

    fn line(_: *Dashboard, w: *Io.Writer, label: []const u8, micros: u64) !void {
        try w.print("    {s:<7}", .{label});
        try Dur.write(w, @floatFromInt(micros));
        try w.writeAll("\n");
    }

    fn drawSparkline(self: *Dashboard, w: *Io.Writer, max_cols: usize) !void {
        const n = @min(@min(self.p99_count, history_len), @max(max_cols, 8));
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
    /// from `Fleet.readFinal` (post-join). The report replaces the live panel
    /// in place — the launching command and anything above stay in scrollback.
    pub fn final(self: *Dashboard, snap: *const stats.Snapshot, elapsed_s: f64) !void {
        try self.erasePanel();
        try self.writeReport(self.writer(), snap, elapsed_s);
        try self.fw.interface.flush();
    }

    /// Settle the terminal when the final report went to `--output` instead of
    /// stdout: erase the live TUI (if any) and leave a pointer to the file.
    pub fn finalRedirected(self: *Dashboard, path: []const u8) !void {
        try self.erasePanel();
        const w = self.writer();
        try w.print("Report written to {s}\n", .{path});
        try self.fw.interface.flush();
    }

    fn erasePanel(self: *Dashboard) !void {
        if (self.tui and self.prev_lines > 0) {
            try self.writer().print("\x1b[{d}F\x1b[J", .{self.prev_lines});
            self.prev_lines = 0;
        }
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
        // A ramp is reported as its full range — neither endpoint alone
        // describes what was offered.
        if (self.cfg.rate_end) |e| {
            try w.print("  {d} connections, target rate {d}→{d} req/s\n\n", .{ self.cfg.connections, self.cfg.rate, e });
        } else {
            try w.print("  {d} connections, target rate {d} req/s\n\n", .{ self.cfg.connections, self.cfg.rate });
        }

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
        if (c.status_class[3] > 0) {
            try w.print("  3xx (redirect) responses: {d} — redirects are not followed\n", .{c.status_class[3]});
        }
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

fn padTo(w: *Io.Writer, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try w.writeAll(" ");
}

/// Terminal column count for the panel layout; 80 when it can't be queried.
/// Re-read every frame, so a live resize reflows the next repaint.
fn termWidth(file: Io.File) usize {
    if (builtin.os.tag == .windows) return 80;
    var ws: std.posix.winsize = undefined;
    const rc = std.posix.system.ioctl(file.handle, std.posix.T.IOCGWINSZ, @intFromPtr(&ws));
    if (std.posix.errno(rc) == .SUCCESS and ws.col > 0) return ws.col;
    return 80;
}

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

/// Byte-quantity formatting helper (binary units), usable via `{f}`.
const Bytes = struct {
    v: f64,

    fn of(v: f64) Bytes {
        return .{ .v = v };
    }

    pub fn format(self: Bytes, w: *Io.Writer) Io.Writer.Error!void {
        try writeBytes(w, self.v);
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
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);

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
