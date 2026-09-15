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
const report = @import("report.zig");

/// Live latency spectrogram geometry. The waterfall keeps the last
/// `spec_rows_max` per-interval distributions (newest at the bottom), each
/// binned onto a fixed `spec_bins`-wide log2 latency axis so history stays
/// aligned while the display auto-frames to the occupied range. The full height
/// is reserved from the first frame (empty rows pad the top until it fills), and
/// the heat is a fixed `spec_width` columns wide.
const spec_rows_max = 10;
const spec_bins = 1024;
const spec_width = 100;

/// Heatmap intensity ramp for occupied cells (empty cells render as a space).
/// An "Inferno" gradient — the classic latency heatmap: faint cells recede as a
/// deep purple, dense cells climb through magenta and orange to the brand amber
/// (214) and a hot pale-yellow. Keeping the dark end saturated-cool is the whole
/// point — a warm ramp goes muddy brown at low brightness, since brown *is* dark
/// desaturated orange. Each stop pairs a 256-color SGR with a shade glyph so
/// intensity survives `NO_COLOR` as 4 block densities.
const HeatStop = struct { sgr: []const u8, glyph: []const u8 };
const heat_ramp = [_]HeatStop{
    .{ .sgr = "\x1b[38;5;53m", .glyph = "░" }, // trace   — deep purple
    .{ .sgr = "\x1b[38;5;90m", .glyph = "░" }, //         — magenta
    .{ .sgr = "\x1b[38;5;125m", .glyph = "▒" }, //         — pink-magenta
    .{ .sgr = "\x1b[38;5;167m", .glyph = "▒" }, //         — red
    .{ .sgr = "\x1b[38;5;202m", .glyph = "▓" }, //         — orange-red
    .{ .sgr = "\x1b[38;5;208m", .glyph = "▓" }, //         — orange
    .{ .sgr = "\x1b[38;5;214m", .glyph = "█" }, //         — amber (brand)
    .{ .sgr = "\x1b[38;5;229m", .glyph = "█" }, // hottest — pale yellow
};

/// Column the live stats block indents to — a 6-wide label, a 9-wide right-
/// aligned value, and a 2-space gap — so the elapsed timer, which sits in the
/// left gutter and widens as it counts up, never shifts the stats to the right.
const stat_col: usize = 6 + 9 + 2;

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

/// DEC private mode 2026 — synchronized output. Between these two the
/// terminal holds its display still and presents the result as one finished
/// frame, so a repaint is never caught mid-erase: without them `\x1b[J` blanks
/// the panel and the next ~1KB-15KB of cells fill it back in wherever the
/// terminal happens to draw, which at the 80ms default refresh is a visible
/// flicker on every frame. Terminals that don't implement it ignore both as
/// unknown private modes, so there is nothing to detect and no fallback.
const sync_begin = "\x1b[?2026h";
const sync_end = "\x1b[?2026l";

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

    /// Raised by the caller's signal watchers once a stop has been requested, so
    /// the panel can report it *itself*. Nothing else may write to this terminal
    /// while the panel is live: two lines printed under it (say, an "interrupt
    /// received" notice on stderr) scroll the panel down without `prev_lines`
    /// knowing, so the next repaint moves up too few lines, lands mid-panel and
    /// leaves a duplicated header stranded above it.
    stop_requested: ?*const std.atomic.Value(bool) = null,

    // Counter samples per frame, so displayed rates are measured over the
    // --interval stats window regardless of how fast --refresh redraws. A
    // per-frame delta at a 10ms refresh holds ~a handful of requests and
    // oscillates between zero and bursts; the window keeps it steady.
    samples: [rate_ring_len]Sample = undefined,
    sample_count: usize = 0,

    // Per-interval latency distributions for the spectrogram, advanced one row
    // per --interval (not per --refresh, so scroll speed doesn't follow the
    // redraw rate). Each row holds the interval's counts across `spec_bins` log2
    // latency bins, isolated by diffing the cumulative snapshot against
    // `spec_cum` (the cumulative bins at the previous row boundary). Both arrays
    // start undefined: `spec_count`/`spec_have_cum` gate every read.
    spec_rows: [spec_rows_max][spec_bins]u64 = undefined,
    spec_cum: [spec_bins]u64 = undefined,
    spec_count: usize = 0,
    spec_have_cum: bool = false,
    last_row_ns: i128 = 0,

    const Sample = struct { ns: i128, completed: u64, bytes: u64 };
    const rate_ring_len = 128;

    /// The measurement a frame renders: throughput over `seconds` of run,
    /// ending `at_s` into it. The four travel together because they only mean
    /// anything together — `rate` next to an offered load sampled from a
    /// different span is the comparison this panel exists to get right.
    const Window = struct {
        rate: f64 = 0,
        bps: f64 = 0,
        seconds: f64 = 0,
        at_s: f64 = 0,
    };

    pub fn init(io: Io, cfg: *const cli.Config, environ: std.process.Environ, buffer: []u8) Dashboard {
        const file = Io.File.stdout();
        const is_tty = file.isTty(io) catch false;
        // `--timeseries -` hands stdout to the NDJSON rows: the panel cannot own
        // a terminal it is not the one writing to, and its colors would be ANSI
        // noise in whatever the summary is redirected to.
        const tui_on = is_tty and !cfg.plain and !cfg.timeseriesOnStdout();
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

    /// Whether a signal has asked the run to stop (see `stop_requested`).
    fn stopping(self: *const Dashboard) bool {
        const flag = self.stop_requested orelse return false;
        return flag.load(.monotonic);
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
        // The span matters as much as the rates: under a ramp the offered
        // schedule moves *within* the window, so `offered` has to be averaged
        // over the same span to be comparable.
        var win: Window = .{ .seconds = elapsed_s, .at_s = elapsed_s };
        if (self.windowSample(now_ns)) |base| {
            const d_s: f64 = @as(f64, @floatFromInt(now_ns - base.ns)) / std.time.ns_per_s;
            if (d_s > 0) {
                win.rate = @as(f64, @floatFromInt(snap.counters.completed -| base.completed)) / d_s;
                win.bps = @as(f64, @floatFromInt(snap.counters.bytes -| base.bytes)) / d_s;
                win.seconds = d_s;
            }
        } else if (elapsed_s > 0) {
            win.rate = @as(f64, @floatFromInt(snap.counters.completed)) / elapsed_s;
            win.bps = @as(f64, @floatFromInt(snap.counters.bytes)) / elapsed_s;
        }
        const rate = win.rate;
        self.samples[self.sample_count % rate_ring_len] = .{
            .ns = now_ns,
            .completed = snap.counters.completed,
            .bytes = snap.counters.bytes,
        };
        self.sample_count += 1;

        // Advance the spectrogram one row per --interval (independent of the
        // faster --refresh redraw), diffing the cumulative snapshot to isolate
        // this interval's latency distribution.
        if (self.spec_count == 0 or now_ns - self.last_row_ns >= self.cfg.interval_ns) {
            self.pushSpecRow(&snap.hist);
            self.last_row_ns = now_ns;
        }

        if (self.tui) {
            // Repaint in place: move to the first panel line and erase below.
            // The command that launched the run stays in scrollback. (A resize
            // that rewraps old lines can leave artifacts for one frame; the
            // next repaint absorbs them.)
            self.term_cols = termWidth(self.file);
            try self.repaint(w, snap, win, elapsed_s, total_s, false);
        } else {
            try w.print("[{d:6.1}s] {d:8.0} req/s {f}/s  p50={f} p99={f} p99.9={f} max={f}  errs={d}\n", .{
                elapsed_s,                               rate,
                Bytes.of(win.bps),                       Dur.of(snap.hist.valueAtPercentile(50)),
                Dur.of(snap.hist.valueAtPercentile(99)), Dur.of(snap.hist.valueAtPercentile(99.9)),
                Dur.of(snap.hist.max()),                 snap.counters.socketErrors() + snap.counters.status_errors + snap.counters.deadline_errors,
            });
        }
        try self.fw.interface.flush();
    }

    /// Erase the previous frame and draw a new one inside a single synchronized
    /// update, recording the new height for the next repaint. Shared by the live
    /// frame and the settled final panel so the two can't drift — and so the
    /// invariant that every `sync_begin` is matched lives in exactly one place.
    ///
    /// `term_cols` is the caller's to refresh: both call sites re-read it from
    /// the terminal first, which leaves tests free to pin a width.
    fn repaint(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, win: Window, elapsed_s: f64, total_s: f64, finished: bool) !void {
        try w.writeAll(sync_begin);
        // A frame that dies between the two sequences leaves the terminal
        // holding its display with nothing left to release it — that reads as a
        // hung program rather than a failed paint, and no later frame reopens it
        // because a failed dashboard is not called again. Closing has to reach
        // the terminal, not just the buffer: a colored panel outruns the 8KiB
        // buffer, so `sync_begin` may already have gone out on an auto-flush.
        // Best-effort by construction — whatever broke the frame most likely
        // breaks these too, and there is no better move left either way.
        errdefer closeSync(w);
        if (self.prev_lines > 0) try w.print("\r\x1b[{d}A\x1b[J", .{self.prev_lines});
        self.prev_lines = try self.drawPanel(w, snap, win, elapsed_s, total_s, finished);
        try w.writeAll(sync_end);
    }

    /// Release a synchronized update that a failed frame left open (see
    /// `repaint`). Silent: the caller is already unwinding an error worth more
    /// than anything these two writes could report.
    fn closeSync(w: *Io.Writer) void {
        w.writeAll(sync_end) catch {};
        w.flush() catch {};
    }

    /// One status segment: a dim label and a (possibly colored) value.
    const Seg = struct {
        label: []const u8,
        text: []const u8,
        color: []const u8 = "",
    };

    /// Draw one live frame; returns the number of terminal lines written so
    /// the next frame knows how far to repaint. Config the launching command
    /// already shows (URL, -c, a ramp's A:B) is not repeated here — it sits
    /// right above in scrollback.
    fn drawPanel(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, win: Window, elapsed_s: f64, total_s: f64, finished: bool) !usize {
        const c = snap.counters;
        const k = self.colors;
        var lines: usize = 0;

        // Breathing room between the command line and the panel.
        try w.writeAll("\n");
        lines += 1;

        // --- status segments -------------------------------------------------
        var vbuf: [10][48]u8 = undefined;
        const v_time = clock(&vbuf[0], elapsed_s);
        const v_total = clock(&vbuf[1], total_s);

        // Offered load over the same window `achieved` was measured over — the
        // schedule at its midpoint, since the ramp is linear in time. Not the
        // schedule *right now*: `achieved` is an average across the window, and
        // a ramp climbs while the window runs, so comparing it to the instant's
        // offered rate books every healthy ramp as half a window of slope
        // behind. At -R100:1000 over 30s with a 1s window that is a standing 15
        // req/s gap; over 4s it is 110, enough to paint a run that missed
        // nothing red from start to finish. Anchored on `win.at_s` rather than
        // `elapsed_s` because the final paint's window closed at the last
        // progress row, which an interrupt can leave most of an --interval
        // behind. Meaningless in --closed mode, which has no offered rate.
        const offered_now = report.offeredRate(self.cfg, win.at_s - win.seconds / 2);
        const v_offered = std.fmt.bufPrint(&vbuf[2], "{d:.0} req/s", .{offered_now}) catch "?";
        const v_achieved = std.fmt.bufPrint(&vbuf[3], "{d:.0} req/s", .{win.rate}) catch "?";
        const v_transfer = std.fmt.bufPrint(&vbuf[4], "{f} ({f}/s)", .{
            Bytes.of(@floatFromInt(c.bytes)), Bytes.of(win.bps),
        }) catch "?";
        const v_2xx = std.fmt.bufPrint(&vbuf[5], "{d}", .{c.status_class[2]}) catch "?";

        // The client failing to hold the schedule is zrk's #1 diagnostic
        // (rate_ratio / Little's law): paint the achieved rate red. Skip the
        // first seconds while the fleet is still connecting. Never applies in
        // --closed mode, which has no schedule to fall behind.
        const behind = !self.cfg.closed and elapsed_s >= 2 and win.rate < 0.95 * offered_now;

        // A fixed three-line status, all indented to `stat_col`: the clock
        // lives alone in the left gutter (above the pXX labels) so its widening
        // never shifts the stats. Rates on the first line; transfer alone on
        // the second (its width wiggles as units climb); status-class counters
        // on the third.
        //
        // A blinking red "recording" dot leads the clock while the run is live;
        // it toggles on a ~1s wall-clock phase (rather than the SGR blink
        // attribute, which most terminals ignore), and the cell stays one column
        // wide — a space while dark — so the clock never jitters. Once finished
        // it settles to a static dim mark: the panel stays on screen as the
        // run's record, and a still grey mark reads as "stopped", not
        // "recording". The mark's *shape* says how the run ended — a dot when it
        // ran its course, a cross when a signal cut it short — and the blink
        // stops the moment a stop is requested, since the fleet is winding down
        // from then on and "recording" would be a lie.
        const stop_req = self.stopping();
        if (finished or stop_req) {
            const mark: []const u8 = if (stop_req) "✕" else "●";
            const tint = if (stop_req and !finished) k.red else k.dim;
            try w.print("{s}{s}{s} ", .{ tint, mark, k.reset });
        } else {
            const blink_on = (@as(u64, @intFromFloat(@max(elapsed_s, 0) * 2)) & 1) == 0;
            if (blink_on) try w.print("{s}●{s} ", .{ k.red, k.reset }) else try w.writeAll("  ");
        }
        try w.print("{s}{s} / {s}{s}", .{ v_time, k.dim, v_total, k.reset });
        const timer_w = 2 + v_time.len + 3 + v_total.len; // "● " + clock + " / "
        try padTo(w, @max(stat_col -| timer_w, 1));
        if (self.cfg.closed) {
            try self.segLine(w, &.{.{ .label = "rate ", .text = v_achieved }});
        } else {
            try self.segLine(w, &.{
                .{ .label = "offered ", .text = v_offered },
                .{ .label = "achieved ", .text = v_achieved, .color = if (behind) k.red else "" },
            });
        }
        try padTo(w, stat_col);
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
        try padTo(w, stat_col);
        try self.segLine(w, cls_buf[0..ncls]);
        lines += 1;

        const errs = c.socketErrors();
        if (errs > 0 or c.status_errors > 0) {
            try padTo(w, stat_col);
            try w.print("{s}socket errors {d}   non-2xx/3xx {d}{s}\n", .{
                k.red, errs, c.status_errors, k.reset,
            });
            lines += 1;
        }
        // Deadline misses and peak schedule lag: the overload signal. The lag
        // gauge shows even when nothing has missed yet (a ramp approaching the
        // knee), so it's the earliest warning that the client is falling behind.
        if (c.deadline_errors > 0 or (self.cfg.deadline_ns != 0 and c.max_behind_ns > 0)) {
            try padTo(w, stat_col);
            try w.print("{s}deadline misses {d}{s}   {s}peak lag{s} {f}\n", .{
                k.red, c.deadline_errors, k.reset,
                k.dim, k.reset,           Dur.of(c.max_behind_ns / std.time.ns_per_us),
            });
            lines += 1;
        }
        // The stop notice belongs *in* the panel, counted in `lines` like every
        // other row: printed underneath it instead (as a stderr line) it would
        // desync the in-place repaint. Joining a large fleet is not instant, so
        // while it happens the hint also says how to give up waiting.
        if (stop_req) {
            try padTo(w, stat_col);
            if (finished) {
                try w.print("{s}stopped early — the numbers above are what was measured{s}\n", .{ k.dim, k.reset });
            } else {
                try w.print("{s}stopping — signal again to abort{s}\n", .{ k.dim, k.reset });
            }
            lines += 1;
        }
        try w.writeAll("\n");
        lines += 1;

        // --- latency: a compact percentile readout, then the spectrogram ------
        // No percentile bars: the spectrogram below shows the whole evolving
        // distribution — including bimodality bars would hide — while this one
        // line keeps the exact numbers the shape can't give, and carries the
        // live SLO signal (p99 turns red past --slo-p99).
        const p99 = snap.hist.valueAtPercentile(99);
        const alarm = self.cfg.slo_p99_ns != null and
            p99 * std.time.ns_per_us > self.cfg.slo_p99_ns.?;
        // Ascending display order; `keep` is the drop priority (lower survives a
        // narrow terminal longer). p50/p99/max are the load-test essentials, so
        // when the line won't fit we shed the middle markers first — p99.9, then
        // p75, then p90 — never the tail (max) or p99.
        const Pctl = struct { label: []const u8, v: u64, keep: u8, alarm: bool = false };
        const pctls = [_]Pctl{
            .{ .label = "p50", .v = snap.hist.valueAtPercentile(50), .keep = 0 },
            .{ .label = "p75", .v = snap.hist.valueAtPercentile(75), .keep = 4 },
            .{ .label = "p90", .v = snap.hist.valueAtPercentile(90), .keep = 3 },
            .{ .label = "p99", .v = p99, .keep = 1, .alarm = alarm },
            .{ .label = "p99.9", .v = snap.hist.valueAtPercentile(99.9), .keep = 5 },
            .{ .label = "max", .v = snap.hist.max(), .keep = 2 },
        };
        var valbuf: [pctls.len][16]u8 = undefined;
        var vals: [pctls.len][]const u8 = undefined;
        for (pctls, 0..) |pc, i| vals[i] = std.fmt.bufPrint(&valbuf[i], "{f}", .{Dur.of(pc.v)}) catch "?";

        // Select which fit by ascending `keep` priority (visible width = label +
        // space + value; color codes add no columns; segments joined by 3 spaces),
        // then render the survivors in display order so the line never wraps.
        var show = [_]bool{false} ** pctls.len;
        var used: usize = 0;
        var shown: usize = 0;
        for (0..pctls.len) |prio| {
            const i = for (pctls, 0..) |pc, j| {
                if (pc.keep == prio) break j;
            } else continue;
            const seg = pctls[i].label.len + 1 + vals[i].len;
            const sep: usize = if (shown == 0) 0 else 3;
            if (used + sep + seg > self.term_cols -| 1) continue; // last column stays free (autowrap)
            show[i] = true;
            used += sep + seg;
            shown += 1;
        }
        var first = true;
        for (pctls, 0..) |pc, i| {
            if (!show[i]) continue;
            if (!first) try w.writeAll("   ");
            first = false;
            try w.print("{s}{s}{s} {s}{s}{s}", .{
                k.dim, pc.label, k.reset, if (pc.alarm) k.red else "", vals[i], k.reset,
            });
        }
        try w.writeAll("\n");
        lines += 1;

        lines += try self.drawSpectrogram(w, snap.hist.highest_trackable);

        return lines;
    }

    /// Fold the cumulative snapshot onto the fixed log2 axis and store this
    /// interval's slice (current cumulative − previous cumulative) as the newest
    /// spectrogram row.
    fn pushSpecRow(self: *Dashboard, hist: *const hdr.Histogram) void {
        var cur: [spec_bins]u64 = undefined;
        hist.binByLog2(&cur);
        if (!self.spec_have_cum) {
            @memset(&self.spec_cum, 0);
            self.spec_have_cum = true;
        }
        const idx = self.spec_count % spec_rows_max;
        for (&self.spec_rows[idx], &cur, &self.spec_cum) |*d, c, p| d.* = c -| p;
        @memcpy(&self.spec_cum, &cur);
        self.spec_count += 1;
    }

    /// The visible row at position `r` (0 = oldest of the `n` shown) in the ring.
    fn rowAt(self: *const Dashboard, r: usize, n: usize) []const u64 {
        return &self.spec_rows[(self.spec_count - n + r) % spec_rows_max];
    }

    /// Draw the latency spectrogram: a fixed `spec_rows_max`-tall, `spec_width`-
    /// wide heat-shaded waterfall of the per-interval distributions (newest at
    /// the bottom, next to the scale), auto-framed to the occupied latency range.
    /// The full height is reserved from the first frame — rows not yet recorded
    /// render empty at the top — so the panel never grows. `axis_highest` is the
    /// histogram's ceiling (µs), fixing the log2 axis the rows were binned on.
    /// Always writes `spec_rows_max + 1` lines (rows + scale); returns that count.
    fn drawSpectrogram(self: *Dashboard, w: *Io.Writer, axis_highest: u64) !usize {
        const k = self.colors;
        const n = @min(self.spec_count, spec_rows_max); // rows with real data

        // Auto-frame: the occupied storage-bin span across the recorded rows.
        var minb: usize = spec_bins;
        var maxb: usize = 0;
        for (0..n) |r| {
            for (self.rowAt(r, n), 0..) |cnt, b| if (cnt > 0) {
                if (b < minb) minb = b;
                if (b > maxb) maxb = b;
            };
        }
        const have_data = minb <= maxb;

        // Pad a narrow distribution out to a minimum span so it isn't a lone
        // stripe, keeping the span within [0, spec_bins).
        const min_span = 24;
        if (have_data and maxb - minb + 1 < min_span) {
            const grow = min_span - (maxb - minb + 1);
            minb -|= grow / 2;
            maxb = @min(maxb + (grow - grow / 2), spec_bins - 1);
        }
        const span = if (have_data) maxb - minb + 1 else 1;

        // Render width prefers the fixed spec_width but clamps to the terminal,
        // leaving the last column free: a row exactly `term_cols` wide triggers
        // last-column autowrap, which adds a phantom line and desyncs the in-place
        // repaint. Storage/render buffers stay sized to the spec_width maximum.
        const width = @max(@min(spec_width, self.term_cols -| 1), 1);

        // Resample each row's storage bins onto `width` display columns, tracking
        // the global peak for a log-compressed intensity scale (so a smaller mode
        // still shows rather than washing out next to the dominant one). Empty
        // ring slots (before the waterfall fills) stay all-zero.
        //
        // A column is a weighted *average* of the bins around its center, not a
        // sum over the bins it happens to straddle: `span` rarely divides
        // `width`, so summing makes a column that covers two bins twice as hot
        // as its one-bin neighbour and the picture bands into vertical stripes
        // that move with the terminal size. The tent kernel spans one column
        // (radius `colw`/2), widening to a full bin when a column is narrower
        // than one, which interpolates instead of replicating when the framed
        // range is upsampled. Bins outside the frame count as zeros, so the
        // occupied range fades out at its edges rather than ending in a cliff.
        var cells: [spec_rows_max][spec_width]f64 = std.mem.zeroes([spec_rows_max][spec_width]f64);
        var peak: f64 = 0;
        if (have_data) {
            const colw = @as(f64, @floatFromInt(span)) / @as(f64, @floatFromInt(width));
            const radius = @max(colw / 2, 1.0);
            for (0..n) |r| {
                const row = self.rowAt(r, n);
                for (0..width) |x| {
                    const center = @as(f64, @floatFromInt(minb)) + (@as(f64, @floatFromInt(x)) + 0.5) * colw;
                    var acc: f64 = 0;
                    var wsum: f64 = 0;
                    var b: isize = @intFromFloat(@floor(center - radius));
                    const last: isize = @intFromFloat(@ceil(center + radius));
                    while (b <= last) : (b += 1) {
                        const d = @abs(@as(f64, @floatFromInt(b)) + 0.5 - center);
                        if (d >= radius) continue;
                        const weight = 1 - d / radius;
                        wsum += weight;
                        if (b >= 0 and b < spec_bins) acc += @as(f64, @floatFromInt(row[@intCast(b)])) * weight;
                    }
                    const v = if (wsum > 0) acc / wsum else 0;
                    // Newest data sits on the bottom rows; older rows pad the top.
                    cells[spec_rows_max - n + r][x] = v;
                    if (v > peak) peak = v;
                }
            }
        }
        const denom = std.math.log2(1 + peak);
        const color_on = k.reset.len > 0; // theme active (TTY and not NO_COLOR)
        const hottest = heat_ramp.len - 1;

        var lines: usize = 0;
        for (0..spec_rows_max) |r| {
            for (0..width) |x| {
                const q = cells[r][x];
                if (q <= 0) {
                    try w.writeAll(" ");
                    continue;
                }
                const frac: f64 = if (denom > 0)
                    std.math.clamp(std.math.log2(1 + q) / denom, 0.0, 1.0)
                else
                    1.0;
                const stop = heat_ramp[@intFromFloat(@round(frac * @as(f64, @floatFromInt(hottest))))];
                if (color_on) {
                    try w.print("{s}{s}{s}", .{ stop.sgr, stop.glyph, k.reset });
                } else {
                    try w.writeAll(stop.glyph);
                }
            }
            try w.writeAll("\n");
            lines += 1;
        }

        try self.drawSpecScale(w, axis_highest, minb, span, width, have_data);
        lines += 1;
        return lines;
    }

    /// The latency scale under the spectrogram: up to four log-spaced tick
    /// labels placed at their columns without overlapping.
    fn drawSpecScale(self: *Dashboard, w: *Io.Writer, axis_highest: u64, minb: usize, span: usize, width: usize, have_data: bool) !void {
        const k = self.colors;
        var buf: [spec_width]u8 = undefined;
        @memset(buf[0..width], ' ');
        // Before any data lands there is no range to label — keep the line (so
        // the height stays fixed) but blank.
        if (have_data) {
            // Left/middle ticks are anchored at their column; the final tick (the
            // top of the range) is right-aligned to the last column so the max
            // latency is always labeled.
            const label = struct {
                fn at(hi: u64, minbb: usize, spann: usize, widthh: usize, col: usize, out: []u8) []const u8 {
                    const b = minbb + col * spann / widthh;
                    var ls: Io.Writer = .fixed(out);
                    Dur.write(&ls, specBinEdgeUs(hi, b)) catch return "";
                    return ls.buffered();
                }
            }.at;
            var lbuf: [12]u8 = undefined;
            var next_free: usize = 0;
            for ([_]usize{ 0, width / 3, (2 * width) / 3 }) |tx| {
                const s = label(axis_highest, minb, span, width, tx, &lbuf);
                if (tx >= next_free and tx + s.len <= width) {
                    @memcpy(buf[tx .. tx + s.len], s);
                    next_free = tx + s.len + 1;
                }
            }
            const top = label(axis_highest, minb, span, width, width - 1, &lbuf);
            if (top.len <= width and width - top.len >= next_free) {
                @memcpy(buf[width - top.len .. width], top);
            }
        }
        try w.print("{s}{s}{s}\n", .{ k.dim, buf[0..width], k.reset });
    }

    fn segLine(self: *Dashboard, w: *Io.Writer, segs: []const Seg) !void {
        const k = self.colors;
        for (segs, 0..) |s, i| {
            if (i > 0) try w.writeAll("   ");
            try w.print("{s}{s}{s}{s}{s}{s}", .{
                k.dim,   s.label, k.reset,
                s.color, s.text,  k.reset,
            });
        }
        try w.writeAll("\n");
    }

    fn line(_: *Dashboard, w: *Io.Writer, label: []const u8, micros: u64) !void {
        try w.print("    {s:<7}", .{label});
        try Dur.write(w, @floatFromInt(micros));
        try w.writeAll("\n");
    }

    /// Emit the final report. With a live TUI the panel *is* the report: the last
    /// frame is repainted with the complete totals and a settled (non-blinking)
    /// dot, then left on screen as the run's record — no separate summary. Without
    /// a TUI (--plain, a pipe, non-tty) a compact plain-text summary is printed
    /// instead. Aggregates should come from `Fleet.readFinal` (post-join).
    pub fn final(self: *Dashboard, snap: *const stats.Snapshot, run: report.Run) !void {
        const w = self.writer();
        if (self.tui) {
            const elapsed_s = run.elapsed_s;
            const total_s: f64 = @as(f64, @floatFromInt(self.cfg.duration_ns)) / std.time.ns_per_s;
            self.term_cols = termWidth(self.file);
            // Every value keeps meaning what it meant in each live frame — the
            // last window's — rather than switching to whole-run averages for
            // this one paint. The panel sets `achieved` beside `offered`, and
            // under a ramp the run average is half the offered rate by
            // construction, so the swap painted a healthy `-R100:1000` run's
            // last frame red for falling behind a schedule it had in fact kept.
            // Transfer comes from the same window for the same reason: paired
            // with a whole-run byte rate, the panel's own two numbers divide
            // out to a bytes-per-request that was never true. The whole-run
            // averages are the summary's `req/s`, where they are labelled.
            try self.repaint(w, snap, .{
                .rate = run.end_rate,
                .bps = run.end_bytes_per_sec,
                .seconds = run.end_window_s,
                .at_s = run.end_window_at_s,
            }, elapsed_s, total_s, true);
        } else {
            try self.writeFinalSummary(w, snap, run);
        }
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
            try self.writer().print("\r\x1b[{d}A\x1b[J", .{self.prev_lines});
            self.prev_lines = 0;
        }
    }

    /// Compact plain-text final summary for non-TUI output (--plain, a pipe, or
    /// the `--output` file). No colors and no wrk2-style framing — just the totals
    /// the live panel would have shown, in the panel's own vocabulary. Does not
    /// flush. Aggregates should come from `Fleet.readFinal` (post-join).
    pub fn writeFinalSummary(self: *Dashboard, w: *Io.Writer, snap: *const stats.Snapshot, run: report.Run) !void {
        const c = snap.counters;
        const elapsed_s = run.elapsed_s;
        const rps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.completed)) / elapsed_s else 0;
        const bps: f64 = if (elapsed_s > 0) @as(f64, @floatFromInt(c.bytes)) / elapsed_s else 0;

        try w.print("\n  {d} requests in {d:.2}s, ", .{ c.completed, elapsed_s });
        try writeBytes(w, @floatFromInt(c.bytes));
        try w.print(" read  ·  {d:.0} req/s  ·  ", .{rps});
        try writeBytes(w, bps);
        try w.writeAll("/s\n");
        // The line above is `requests / duration`, which under a ramp is the
        // midpoint of the offered range and nothing more: it reads the same
        // whether the target held the end rate or fell over halfway up. So a
        // ramp gets a second line with the number the ramp was run to find —
        // the same one `--format json` reports as `achieved_rate`.
        if (self.cfg.rate_end) |end| {
            try w.print("  ramp {d} → {d} req/s  ·  {d:.0} req/s over the final {d:.1}s\n", .{
                self.cfg.rate, end, run.end_rate, run.end_window_s,
            });
        }

        if (self.cfg.closed) {
            try w.writeAll("  latency (closed-loop round-trip)\n");
        } else {
            try w.writeAll("  latency (coordinated-omission corrected)\n");
        }
        try self.line(w, "p50", snap.hist.valueAtPercentile(50));
        try self.line(w, "p75", snap.hist.valueAtPercentile(75));
        try self.line(w, "p90", snap.hist.valueAtPercentile(90));
        try self.line(w, "p99", snap.hist.valueAtPercentile(99));
        try self.line(w, "p99.9", snap.hist.valueAtPercentile(99.9));
        try self.line(w, "max", snap.hist.max());
        if (self.cfg.latency) try self.fullSpectrum(w, &snap.hist);

        if (c.status_errors > 0) try w.print("  non-2xx/3xx: {d}\n", .{c.status_errors});
        if (c.status_class[3] > 0) {
            try w.print("  3xx (redirect): {d} — redirects are not followed\n", .{c.status_class[3]});
        }
        if (c.socketErrors() > 0) {
            try w.print("  socket errors: connect {d}, read {d}, write {d}, timeout {d}\n", .{
                c.connect_errors, c.read_errors, c.write_errors, c.timeouts,
            });
        }
        if (c.deadline_errors > 0) {
            try w.print("  deadline misses: {d} (CO latency exceeded --deadline)\n", .{c.deadline_errors});
        }
        // Peak schedule lag is the backlog gauge; sub-millisecond lag is normal
        // jitter, so only report it once it's large enough to signal overload.
        if (c.max_behind_ns >= std.time.ns_per_ms) {
            try w.writeAll("  peak schedule lag: ");
            try Dur.write(w, @floatFromInt(c.max_behind_ns / std.time.ns_per_us));
            try w.writeAll("\n");
        }
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

/// Latency (µs) at the lower edge of log2 bin `b`, mirroring `hdr.binByLog2`
/// (`spec_bins` bins tiling `[1, axis_highest]`) — the inverse used to label
/// the scale.
fn specBinEdgeUs(axis_highest: u64, b: usize) f64 {
    const span = std.math.log2(@as(f64, @floatFromInt(axis_highest)));
    const frac = @as(f64, @floatFromInt(b)) / @as(f64, @floatFromInt(spec_bins));
    return std.math.pow(f64, 2, frac * span);
}

/// Format a duration in seconds as `M:SS` — minutes uncapped, seconds
/// zero-padded (e.g. 75s → "1:15", 3600s → "60:00").
fn clock(buf: []u8, secs: f64) []const u8 {
    const total: u64 = @intFromFloat(@max(secs, 0));
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ total / 60, total % 60 }) catch "?";
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
const zio = @import("zio");

test "writeFinalSummary renders the compact plain summary to any writer" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
    try dash.writeFinalSummary(&out.writer, &snap, .{ .elapsed_s = 2.0, .launched = 1, .end_rate = 500, .end_window_s = 1.0 });
    const text = out.written();

    try testing.expect(std.mem.indexOf(u8, text, "latency (coordinated-omission corrected)") != null);
    try testing.expect(std.mem.indexOf(u8, text, "100 requests in 2.00s") != null);
    try testing.expect(std.mem.indexOf(u8, text, "50 req/s") != null);
    // No wrk2-style framing survives.
    try testing.expect(std.mem.indexOf(u8, text, "Requests/sec:") == null);
    try testing.expect(std.mem.indexOf(u8, text, "Running") == null);
    // No terminal control sequences in the redirectable summary.
    try testing.expect(std.mem.indexOf(u8, text, "\x1b") == null);
    // No deadline mode here, so neither overload line appears.
    try testing.expect(std.mem.indexOf(u8, text, "deadline misses") == null);
    try testing.expect(std.mem.indexOf(u8, text, "peak schedule lag") == null);
    // Constant load: the average is the whole story, so no ramp line.
    try testing.expect(std.mem.indexOf(u8, text, "ramp") == null);
}

test "a ramp's summary reports the rate it ended at, not just the average" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{
        .rate = 100,
        .rate_end = 1000,
        .url = try cli.parseUrl("http://127.0.0.1:8080/"),
    };
    var dash_buf: [1024]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 5500; // 10s of a perfect 100->1000 ramp
    snap.counters.recordStatus(200);

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    try dash.writeFinalSummary(&out.writer, &snap, .{ .elapsed_s = 10.0, .launched = 8, .end_rate = 955, .end_window_s = 1.0 });
    const text = out.written();

    // The first line stays `requests / duration` — 550, the ramp's midpoint,
    // which would read as a failure against a 1000 req/s target. The second
    // line carries the tail, and says the ramp was in fact kept.
    try testing.expect(std.mem.indexOf(u8, text, "5500 requests in 10.00s") != null);
    try testing.expect(std.mem.indexOf(u8, text, "550 req/s") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ramp 100 \u{2192} 1000 req/s") != null);
    try testing.expect(std.mem.indexOf(u8, text, "955 req/s over the final 1.0s") != null);
}

test "a kept ramp is not painted as falling behind its schedule" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    // -R100:1000 over 4s: the schedule climbs 225 req/s every second, so the
    // second ending at t=4 offers 887.5 on average while standing at 1000 the
    // instant it closes. A client that served exactly 888 of them missed
    // nothing — comparing it against the instant would call it 11% short and
    // paint the panel red for a run that kept its schedule perfectly.
    const cfg = cli.Config{
        .rate = 100,
        .rate_end = 1000,
        .duration_ns = 4 * std.time.ns_per_s,
        .url = try cli.parseUrl("http://127.0.0.1/"),
    };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .enabled; // the red is the assertion, so force color on
    dash.term_cols = 120;

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 2200;
    snap.counters.recordStatus(200);

    var kept = Io.Writer.Allocating.init(testing.allocator);
    defer kept.deinit();
    _ = try dash.drawPanel(&kept.writer, &snap, .{ .rate = 888, .bps = 1000, .seconds = 1.0, .at_s = 4.0 }, 4.0, 4.0, true);
    // Both halves of the line read 888: the same window, measured two ways.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, kept.written(), "888 req/s"));
    try testing.expect(std.mem.indexOf(u8, kept.written(), "offered ") != null);
    try testing.expect(std.mem.indexOf(u8, kept.written(), "achieved ") != null);
    try testing.expect(std.mem.indexOf(u8, kept.written(), Colors.enabled.red ++ "888 req/s") == null);

    // A target that genuinely couldn't hold the top of the ramp still goes red.
    var behind = Io.Writer.Allocating.init(testing.allocator);
    defer behind.deinit();
    _ = try dash.drawPanel(&behind.writer, &snap, .{ .rate = 400, .bps = 1000, .seconds = 1.0, .at_s = 4.0 }, 4.0, 4.0, true);
    try testing.expect(std.mem.indexOf(u8, behind.written(), Colors.enabled.red ++ "400 req/s") != null);
}

test "a requested stop shows on the panel without breaking its line accounting" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/") };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .{};
    dash.term_cols = 120;

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 100;
    snap.counters.recordStatus(200);

    var stop = std.atomic.Value(bool).init(false);
    dash.stop_requested = &stop;

    // The whole point of the accounting: `prev_lines` is how far the *next*
    // frame moves up, so a panel that writes more newlines than it reports
    // repaints mid-panel and strands a duplicate header above itself. A stop
    // notice printed to stderr from outside the panel does exactly that.
    var running = Io.Writer.Allocating.init(testing.allocator);
    defer running.deinit();
    const live = try dash.drawPanel(&running.writer, &snap, .{ .rate = 100, .bps = 1000, .seconds = 1.0, .at_s = 1.0 }, 1.0, 30.0, false);
    try testing.expectEqual(std.mem.count(u8, running.written(), "\n"), live);
    try testing.expect(std.mem.indexOf(u8, running.written(), "✕") == null);

    stop.store(true, .monotonic);
    var stopping = Io.Writer.Allocating.init(testing.allocator);
    defer stopping.deinit();
    const cut = try dash.drawPanel(&stopping.writer, &snap, .{ .rate = 100, .bps = 1000, .seconds = 1.0, .at_s = 1.0 }, 1.0, 30.0, false);
    try testing.expectEqual(std.mem.count(u8, stopping.written(), "\n"), cut);
    // The recording dot gives way to a cross, and the notice lands inside the
    // panel — one line taller than the same frame with no stop pending.
    try testing.expect(std.mem.indexOf(u8, stopping.written(), "✕") != null);
    try testing.expect(std.mem.indexOf(u8, stopping.written(), "●") == null);
    try testing.expect(std.mem.indexOf(u8, stopping.written(), "stopping — signal again to abort") != null);
    try testing.expectEqual(live + 1, cut);

    // Settled: the panel stays as the run's record, so the cross persists and
    // the hint gives way to what the numbers mean.
    var final_out = Io.Writer.Allocating.init(testing.allocator);
    defer final_out.deinit();
    const done = try dash.drawPanel(&final_out.writer, &snap, .{ .rate = 100, .bps = 1000, .seconds = 1.0, .at_s = 1.0 }, 1.0, 30.0, true);
    try testing.expectEqual(std.mem.count(u8, final_out.written(), "\n"), done);
    try testing.expect(std.mem.indexOf(u8, final_out.written(), "✕") != null);
    try testing.expect(std.mem.indexOf(u8, final_out.written(), "signal again") == null);
    try testing.expect(std.mem.indexOf(u8, final_out.written(), "stopped early") != null);
}

test "a live repaint is bracketed by exactly one synchronized update" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io_ = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/") };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io_, &cfg, .empty, &dash_buf);
    dash.colors = .{}; // no SGR, so the only escapes left are the ones under test
    dash.term_cols = 120;

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 100;
    snap.counters.recordStatus(200);

    var first = Io.Writer.Allocating.init(testing.allocator);
    defer first.deinit();
    try dash.repaint(&first.writer, &snap, .{ .rate = 100, .bps = 1000, .seconds = 1.0, .at_s = 1.0 }, 1.0, 30.0, false);
    const f = first.written();

    // The whole frame sits inside the update: opened before anything is drawn
    // (the erase included — mid-erase is exactly the state being hidden) and
    // closed only once the last cell is out.
    try testing.expect(std.mem.startsWith(u8, f, sync_begin));
    try testing.expect(std.mem.endsWith(u8, f, sync_end));
    // Balanced, and nothing else escapes: an unmatched or duplicated open would
    // leave the terminal holding its display, which looks like a hung run.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, f, sync_begin));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, f, sync_end));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, f, "\x1b"));
    // The bracket carries no newlines, so `prev_lines` still counts panel rows
    // and the next repaint moves up exactly as far as it did before.
    try testing.expectEqual(std.mem.count(u8, f, "\n"), dash.prev_lines);

    // The second frame erases the first from *inside* the update — the point of
    // the bracket — and is still opened and closed exactly once.
    var second = Io.Writer.Allocating.init(testing.allocator);
    defer second.deinit();
    const before = dash.prev_lines;
    try dash.repaint(&second.writer, &snap, .{ .rate = 100, .bps = 1000, .seconds = 1.0, .at_s = 2.0 }, 2.0, 30.0, false);
    const g = second.written();

    var cursor_up_buf: [16]u8 = undefined;
    const cursor_up = try std.fmt.bufPrint(&cursor_up_buf, "\r\x1b[{d}A\x1b[J", .{before});
    const up_at = std.mem.indexOf(u8, g, cursor_up) orelse return error.NoRepaintSeek;
    try testing.expect(up_at > std.mem.indexOf(u8, g, sync_begin).?);
    try testing.expect(up_at < std.mem.indexOf(u8, g, sync_end).?);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, g, sync_begin));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, g, sync_end));
    try testing.expectEqual(std.mem.count(u8, g, "\n"), dash.prev_lines);
}

test "spectrogram renders a bimodal interval as two separated clusters" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/"), .interval_ns = std.time.ns_per_s };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .{}; // disabled: cells are glyph-or-space with no SGR to parse
    dash.term_cols = 80;

    // A bimodal cumulative snapshot: a ~0.5ms mode and a ~500ms mode, three
    // decades apart.
    var h = try stats.newHistogram(testing.allocator);
    defer h.deinit();
    var i: usize = 0;
    while (i < 400) : (i += 1) h.record(500);
    while (i < 600) : (i += 1) h.record(500_000);
    dash.pushSpecRow(&h);

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    const lines = try dash.drawSpectrogram(&out.writer, h.highest_trackable);
    const text = out.written();

    // Fixed height from the first frame: spec_rows_max rows + the scale line.
    try testing.expectEqual(@as(usize, spec_rows_max + 1), lines);
    // The scale carries latency labels spanning the two modes.
    try testing.expect(std.mem.indexOf(u8, text, "us") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ms") != null);

    // The single data row is the last one (newest sits at the bottom); the rows
    // above it are empty padding. Bimodality: that row has two heat clusters with
    // a gap. Heat glyphs are 3-byte UTF-8 (lead byte 0xE2); an empty cell is a
    // space (0x20). Find a 0xE2 … 0x20 … 0xE2 pattern within it.
    var it = std.mem.splitScalar(u8, text, '\n');
    var data_row: []const u8 = "";
    while (it.next()) |ln| {
        if (std.mem.indexOfScalar(u8, ln, 0xE2) != null) data_row = ln;
    }
    const g1 = std.mem.indexOfScalar(u8, data_row, 0xE2) orelse return error.NoGlyph;
    const gap = std.mem.indexOfScalarPos(u8, data_row, g1, ' ') orelse return error.NoGap;
    try testing.expect(std.mem.indexOfScalarPos(u8, data_row, gap, 0xE2) != null);
}

test "spectrogram renders a dense interval as an unbroken gradient" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/"), .interval_ns = std.time.ns_per_s };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .{}; // disabled: cells are glyph-or-space with no SGR to parse
    dash.term_cols = 120; // wider than spec_width, so the full 100 columns render

    // One dense mode: a lognormal around 78µs, wide enough (20µs..300µs, ~2
    // octaves more than the 100 columns can hold) that the framed bin range is
    // downsampled onto the columns — the regime the issue's run was in.
    var h = try stats.newHistogram(testing.allocator);
    defer h.deinit();
    var v: u64 = 20;
    while (v <= 300) : (v += 1) {
        const z = (@log(@as(f64, @floatFromInt(v))) - @log(78.0)) / 0.35;
        h.recordCount(v, @intFromFloat(3.0e6 * @exp(-0.5 * z * z) / @as(f64, @floatFromInt(v))));
    }
    dash.pushSpecRow(&h);

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    _ = try dash.drawSpectrogram(&out.writer, h.highest_trackable);

    // The newest row is the last one carrying glyphs.
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    var row: []const u8 = "";
    while (it.next()) |ln| {
        if (std.mem.indexOfScalar(u8, ln, 0xE2) != null) row = ln;
    }

    // Decode the row into one intensity level per column: a space is 0, and the
    // four block glyphs (U+2591..U+2593, U+2588) climb from 1 to 4.
    var level: [spec_width]u8 = undefined;
    var cols: usize = 0;
    var i: usize = 0;
    while (i < row.len) : (cols += 1) {
        if (row[i] == ' ') {
            level[cols] = 0;
            i += 1;
            continue;
        }
        level[cols] = switch (std.mem.readInt(u24, row[i..][0..3], .big)) {
            0xE29691 => 1, // ░
            0xE29692 => 2, // ▒
            0xE29693 => 3, // ▓
            0xE29688 => 4, // █
            else => return error.UnexpectedGlyph,
        };
        i += 3;
    }

    // A single mode must render as a single run of occupied cells: no interior
    // blanks. Bins finer than the histogram's resolution would otherwise leave
    // gaps there, drawing an unbroken distribution as a comb of stripes.
    var lo: usize = 0;
    while (lo < cols and level[lo] == 0) lo += 1;
    var hi: usize = cols - 1;
    while (hi > lo and level[hi] == 0) hi -= 1;
    try testing.expect(hi - lo > 20); // the mode spans most of the width
    for (level[lo .. hi + 1]) |l| try testing.expect(l > 0);

    // And it must render as one hill: intensity climbs to the peak, then falls.
    // Summing whole bins per column made a column covering two of them twice as
    // hot as its one-bin neighbour, which shows up here as a dip on the way up
    // (or a bump on the way down).
    var peak = lo;
    for (level[lo .. hi + 1], lo..) |l, x| if (l > level[peak]) {
        peak = x;
    };
    for (lo..peak) |x| try testing.expect(level[x] <= level[x + 1]);
    for (peak..hi) |x| try testing.expect(level[x] >= level[x + 1]);
}

test "spectrogram reserves full height even before any data" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/") };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .{};
    dash.term_cols = 120; // wider than spec_width, so the full 100 columns render

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();

    // No rows pushed yet: the full height is still reserved (empty rows + a
    // blank scale), so the panel never grows once data arrives.
    try testing.expectEqual(@as(usize, spec_rows_max + 1), try dash.drawSpectrogram(&out.writer, stats.hist_highest));
    // Every rendered row is exactly spec_width columns (no glyphs, all spaces).
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    var rows: usize = 0;
    while (it.next()) |ln| {
        if (ln.len == 0) continue;
        rows += 1;
        try testing.expectEqual(@as(usize, spec_width), ln.len);
        try testing.expect(std.mem.indexOfScalar(u8, ln, 0xE2) == null);
    }
    try testing.expectEqual(@as(usize, spec_rows_max + 1), rows);
}

test "spectrogram clamps its width to a narrow terminal (no wrap)" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1/") };
    var dash_buf: [64]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);
    dash.colors = .{};
    dash.term_cols = 40; // narrower than spec_width

    var h = try stats.newHistogram(testing.allocator);
    defer h.deinit();
    h.record(1000);
    dash.pushSpecRow(&h);

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    _ = try dash.drawSpectrogram(&out.writer, h.highest_trackable);
    // No row exceeds the terminal width, so nothing wraps and desyncs the repaint.
    var it = std.mem.splitScalar(u8, out.written(), '\n');
    while (it.next()) |ln| {
        if (ln.len == 0) continue;
        // Bytes may exceed columns (multibyte glyphs), so count display columns:
        // ASCII/space = 1 col, each 3-byte block glyph = 1 col.
        var cols: usize = 0;
        var bi: usize = 0;
        while (bi < ln.len) {
            if (ln[bi] & 0x80 == 0) bi += 1 else bi += 3;
            cols += 1;
        }
        try testing.expect(cols <= dash.term_cols);
    }
}

test "writeFinalSummary surfaces deadline misses and peak schedule lag" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const cfg = cli.Config{ .url = try cli.parseUrl("http://127.0.0.1:8080/"), .deadline_ns = 100 * std.time.ns_per_ms };
    var dash_buf: [1024]u8 = undefined;
    var dash = Dashboard.init(io, &cfg, .empty, &dash_buf);

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    snap.hist.record(1000);
    snap.counters.completed = 100;
    snap.counters.recordStatus(200);
    snap.counters.deadline_errors = 42;
    snap.counters.max_behind_ns = 250 * std.time.ns_per_ms; // 250ms peak lag

    var out = Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    try dash.writeFinalSummary(&out.writer, &snap, .{ .elapsed_s = 2.0, .launched = 1, .end_rate = 500, .end_window_s = 1.0 });
    const text = out.written();

    try testing.expect(std.mem.indexOf(u8, text, "deadline misses: 42") != null);
    try testing.expect(std.mem.indexOf(u8, text, "peak schedule lag: 250.00ms") != null);
}
