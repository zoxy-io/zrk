const std = @import("std");
const zio = @import("zio");
const Io = std.Io;

const cli = @import("cli.zig");
const runner = @import("runner.zig");
const stats = @import("stats.zig");
const report = @import("report.zig");
const hdr = @import("hdr.zig");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    const argv = if (args.len > 1) args[1..] else args[0..0];

    const parsed = cli.parse(arena, argv) catch |err| {
        try printUsageError(init.io, err);
        std.process.exit(2);
    };
    var cfg: cli.Config = switch (parsed) {
        .help => {
            try writeAll(init.io, .stdout(), cli.usage);
            return;
        },
        .version => {
            try writeAll(init.io, .stdout(), "zrk " ++ cli.version ++ "\n");
            return;
        },
        .config => |c| c,
    };

    const rt = try zio.Runtime.init(arena, .{
        .executors = .exact(cfg.threads),
    });
    defer rt.deinit();
    const io = rt.io();

    // Resolve `-b @FILE` / `-b @-` now that we have I/O; the runner only ever
    // sees `cfg.body` as raw bytes.
    if (cfg.body_path) |path| {
        cfg.body = readBody(arena, io, path) catch |err| {
            try printBodyError(io, path, err);
            std.process.exit(2);
        };
    }

    const json = cfg.format == .json;

    // The CLI is a thin shell over the embeddable runner. In text mode the
    // dashboard renders the runner's periodic snapshots via the progress
    // callback; in JSON mode the run is silent and only the summary is emitted.
    var dash_buf: [8192]u8 = undefined;
    var dash = tui.Dashboard.init(io, &cfg, init.minimal.environ, &dash_buf);

    // Optional per-interval NDJSON time series. The File.Writer is a pinned
    // local (TimeSeries only borrows a *Io.Writer) so nothing dangles on a move.
    //
    // `--timeseries -` streams the rows to stdout so they can be piped into a
    // live plotter; stdout is then the series' and not the report's, so the
    // dashboard is suppressed below and the summary goes elsewhere.
    const ts_stdout = cfg.timeseriesOnStdout();
    var ts_buf: [4096]u8 = undefined;
    var ts_file: Io.File = undefined;
    var ts_fw: Io.File.Writer = undefined;
    var ts_obj: report.TimeSeries = undefined;
    var ts_ptr: ?*report.TimeSeries = null;
    if (cfg.timeseries_path) |path| {
        ts_file = if (ts_stdout) .stdout() else try Io.Dir.cwd().createFile(io, path, .{});
        // A created file is ours from offset 0, so positional writes are fine.
        // stdout is not: it is a shared stream whose offset other writers (and
        // the shell's `>>`) advance, and pwriting it from 0 would overwrite
        // whatever is already there -- see the note on `writeAll`.
        ts_fw = if (ts_stdout) .initStreaming(ts_file, io, &ts_buf) else .init(ts_file, io, &ts_buf);
        ts_obj = try report.TimeSeries.init(arena, &ts_fw.interface, &cfg);
        ts_ptr = &ts_obj;
    }
    defer if (cfg.timeseries_path != null) {
        ts_obj.deinit();
        // stdout is the process', not ours to close.
        if (!ts_stdout) ts_file.close(io);
    };

    var progress: Progress = .{ .io = io, .dash = if (json or ts_stdout) null else &dash, .ts = ts_ptr };
    const active = progress.dash != null or progress.ts != null;
    const ctx: ?*anyopaque = if (active) @ptrCast(&progress) else null;
    const cb: ?runner.ProgressFn = if (active) onProgress else null;

    // The fast redraw cadence only makes sense for a live TUI; plain lines
    // and headless runs stay on the --interval stats window.
    const frame_ns: u64 = if (progress.dash != null and dash.tui) cfg.refresh_ns else 0;

    // Ctrl-C (or SIGTERM) stops the run and still reports what was measured — a
    // long run interrupted near its end otherwise threw all of it away. The
    // watchers set a flag the runner polls rather than canceling it:
    // cancellation discards the measurement, the opposite of what an interrupt
    // should do here.
    var interrupt: Interrupt = .{};
    var sig_group: Io.Group = .init;
    // With a live panel the terminal belongs to the dashboard: the watchers stay
    // silent and the panel reports the stop itself, since a stderr notice
    // printed under the panel scrolls it out from under the repaint accounting.
    const live_panel = progress.dash != null and dash.tui;
    const watching = installInterrupt(io, &sig_group, &interrupt, !live_panel);
    defer if (watching) sig_group.cancel(io);
    if (watching) dash.stop_requested = &interrupt.flag;

    const result = runner.run(arena, io, &cfg, frame_ns, ctx, cb, if (watching) &interrupt.flag else null) catch |err| {
        try printRunError(io, err);
        std.process.exit(1);
    };
    var snapshot = result.snapshot;

    const run_facts: report.Run = .{
        .elapsed_s = result.elapsed_s,
        .launched = result.launched,
        .interrupted = result.interrupted,
        .end_rate = result.end_rate,
        .end_bytes_per_sec = result.end_bytes_per_sec,
        .end_window_s = result.end_window_s,
        .end_window_at_s = result.end_window_at_s,
    };

    if (json) {
        try writeJsonReport(arena, io, &cfg, &snapshot, run_facts);
    } else if (cfg.output_path) |path| {
        // Text report redirected to --output; leave a breadcrumb on stdout —
        // unless the time series owns stdout, where a breadcrumb would land
        // mid-stream as a line no NDJSON reader can parse.
        try writeTextReport(io, &dash, path, &snapshot, run_facts);
        if (!ts_stdout) try dash.finalRedirected(path);
    } else if (ts_stdout) {
        try writeSummaryToStderr(io, &dash, &snapshot, run_facts);
    } else {
        try dash.final(&snapshot, run_facts);
    }

    // Optional HdrHistogram percentile distribution (.hgrm) export.
    if (cfg.hdr_path) |path| {
        try writeHdrFile(io, path, &snapshot.hist);
    }

    // An interrupted run is not a result to gate on: it covers less than
    // --duration, so a passing --slo-p99 would mean nothing. Exit 128+signal
    // without evaluating the gates.
    if (result.interrupted) std.process.exit(interrupt.exit_code.load(.monotonic));

    // CI gates: a breach exits 3 so a harness can fail the build.
    const slo = report.checkSlo(&cfg, &snapshot);
    if (!slo.passed()) {
        try printSloBreach(io, &cfg, &snapshot, slo);
        std.process.exit(3);
    }
}

/// Shared state for the signal watchers. One watcher runs per signal kind, so
/// everything here is touched from several tasks at once.
const Interrupt = struct {
    /// Polled by the runner's progress loop; raising it ends the run early.
    flag: std.atomic.Value(bool) = .init(false),
    /// Claimed by whichever watcher sees the *first* signal. Shared across kinds
    /// so SIGINT-then-SIGTERM aborts rather than printing a second notice — two
    /// tasks writing stderr at once interleave and truncate each other.
    claimed: std.atomic.Value(bool) = .init(false),
    /// 128 + signal number, the shell's convention: 130 for SIGINT, 143 for
    /// SIGTERM. Set by the watcher that claims the stop.
    exit_code: std.atomic.Value(u8) = .init(130),
};

/// Watch for SIGINT and SIGTERM for the duration of the run. The first signal
/// asks the runner to stop and report; a second (of either kind) means whoever
/// sent it wants out now, so take the process down rather than keep waiting on
/// a graceful stop that is evidently not arriving. Returns false if no watcher
/// could be installed, in which case the default disposition stays and a signal
/// kills the process as before.
///
/// `notify` writes the stop notice to stderr; pass false when a live dashboard
/// owns the terminal, which shows the stop on the panel instead.
fn installInterrupt(io: Io, group: *Io.Group, it: *Interrupt, notify: bool) bool {
    var any = false;
    // SIGTERM matters as much as SIGINT here: `docker stop` and most CI
    // cancellations send it, and without this a containerized run loses
    // everything it measured.
    for ([_]SignalSpec{
        .{ .kind = .interrupt, .code = 130, .notice = "\nzrk: interrupt received, stopping (Ctrl-C again to abort)\n" },
        .{ .kind = .terminate, .code = 143, .notice = "\nzrk: SIGTERM received, stopping (signal again to abort)\n" },
    }) |spec| {
        group.concurrent(io, watchSignal, .{ io, spec, it, notify }) catch continue;
        any = true;
    }
    return any;
}

const SignalSpec = struct {
    kind: zio.SignalKind,
    code: u8,
    notice: []const u8,
};

fn watchSignal(io: Io, spec: SignalSpec, it: *Interrupt, notify: bool) void {
    var sig = zio.Signal.init(spec.kind) catch return;
    defer sig.deinit();
    while (true) {
        sig.wait() catch return; // canceled at end of run
        // Whoever gets here first owns the stop and the notice; anyone after —
        // a repeat of this signal, or the other kind — is the abort request.
        if (it.claimed.swap(true, .acq_rel)) std.process.exit(spec.code);
        it.exit_code.store(spec.code, .monotonic);
        it.flag.store(true, .monotonic);
        if (notify) writeAll(io, .stderr(), spec.notice) catch {};
    }
}

/// Write the wrk2-style text report to `--output` (text mode with -o set).
fn writeTextReport(io: Io, dash: *tui.Dashboard, path: []const u8, snap: *const stats.Snapshot, run: report.Run) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [8192]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    try dash.writeFinalSummary(&fw.interface, snap, run);
    try fw.interface.flush();
}

/// Write the JSON summary to `--output` (or stdout when unset; stderr when
/// `--timeseries -` has claimed stdout for the row stream).
fn writeJsonReport(gpa: std.mem.Allocator, io: Io, cfg: *const cli.Config, snap: *const stats.Snapshot, run: report.Run) !void {
    var close = false;
    const fallback: Io.File = if (cfg.timeseriesOnStdout()) .stderr() else .stdout();
    const file = try openOut(io, cfg.output_path, fallback, &close);
    defer if (close) file.close(io);
    var buf: [8192]u8 = undefined;
    // Only a freshly created --output file can be written positionally; the
    // stdout/stderr fallback is a shared stream that earlier writes (an SLO
    // breach notice, a sink warning) have already advanced, and pwriting it
    // from byte 0 corrupts the summary rather than following them.
    var fw: Io.File.Writer = if (cfg.output_path != null)
        .init(file, io, &buf)
    else
        .initStreaming(file, io, &buf);
    try report.writeJson(gpa, &fw.interface, cfg, snap, run);
    try fw.interface.flush();
}

/// Write the compact text summary to stderr. Used when `--timeseries -` owns
/// stdout and no `--output` was given: the run still has to report itself
/// somewhere, and stderr is the stream a plotting pipe leaves free.
fn writeSummaryToStderr(io: Io, dash: *tui.Dashboard, snap: *const stats.Snapshot, run: report.Run) !void {
    var buf: [8192]u8 = undefined;
    // Streaming, not positional: stderr is shared with the interrupt notice, the
    // sink warnings and the SLO breach message, and a pwrite from byte 0 would
    // interleave with them instead of following them (see `writeAll`).
    var fw: Io.File.Writer = .initStreaming(.stderr(), io, &buf);
    try dash.writeFinalSummary(&fw.interface, snap, run);
    try fw.interface.flush();
}

/// Write the `.hgrm` percentile distribution, scaling microseconds to
/// milliseconds to match wrk2 / the HdrHistogram plotter convention.
fn writeHdrFile(io: Io, path: []const u8, h: *const hdr.Histogram) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [8192]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    try h.writePercentileDistribution(&fw.interface, 1000.0, 5);
    try fw.interface.flush();
}

fn openOut(io: Io, path: ?[]const u8, fallback: Io.File, close: *bool) !Io.File {
    if (path) |p| {
        close.* = true;
        return Io.Dir.cwd().createFile(io, p, .{});
    }
    close.* = false;
    return fallback;
}

/// Upper bound on a request body read from a file/stdin, so a wrong path can't
/// exhaust memory. 64 MiB is far larger than any realistic load-test payload.
const max_body_bytes = 64 << 20;

/// Read the request body from `path` (or stdin when `path` is "-"). Returned
/// bytes live in `arena`.
fn readBody(arena: std.mem.Allocator, io: Io, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) {
        var buf: [4096]u8 = undefined;
        var fr: Io.File.Reader = .init(.stdin(), io, &buf);
        return fr.interface.allocRemaining(arena, .limited(max_body_bytes));
    }
    return Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_body_bytes));
}

fn printBodyError(io: Io, path: []const u8, err: anyerror) !void {
    var buf: [512]u8 = undefined;
    const src = if (std.mem.eql(u8, path, "-")) "stdin" else path;
    const msg = std.fmt.bufPrint(&buf, "zrk: cannot read body from {s}: {s}\n", .{ src, @errorName(err) }) catch
        "zrk: cannot read request body\n";
    try writeAll(io, .stderr(), msg);
}

fn printSloBreach(io: Io, cfg: *const cli.Config, snap: *const stats.Snapshot, slo: report.SloResult) !void {
    var buf: [256]u8 = undefined;
    if (!slo.p99_ok) {
        const p99_us = snap.hist.valueAtPercentile(99);
        const limit_us = (cfg.slo_p99_ns orelse 0) / std.time.ns_per_us;
        const msg = std.fmt.bufPrint(&buf, "zrk: SLO breach: p99 {d}us exceeds limit {d}us\n", .{ p99_us, limit_us }) catch "zrk: SLO breach: p99\n";
        try writeAll(io, .stderr(), msg);
    }
    if (!slo.error_rate_ok) {
        const rate = report.errorRate(snap.counters);
        const msg = std.fmt.bufPrint(&buf, "zrk: SLO breach: error rate {d:.4} exceeds limit {d:.4}\n", .{ rate, cfg.max_error_rate orelse 0 }) catch "zrk: SLO breach: error rate\n";
        try writeAll(io, .stderr(), msg);
    }
}

/// Fan-out target for the runner's progress callback: the live dashboard and/or
/// the NDJSON time series, whichever are active this run.
const Progress = struct {
    io: Io,
    dash: ?*tui.Dashboard,
    ts: ?*report.TimeSeries,
    /// Set once a sink has reported a failure, so a persistently broken one
    /// (a full disk, a closed pipe) warns a single time instead of on every
    /// wake — this callback fires up to 12.5x a second with a live dashboard.
    dash_failed: bool = false,
    ts_failed: bool = false,
};

fn onProgress(
    context: ?*anyopaque,
    snapshot: *const stats.Snapshot,
    now_ns: i128,
    elapsed_s: f64,
    total_s: f64,
    tick: runner.Tick,
) void {
    const p: *Progress = @ptrCast(@alignCast(context.?));
    // A failing sink must not abort the run — the measurement is the point, and
    // this callback cannot propagate anyway (ProgressFn returns void). But
    // dropping the error silently meant a `--timeseries` file that stopped
    // accepting writes produced a short file and a report that looked fine, with
    // nothing said. Report it once and keep measuring.
    if (tick.frame) if (p.dash) |d| d.frame(snapshot, now_ns, elapsed_s, total_s) catch |err| {
        if (!p.dash_failed) {
            p.dash_failed = true;
            warnSinkFailed(p.io, "dashboard", err);
        }
    };
    if (tick.row) if (p.ts) |t| t.record(snapshot, elapsed_s) catch |err| {
        if (!p.ts_failed) {
            p.ts_failed = true;
            warnSinkFailed(p.io, "--timeseries", err);
        }
    };
}

/// Note a progress sink that stopped working, without derailing the run: this
/// runs mid-measurement, so a failure to report the failure is itself ignored.
fn warnSinkFailed(io: Io, sink: []const u8, err: anyerror) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &buf,
        "zrk: {s} output failed ({s}); continuing without it\n",
        .{ sink, @errorName(err) },
    ) catch "zrk: progress output failed; continuing without it\n";
    writeAll(io, .stderr(), msg) catch {};
}

fn printRunError(io: Io, err: anyerror) !void {
    var buf: [256]u8 = undefined;
    const msg = switch (err) {
        error.UnknownHostName, error.HostLacksNetworkAddresses => std.fmt.bufPrint(
            &buf,
            "zrk: could not resolve the target host: {s}\n",
            .{@errorName(err)},
        ) catch "zrk: could not resolve the target host\n",
        error.NoConnectionsLaunched => "zrk: could not launch any connections\n",
        // The run was cut short, so there is no full-duration sample to report.
        // Say so and exit nonzero rather than emitting a report that looks
        // complete but covers a fraction of --duration.
        error.Canceled => "zrk: run was interrupted before --duration elapsed; no report written\n",
        else => std.fmt.bufPrint(
            &buf,
            "zrk: {s} (try -k to skip TLS verification if this is certificate-related)\n",
            .{@errorName(err)},
        ) catch "zrk: run failed\n",
    };
    try writeAll(io, .stderr(), msg);
}

fn writeAll(io: Io, file: Io.File, bytes: []const u8) !void {
    var buf: [256]u8 = undefined;
    // .init defaults to positional mode (pwrite-style, starting at offset 0
    // on every fresh Writer). Every call site here constructs a new Writer
    // per write, so two sequential calls to the same redirected file (e.g.
    // printUsageError's message line, then the usage block) would each
    // start writing at byte 0 and clobber one another instead of appending
    // -- invisible against a terminal or pipe (neither is seekable, so the
    // position is moot), but silently drops everything but the last write
    // once stderr/stdout is redirected to a real file. .initStreaming just
    // writes at the fd's current offset, which is what a log stream wants.
    var fw: Io.File.Writer = .initStreaming(file, io, &buf);
    try fw.interface.writeAll(bytes);
    try fw.interface.flush();
}

fn printUsageError(io: Io, err: cli.ParseError) !void {
    const msg = switch (err) {
        error.MissingUrl => "zrk: missing target URL\n\n",
        error.UnknownFlag => "zrk: unknown flag\n\n",
        error.MissingValue => "zrk: an option is missing its value\n\n",
        error.InvalidNumber => "zrk: expected a number\n\n",
        error.InvalidDuration => "zrk: invalid duration (use e.g. 500ms, 30s, 2m, 1h)\n\n",
        error.InvalidUrl => "zrk: invalid URL (expected http:// or https://)\n\n",
        error.InvalidHeader => "zrk: invalid header (expected 'Name: Value')\n\n",
        error.InvalidFormat => "zrk: invalid --format (expected 'text' or 'json')\n\n",
        error.ZeroThreads => "zrk: threads (-t) must be greater than 0\n\n",
        error.TooManyThreads => "zrk: threads (-t) exceeds the maximum this platform supports\n\n",
        error.ZeroConnections => "zrk: connections (-c) must be greater than 0\n\n",
        error.ZeroRate => "zrk: rate (-R) must be greater than 0\n\n",
        error.ZeroInterval => "zrk: --interval must be greater than 0\n\n",
        error.ZeroRefresh => "zrk: --refresh must be greater than 0\n\n",
        error.ClosedWithRamp => "zrk: --closed is incompatible with a ramp (-R A:B)\n\n",
        error.ClosedWithDeadline => "zrk: --closed is incompatible with --deadline\n\n",
        error.KeepaliveWithHttp2 => "zrk: --disable-keepalive is incompatible with --http2\n\n",
        error.ZeroStreams => "zrk: streams (-s) must be greater than 0\n\n",
        error.StreamsWithoutHttp2 => "zrk: streams (-s) requires --http2 or --http3; HTTP/1.1 has no second stream to open\n\n",
        error.TooManyStreams => "zrk: streams (-s) exceeds the per-connection maximum\n\n",
        error.Http3WithHttp2 => "zrk: --http3 and --http2 are different transports; run them separately\n\n",
        error.Http3WithoutTls => "zrk: --http3 needs an https:// URL; QUIC has no cleartext mode\n\n",
        error.Http3BodyTooLarge => "zrk: --body is too large for --http3; the request must fit one QUIC stream write\n\n",
        error.OutOfMemory => "zrk: out of memory\n\n",
    };
    try writeAll(io, .stderr(), msg);
    try writeAll(io, .stderr(), cli.usage);
}

test {
    std.testing.refAllDecls(@This());
}
