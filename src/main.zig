const std = @import("std");
const Io = std.Io;

const cli = @import("cli.zig");
const runner = @import("runner.zig");
const stats = @import("stats.zig");
const report = @import("report.zig");
const hdr = @import("hdr.zig");
const tui = @import("tui.zig");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    const argv = if (args.len > 1) args[1..] else args[0..0];

    const parsed = cli.parse(arena, argv) catch |err| {
        try printUsageError(io, err);
        std.process.exit(2);
    };
    var cfg: cli.Config = switch (parsed) {
        .help => {
            try writeAll(io, .stdout(), cli.usage);
            return;
        },
        .version => {
            try writeAll(io, .stdout(), "zrk " ++ cli.version ++ "\n");
            return;
        },
        .config => |c| c,
    };

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
    var dash = tui.Dashboard.init(io, &cfg, &dash_buf);

    // Optional per-interval NDJSON time series. The File.Writer is a pinned
    // local (TimeSeries only borrows a *Io.Writer) so nothing dangles on a move.
    var ts_buf: [4096]u8 = undefined;
    var ts_file: Io.File = undefined;
    var ts_fw: Io.File.Writer = undefined;
    var ts_obj: report.TimeSeries = undefined;
    var ts_ptr: ?*report.TimeSeries = null;
    if (cfg.timeseries_path) |path| {
        ts_file = try Io.Dir.cwd().createFile(io, path, .{});
        ts_fw = .init(ts_file, io, &ts_buf);
        ts_obj = try report.TimeSeries.init(arena, &ts_fw.interface, &cfg);
        ts_ptr = &ts_obj;
    }
    defer if (cfg.timeseries_path != null) {
        ts_obj.deinit();
        ts_file.close(io);
    };

    var progress: Progress = .{ .dash = if (json) null else &dash, .ts = ts_ptr };
    const active = progress.dash != null or progress.ts != null;
    const ctx: ?*anyopaque = if (active) @ptrCast(&progress) else null;
    const cb: ?runner.ProgressFn = if (active) onProgress else null;

    const result = runner.run(arena, io, &cfg, ctx, cb) catch |err| {
        try printRunError(io, err);
        std.process.exit(1);
    };
    var snapshot = result.snapshot;

    if (json) {
        try writeJsonReport(arena, io, &cfg, &snapshot, result.elapsed_s, result.launched);
    } else if (cfg.output_path) |path| {
        // Text report redirected to --output; leave a breadcrumb on stdout.
        try writeTextReport(io, &dash, path, &snapshot, result.elapsed_s);
        try dash.finalRedirected(path);
    } else {
        try dash.final(&snapshot, result.elapsed_s);
    }

    // Optional HdrHistogram percentile distribution (.hgrm) export.
    if (cfg.hdr_path) |path| {
        try writeHdrFile(io, path, &snapshot.hist);
    }

    // CI gates: a breach exits 3 so a harness can fail the build.
    const slo = report.checkSlo(&cfg, &snapshot);
    if (!slo.passed()) {
        try printSloBreach(io, &cfg, &snapshot, slo);
        std.process.exit(3);
    }
}

/// Write the wrk2-style text report to `--output` (text mode with -o set).
fn writeTextReport(io: Io, dash: *tui.Dashboard, path: []const u8, snap: *const stats.Snapshot, elapsed_s: f64) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [8192]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    try dash.writeReport(&fw.interface, snap, elapsed_s);
    try fw.interface.flush();
}

/// Write the JSON summary to `--output` (or stdout when unset).
fn writeJsonReport(gpa: std.mem.Allocator, io: Io, cfg: *const cli.Config, snap: *const stats.Snapshot, elapsed_s: f64, launched: u32) !void {
    var close = false;
    const file = try openOut(io, cfg.output_path, &close);
    defer if (close) file.close(io);
    var buf: [8192]u8 = undefined;
    var fw: Io.File.Writer = .init(file, io, &buf);
    try report.writeJson(gpa, &fw.interface, cfg, snap, elapsed_s, launched);
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

fn openOut(io: Io, path: ?[]const u8, close: *bool) !Io.File {
    if (path) |p| {
        close.* = true;
        return Io.Dir.cwd().createFile(io, p, .{});
    }
    close.* = false;
    return Io.File.stdout();
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
        var aw: Io.Writer.Allocating = .init(arena);
        _ = try fr.interface.streamRemaining(&aw.writer);
        return aw.toOwnedSlice();
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
    dash: ?*tui.Dashboard,
    ts: ?*report.TimeSeries,
};

fn onProgress(
    context: ?*anyopaque,
    snapshot: *const stats.Snapshot,
    now_ns: i128,
    elapsed_s: f64,
    total_s: f64,
) void {
    const p: *Progress = @ptrCast(@alignCast(context.?));
    if (p.dash) |d| d.frame(snapshot, now_ns, elapsed_s, total_s) catch {};
    if (p.ts) |t| t.record(snapshot, elapsed_s) catch {};
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
    var fw: Io.File.Writer = .init(file, io, &buf);
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
        error.ZeroConnections => "zrk: connections (-c) must be greater than 0\n\n",
        error.ZeroRate => "zrk: rate (-R) must be greater than 0\n\n",
        error.OutOfMemory => "zrk: out of memory\n\n",
    };
    try writeAll(io, .stderr(), msg);
    try writeAll(io, .stderr(), cli.usage);
}

test {
    std.testing.refAllDecls(@This());
}
