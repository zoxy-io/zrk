const std = @import("std");
const Io = std.Io;

const cli = @import("cli.zig");
const runner = @import("runner.zig");
const stats = @import("stats.zig");
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
    const cfg: cli.Config = switch (parsed) {
        .help => {
            try writeAll(io, .stdout(), cli.usage);
            return;
        },
        .config => |c| c,
    };

    // The CLI is a thin shell over the embeddable runner: the dashboard
    // renders the runner's periodic snapshots via the progress callback.
    var dash_buf: [8192]u8 = undefined;
    var dash = tui.Dashboard.init(io, &cfg, &dash_buf);

    const report = runner.run(arena, io, &cfg, @ptrCast(&dash), onProgress) catch |err| {
        try printRunError(io, err);
        std.process.exit(1);
    };
    var snapshot = report.snapshot;
    try dash.final(&snapshot, report.elapsed_s);
}

fn onProgress(
    context: ?*anyopaque,
    snapshot: *const stats.Snapshot,
    now_ns: i128,
    elapsed_s: f64,
    total_s: f64,
) void {
    const dash: *tui.Dashboard = @ptrCast(@alignCast(context.?));
    dash.frame(snapshot, now_ns, elapsed_s, total_s) catch {};
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
        error.ZeroConnections => "zrk: connections (-c) must be greater than 0\n\n",
        error.ZeroThreads => "zrk: threads (-t) must be greater than 0\n\n",
        error.ZeroRate => "zrk: rate (-R) must be greater than 0\n\n",
        error.OutOfMemory => "zrk: out of memory\n\n",
    };
    try writeAll(io, .stderr(), msg);
    try writeAll(io, .stderr(), cli.usage);
}

test {
    std.testing.refAllDecls(@This());
}
