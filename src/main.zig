const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const cli = @import("cli.zig");
const httpmod = @import("http.zig");
const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const stats = @import("stats.zig");
const tui = @import("tui.zig");
const tlsmod = @import("tls.zig");

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

    try run(arena, io, &cfg);
}

fn run(arena: std.mem.Allocator, io: Io, cfg: *const cli.Config) !void {
    const request = try httpmod.buildRequest(arena, cfg);
    const address = resolveAddress(io, cfg.url.host, cfg.url.port) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "zrk: could not resolve {s}:{d}: {s}\n", .{
            cfg.url.host, cfg.url.port, @errorName(err),
        }) catch "zrk: could not resolve host\n";
        try writeAll(io, .stderr(), msg);
        std.process.exit(1);
    };

    // Load the system trust store once (shared, read-mostly) for HTTPS with
    // verification enabled.
    var ca_store: ?tlsmod.CaStore = null;
    if (cfg.url.isTls() and !cfg.insecure) {
        ca_store = tlsmod.CaStore.load(arena, io) catch |err| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "zrk: could not load CA certificates: {s} (try -k to skip verification)\n", .{@errorName(err)}) catch "zrk: could not load CA certificates\n";
            try writeAll(io, .stderr(), msg);
            std.process.exit(1);
        };
    }
    const ca_ptr: ?*tlsmod.CaStore = if (ca_store) |*c| c else null;

    var fleet = try stats.Fleet.init(arena, cfg.connections, cfg.interval_ns, cfg.url.isTls());
    defer fleet.deinit();

    var stop = std.atomic.Value(bool).init(false);

    // Per-connection scheduled send spacing: the total target rate split evenly.
    const interval_ns: u64 = @intFromFloat(
        @as(f64, std.time.ns_per_s) * @as(f64, @floatFromInt(cfg.connections)) / @as(f64, @floatFromInt(cfg.rate)),
    );

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromNanoseconds(@intCast(cfg.duration_ns)));

    const params = fleet.buildParams(.{
        .io = io,
        .address = address,
        .host = cfg.url.host,
        .request = request,
        .is_tls = cfg.url.isTls(),
        .insecure = cfg.insecure,
        .interval_ns = interval_ns,
        .timeout_ns = cfg.timeout_ns,
        .end = end,
        .stop = &stop,
        .allocator = arena,
        .ca_store = ca_ptr,
        // histogram/counters/publish/tls_state are filled in by buildParams.
        .histogram = undefined,
        .counters = undefined,
    });

    // Launch each connection on its own thread. `concurrent` (unlike `async`)
    // guarantees real parallelism on the Threaded backend.
    var group: Io.Group = .init;
    var launched: u32 = 0;
    for (params) |*p| {
        group.concurrent(io, connection.run, .{p}) catch break;
        launched += 1;
    }
    if (launched == 0) {
        try writeAll(io, .stderr(), "zrk: could not launch any connections\n");
        std.process.exit(1);
    }

    // Drive the live dashboard on the main thread until the test duration ends.
    var dash_buf: [8192]u8 = undefined;
    var dash = tui.Dashboard.init(io, cfg, &dash_buf);

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(arena), .counters = .{} };

    while (true) {
        io.sleep(Io.Duration.fromNanoseconds(@intCast(cfg.interval_ns)), .awake) catch break;
        const t = Io.Timestamp.now(io, .awake);
        fleet.readSnapshot(io, &snap);
        const elapsed_s: f64 = @as(f64, @floatFromInt(start.durationTo(t).nanoseconds)) / std.time.ns_per_s;
        const total_s: f64 = @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s;
        dash.frame(&snap, t.nanoseconds, elapsed_s, total_s) catch {};
        if (t.nanoseconds >= end.nanoseconds) break;
    }

    // Signal stop, then cancel: connections idling between paced sends observe
    // `stop`, while any blocked on a stalled server read are interrupted by the
    // cancellation so shutdown never hangs.
    stop.store(true, .monotonic);
    group.cancel(io);

    const elapsed = start.durationTo(Io.Timestamp.now(io, .awake));
    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed.nanoseconds)) / std.time.ns_per_s;
    fleet.readFinal(&snap);
    try dash.final(&snap, elapsed_s);
}

/// Resolve a host (literal IP or DNS name) to a single address. DNS is done
/// once here; every connection then dials the resolved IP directly.
fn resolveAddress(io: Io, host: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parse(host, port)) |ip| return ip else |_| {}

    const host_name = try net.HostName.init(host);
    var buf: [16]net.HostName.LookupResult = undefined;
    var queue: Io.Queue(net.HostName.LookupResult) = .init(&buf);
    try host_name.lookup(io, &queue, .{ .port = port });

    // Prefer IPv4 (widely reachable); fall back to the first address of any
    // family if no IPv4 record is returned.
    var first: ?net.IpAddress = null;
    while (queue.getOneUncancelable(io)) |result| {
        switch (result) {
            .address => |a| {
                if (a == .ip4) return a;
                if (first == null) first = a;
            },
            .canonical_name => {},
        }
    } else |_| {} // error.Closed: queue drained
    return first orelse error.UnknownHostName;
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
