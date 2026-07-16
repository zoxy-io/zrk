//! Programmatic load-test entry point: everything the `zrk` CLI does,
//! minus argument parsing and the terminal dashboard. Embedders (for
//! example zoxy's bench harness) call `run` with a `cli.Config` and get
//! a typed `Report` back; an optional progress callback receives the
//! same periodic snapshots the dashboard renders.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const cli = @import("cli.zig");
const connection = @import("connection.zig");
const httpmod = @import("http.zig");
const pace = @import("pace.zig");
const stats = @import("stats.zig");
const tlsmod = @import("tls.zig");

/// The outcome of one complete load test. `snapshot.hist` is the
/// coordinated-omission-corrected latency histogram; both live in the
/// arena passed to `run`.
pub const Report = struct {
    snapshot: stats.Snapshot,
    elapsed_s: f64,
    launched: u32,
};

/// Called once per dashboard interval with the merged fleet snapshot.
pub const ProgressFn = *const fn (
    context: ?*anyopaque,
    snapshot: *const stats.Snapshot,
    now_ns: i128,
    elapsed_s: f64,
    total_s: f64,
) void;

/// Run one constant-throughput load test to completion. Blocks the
/// calling thread (worker connections run on their own threads); returns
/// after the configured duration with the final merged report.
pub fn run(
    arena: std.mem.Allocator,
    io: Io,
    cfg: *const cli.Config,
    progress_context: ?*anyopaque,
    progress: ?ProgressFn,
) !Report {
    const request = try httpmod.buildRequest(arena, cfg);
    const address = try resolveAddress(io, cfg.url.host, cfg.url.port);

    // Load the system trust store once (shared, read-mostly) for HTTPS
    // with verification enabled.
    var ca_store: ?tlsmod.CaStore = null;
    if (cfg.url.isTls() and !cfg.insecure) {
        ca_store = try tlsmod.CaStore.load(arena, io);
    }
    const ca_ptr: ?*tlsmod.CaStore = if (ca_store) |*c| c else null;

    var fleet = try stats.Fleet.init(arena, cfg.connections, cfg.interval_ns, cfg.url.isTls());
    defer fleet.deinit();

    var stop = std.atomic.Value(bool).init(false);

    // Per-connection send schedule: a constant spacing, or a linear ramp from
    // `rate` to `rate_end` over the run, split evenly across connections.
    const duration_s: f64 = @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s;
    const schedule = if (cfg.rate_end) |end_rate|
        pace.Schedule.linearTotal(cfg.rate, end_rate, cfg.connections, duration_s)
    else
        pace.Schedule.constantTotal(cfg.rate, cfg.connections);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromNanoseconds(@intCast(cfg.duration_ns)));

    const params = fleet.buildParams(.{
        .io = io,
        .address = address,
        .host = cfg.url.host,
        .request = request,
        .method = .of(cfg.method),
        .is_tls = cfg.url.isTls(),
        .insecure = cfg.insecure,
        .schedule = schedule,
        .timeout_ns = cfg.timeout_ns,
        .record_timeouts = cfg.record_timeouts,
        .end = end,
        .stop = &stop,
        .allocator = arena,
        .ca_store = ca_ptr,
        // histogram/counters/publish/tls_state are filled in by buildParams.
        .histogram = undefined,
        .counters = undefined,
    });

    // Launch each connection on its own thread. `concurrent` (unlike
    // `async`) guarantees real parallelism on the Threaded backend.
    var group: Io.Group = .init;
    var launched: u32 = 0;
    for (params) |*p| {
        group.concurrent(io, connection.run, .{p}) catch break;
        launched += 1;
    }
    if (launched == 0) {
        return error.NoConnectionsLaunched;
    }

    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(arena), .counters = .{} };
    const total_s: f64 = @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s;

    // Snapshot cadence: wake every interval, but never sleep past `end` — the
    // final (possibly partial) interval still gets a progress callback, and
    // the measured elapsed time tracks the configured duration instead of
    // rounding up to the next interval boundary (which deflated Requests/sec
    // whenever the duration wasn't a multiple of --interval).
    while (true) {
        const before = Io.Timestamp.now(io, .awake);
        if (before.nanoseconds >= end.nanoseconds) break;
        const interval_ns: @TypeOf(end.nanoseconds) = @intCast(cfg.interval_ns);
        const sleep_ns = @min(end.nanoseconds - before.nanoseconds, interval_ns);
        io.sleep(Io.Duration.fromNanoseconds(sleep_ns), .awake) catch break;

        const t = Io.Timestamp.now(io, .awake);
        fleet.readSnapshot(io, &snap);
        const elapsed_s: f64 = @as(f64, @floatFromInt(start.durationTo(t).nanoseconds)) / std.time.ns_per_s;
        if (progress) |callback| {
            callback(progress_context, &snap, t.nanoseconds, elapsed_s, total_s);
        }
    }

    // Signal stop, then cancel: connections idling between paced sends
    // observe `stop`, while any blocked on a stalled server read are
    // interrupted by the cancellation so shutdown never hangs.
    stop.store(true, .monotonic);
    group.cancel(io);

    const elapsed = start.durationTo(Io.Timestamp.now(io, .awake));
    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed.nanoseconds)) / std.time.ns_per_s;
    fleet.readFinal(&snap);
    return .{ .snapshot = snap, .elapsed_s = elapsed_s, .launched = launched };
}

/// Resolve a host (literal IP or DNS name) to a single address. DNS is
/// done once here; every connection then dials the resolved IP directly.
pub fn resolveAddress(io: Io, host: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.parse(host, port)) |ip| return ip else |_| {}

    const host_name = try net.HostName.init(host);
    var buf: [16]net.HostName.LookupResult = undefined;
    var queue: Io.Queue(net.HostName.LookupResult) = .init(&buf);
    try host_name.lookup(io, &queue, .{ .port = port });

    // Prefer IPv4 (widely reachable); fall back to the first address of
    // any family if no IPv4 record is returned.
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

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// Consume one request's header lines through the terminating blank line.
/// (Mirrors the fixture in connection.zig's tests.)
fn discardRequestHead(r: *Io.Reader) !void {
    while (true) {
        const line = try r.takeDelimiterInclusive('\n');
        if (line.len <= 2) return; // "\r\n" or "\n": end of headers
    }
}

/// Minimal keep-alive server: accepts one connection and answers every request
/// with a fixed 200 until the client closes.
fn testServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    while (true) {
        discardRequestHead(&r.interface) catch return;
        w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") catch return;
        w.interface.flush() catch return;
    }
}

test "run's elapsed time tracks the duration, not the interval grid" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();

    var group: Io.Group = .init;
    group.async(io, testServe, .{ io, &server });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});

    var cfg: cli.Config = .{
        .connections = 1,
        .rate = 200,
        // 300ms run with a 1s snapshot interval: the old loop always slept a
        // full interval before checking `end`, reporting ~1s elapsed for a
        // 0.3s test and deflating Requests/sec by >3x.
        .duration_ns = 300 * std.time.ns_per_ms,
        .interval_ns = 1 * std.time.ns_per_s,
        .url = try cli.parseUrl(url),
    };
    const result = try run(arena_state.allocator(), io, &cfg, null, null);

    group.await(io) catch {};
    server.deinit(io);

    try testing.expectEqual(@as(u32, 1), result.launched);
    try testing.expect(result.snapshot.counters.completed > 0);
    // Elapsed must track the 0.3s duration. Generous upper bound for slow CI;
    // the quantization regression would report >= 1.0s.
    try testing.expect(result.elapsed_s >= 0.29);
    try testing.expect(result.elapsed_s < 0.9);
}

test {
    std.testing.refAllDecls(@This());
}
