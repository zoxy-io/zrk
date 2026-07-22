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

/// Which consumers a progress callback is for. The dashboard redraws on the
/// (faster) `--refresh` cadence; `--timeseries` rows and `--plain` lines keep
/// the `--interval` stats window. A single wake can serve both.
pub const Tick = struct {
    frame: bool,
    row: bool,
};

/// Called on each progress wake with the merged fleet snapshot.
pub const ProgressFn = *const fn (
    context: ?*anyopaque,
    snapshot: *const stats.Snapshot,
    now_ns: i128,
    elapsed_s: f64,
    total_s: f64,
    tick: Tick,
) void;

/// Run one constant-throughput load test to completion. Blocks the
/// calling thread (worker connections run on executor threads); returns
/// after the configured duration with the final merged report.
///
/// `frame_interval_ns` is the dashboard redraw cadence (0 = follow
/// `cfg.interval_ns`); the caller passes `cfg.refresh_ns` only when a live
/// TUI is attached, so plain/JSON runs never wake faster than the stats
/// window.
pub fn run(
    arena: std.mem.Allocator,
    io: Io,
    cfg: *const cli.Config,
    frame_interval_ns: u64,
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

    // Publish the (expensive) live-histogram copy as often as the fastest
    // consumer wakes: the dashboard's `--refresh` when a live TUI is attached,
    // else the `--interval` stats window. This is what lets the latency bars
    // step with each redraw instead of only once per stats window — the panel
    // repaints every frame but the numbers behind it are only as fresh as the
    // last publish.
    const publish_ns = if (frame_interval_ns > 0) @min(frame_interval_ns, cfg.interval_ns) else cfg.interval_ns;
    var fleet = try stats.Fleet.init(arena, cfg.connections, publish_ns, cfg.url.isTls());
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
        .deadline_ns = cfg.deadline_ns,
        .deadline_abort = cfg.deadline_abort,
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
    // If anything below fails, the workers must be stopped and joined before
    // this frame unwinds: they hold pointers to `stop` (this stack) and to
    // fleet state that the deferred `fleet.deinit` (declared earlier, so it
    // runs after this) is about to free.
    errdefer {
        stop.store(true, .monotonic);
        group.cancel(io);
    }
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

    // Progress cadence: two independent deadlines share one loop — dashboard
    // frames every `frame_ns` and stats rows every `--interval` — sleeping to
    // whichever comes first, but never past `end`. The final (possibly
    // partial) window still gets a `row` callback, and the measured elapsed
    // time tracks the configured duration instead of rounding up to the next
    // boundary (which deflated Requests/sec whenever the duration wasn't a
    // multiple of --interval).
    const row_ns: i128 = @intCast(cfg.interval_ns);
    const frame_ns: i128 = if (frame_interval_ns > 0) @intCast(frame_interval_ns) else row_ns;
    var next_row: i128 = start.nanoseconds + row_ns;
    var next_frame: i128 = start.nanoseconds + frame_ns;
    while (true) {
        const before = Io.Timestamp.now(io, .awake);
        if (before.nanoseconds >= end.nanoseconds) break;
        const next_wake = @min(@min(next_frame, next_row), end.nanoseconds);
        if (next_wake > before.nanoseconds) {
            io.sleep(Io.Duration.fromNanoseconds(@intCast(next_wake - before.nanoseconds)), .awake) catch break;
        }

        const t = Io.Timestamp.now(io, .awake);
        // The wake at `end` flushes both consumers so the last partial window
        // is never dropped.
        const at_end = t.nanoseconds >= end.nanoseconds;
        const tick: Tick = .{
            .frame = at_end or t.nanoseconds >= next_frame,
            .row = at_end or t.nanoseconds >= next_row,
        };
        // A hair-early sleep return crosses no deadline: sleep again rather
        // than merging a snapshot nobody consumes.
        if (!tick.frame and !tick.row) continue;
        while (next_frame <= t.nanoseconds) next_frame += frame_ns;
        while (next_row <= t.nanoseconds) next_row += row_ns;

        fleet.readSnapshot(io, &snap);
        const elapsed_s: f64 = @as(f64, @floatFromInt(start.durationTo(t).nanoseconds)) / std.time.ns_per_s;
        if (progress) |callback| {
            callback(progress_context, &snap, t.nanoseconds, elapsed_s, total_s, tick);
        }
        if (at_end) break;
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
const zio = @import("zio");

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
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
    const result = try run(arena_state.allocator(), io, &cfg, 0, null, null);

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
