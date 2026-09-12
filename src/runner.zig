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
const h3conn = @import("h3conn.zig");
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
    /// The run stopped early because the caller raised `interrupt`. The report
    /// covers `elapsed_s`, not the configured duration — a consumer that gates
    /// on these numbers (an SLO check, a regression baseline) must not treat an
    /// interrupted run as a completed one.
    interrupted: bool = false,
    /// Throughput (req/s) over the run's *final* window — the last `--interval`
    /// or so, measured the same way a `--timeseries` row is.
    ///
    /// `snapshot.counters.completed / elapsed_s` is the whole-run average: the
    /// right number under constant load, and a misleading one under a ramp,
    /// where `-R100:1000` averages ~550 no matter what the target sustained at
    /// the top. This is the tail — what the target was actually serving when
    /// the run ended. Falls back to the whole-run average for a run too short
    /// to hold a window.
    end_rate: f64 = 0,
    /// Bytes/second over that same window, so the two stay proportional: a
    /// consumer dividing one by the other gets bytes-per-request either way.
    end_bytes_per_sec: f64 = 0,
    /// Wall-clock length of the window `end_rate` was measured over. Equal to
    /// `elapsed_s` when the run was too short for a window of its own.
    end_window_s: f64 = 0,
    /// Elapsed time at which that window *closed*, which is not `elapsed_s`:
    /// the window ends at the last progress row, while `elapsed_s` is measured
    /// after the fleet is joined. An interrupt widens that gap to most of an
    /// `--interval` (a signal raises no row of its own), and a consumer placing
    /// the window on a ramp's schedule has to know where it actually sat.
    end_window_at_s: f64 = 0,
};

/// One published counter reading at a progress-row boundary. Kept so `run` can
/// difference the last window out of the run (see `Report.end_rate`).
const RowSample = struct { ns: i128, completed: u64, bytes: u64 };

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

/// How often the progress loop rechecks `interrupt` while otherwise idle. The
/// loop already sleeps only to its next frame/row deadline, which with a long
/// `--interval` can be seconds away; capping the sleep bounds how long a
/// Ctrl-C sits unnoticed. The extra wakes are nearly free — one timestamp and
/// two comparisons, then straight back to sleep, since no tick deadline passed.
const interrupt_poll_ns: i128 = 100 * std.time.ns_per_ms;

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
    /// Raise to stop the run early and return what was measured so far, with
    /// `Report.interrupted` set. Preferred over canceling the task running
    /// `run`: cancellation discards the measurement, this keeps it.
    interrupt: ?*const std.atomic.Value(bool),
) !Report {
    const request = try httpmod.buildRequest(arena, cfg);
    // Built once for the whole run and shared by every connection, which is
    // what `Encoder.Mode.static_only` guarantees is legal: the block depends on
    // no encoder state, so replaying the same octets on every stream of every
    // connection is byte-identical to encoding it each time.
    const request_block = if (cfg.http2) try httpmod.buildRequestBlock(arena, cfg) else &[_]u8{};
    // The HTTP/3 half of the same trade: one QPACK HEADERS frame (and a DATA
    // frame when there is a body), built once and replayed byte-identically on
    // every stream of every connection. See `h3conn.buildRequest`.
    const h3_request = if (cfg.http3) try h3conn.buildRequest(arena, cfg) else &[_]u8{};
    const address = try resolveAddress(io, cfg.url.host, cfg.url.port);

    // Load the system trust store once (shared, read-mostly) for HTTPS
    // with verification enabled.
    //
    // `--http3` included: it terminates TLS through `quic_tls.zig` rather than
    // zssl, but the trust decision is the same one — `tls.Trust` serves both
    // engines — so the store it reads has to be loaded for both.
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
    // `enable_tls` is zssl's per-connection block, which the HTTP/3 path does
    // not use: QUIC's handshake state lives inside `h3conn.State` instead.
    var fleet = try stats.Fleet.init(
        arena,
        cfg.connections,
        publish_ns,
        cfg.url.isTls() and !cfg.http3,
        cfg.http3,
    );
    defer fleet.deinit();

    // Merging the fleet's per-connection histograms is O(connections) and does
    // not yield, so it runs on its own thread instead of on this one — this
    // thread is executor 0, and stalling it stalls the connections it hosts.
    // Declared after `fleet` so it is joined before those histograms are freed.
    var sweeper = try stats.Sweeper.init(arena, &fleet, io);
    defer sweeper.deinit();
    sweeper.start();

    var stop = std.atomic.Value(bool).init(false);

    // Per-connection send schedule: no schedule at all in --closed mode, else
    // a constant spacing or a linear ramp from `rate` to `rate_end`, split
    // evenly across connections.
    const duration_s: f64 = @as(f64, @floatFromInt(cfg.duration_ns)) / std.time.ns_per_s;
    const schedule: pace.Schedule = if (cfg.closed)
        .closed
    else if (cfg.rate_end) |end_rate|
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
        .request_block = request_block,
        .body = cfg.body,
        .http2 = cfg.http2,
        .http3 = cfg.http3,
        .h3_request = h3_request,
        .streams = cfg.streams,
        .method = .of(cfg.method),
        .is_tls = cfg.url.isTls(),
        .insecure = cfg.insecure,
        .schedule = schedule,
        .timeout_ns = cfg.timeout_ns,
        .deadline_ns = cfg.deadline_ns,
        .deadline_abort = cfg.deadline_abort,
        .record_timeouts = cfg.record_timeouts,
        .disable_keepalive = cfg.disable_keepalive,
        .end = end,
        .stop = &stop,
        .allocator = arena,
        .ca_store = ca_ptr,
        // histogram/counters/publish/tls_state are filled in by buildParams.
        .histogram = undefined,
        .counters = undefined,
    });

    // Launch each connection as a zio coroutine. `concurrent` (unlike
    // `async`) guarantees real parallelism across executor threads.
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
    var interrupted = false;
    // Row-boundary counter readings, for the tail window computed after the
    // loop. Four is enough to always hold one sample a full `--interval` back:
    // rows land on the interval cadence, and only the last one (the flush at
    // `end`) can sit a fraction of an interval after its predecessor.
    var rows: [4]RowSample = undefined;
    var row_count: usize = 0;
    while (true) {
        const before = Io.Timestamp.now(io, .awake);
        if (before.nanoseconds >= end.nanoseconds) break;
        var next_wake = @min(@min(next_frame, next_row), end.nanoseconds);
        // Bound the sleep so the interrupt check below runs on a fixed cadence
        // rather than only at the next frame/row deadline.
        if (interrupt != null) next_wake = @min(next_wake, before.nanoseconds + interrupt_poll_ns);
        if (next_wake > before.nanoseconds) {
            // Propagate rather than `catch break`. The only failure here is
            // cancellation, and breaking would run the normal completion path:
            // the caller would get a Report that looks like a finished run but
            // covers a fraction of `--duration`, with nothing marking it short.
            // A CI gate (`--slo-p99`, `--max-error-rate`) would then pass on a
            // sample that was never collected. Unreachable from the CLI, which
            // never cancels this task, but `run` is the embeddable entry point
            // and an embedder's coroutine can be canceled — and when it is, the
            // caller asked to stop and should learn the run did not complete.
            // The errdefer above stops and joins the connections on the way out.
            try io.sleep(Io.Duration.fromNanoseconds(@intCast(next_wake - before.nanoseconds)), .awake);
        }

        const t = Io.Timestamp.now(io, .awake);
        // The wake at `end` flushes both consumers so the last partial window
        // is never dropped.
        const at_end = t.nanoseconds >= end.nanoseconds;
        // A raised interrupt ends the run here rather than at the top of the
        // next pass, so it takes the same last-frame flush as `at_end` does.
        // Stopping is not instant — the fleet still has to be joined — and
        // without that frame a live dashboard sits frozen on its last
        // pre-interrupt paint, giving no sign the signal even arrived.
        if (interrupt) |flag| if (flag.load(.monotonic)) {
            interrupted = true;
        };
        const tick: Tick = .{
            .frame = at_end or interrupted or t.nanoseconds >= next_frame,
            .row = at_end or t.nanoseconds >= next_row,
        };
        // A hair-early sleep return crosses no deadline: sleep again rather
        // than merging a snapshot nobody consumes.
        if (!tick.frame and !tick.row) continue;
        while (next_frame <= t.nanoseconds) next_frame += frame_ns;
        while (next_row <= t.nanoseconds) next_row += row_ns;

        sweeper.snapshot(&snap);
        const elapsed_s: f64 = @as(f64, @floatFromInt(start.durationTo(t).nanoseconds)) / std.time.ns_per_s;
        if (progress) |callback| {
            callback(progress_context, &snap, t.nanoseconds, elapsed_s, total_s, tick);
        }
        if (tick.row) {
            rows[row_count % rows.len] = .{
                .ns = t.nanoseconds,
                .completed = snap.counters.completed,
                .bytes = snap.counters.bytes,
            };
            row_count += 1;
        }
        if (at_end or interrupted) break;
    }

    // Signal stop, then cancel: connections idling between paced sends
    // observe `stop`, while any blocked on a stalled server read are
    // interrupted by the cancellation so shutdown never hangs.
    stop.store(true, .monotonic);
    group.cancel(io);

    const elapsed = start.durationTo(Io.Timestamp.now(io, .awake));
    const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed.nanoseconds)) / std.time.ns_per_s;
    fleet.readFinal(&snap);

    const tail = tailWindow(rows[0..], row_count, cfg.interval_ns);
    return .{
        .snapshot = snap,
        .elapsed_s = elapsed_s,
        .launched = launched,
        .interrupted = interrupted,
        .end_rate = if (tail) |t| t.rate else perSecond(snap.counters.completed, elapsed_s),
        .end_bytes_per_sec = if (tail) |t| t.bytes_per_sec else perSecond(snap.counters.bytes, elapsed_s),
        .end_window_s = if (tail) |t| t.seconds else elapsed_s,
        .end_window_at_s = if (tail) |t|
            @as(f64, @floatFromInt(t.end_ns - start.nanoseconds)) / std.time.ns_per_s
        else
            elapsed_s,
    };
}

fn perSecond(count: u64, seconds: f64) f64 {
    if (seconds <= 0) return 0;
    return @as(f64, @floatFromInt(count)) / seconds;
}

/// Difference the run's last window out of the row-boundary ring: the earlier
/// sample whose distance to the final one is closest to a whole `--interval`,
/// against that final one. Null when fewer than two rows landed (a run shorter
/// than a single window).
///
/// Closest-to-an-interval rather than the plainer "newest sample at least an
/// interval back", because neither end of the run lands on the grid exactly.
/// Rows fire a wake-latency after their deadline while the end-of-run flush
/// fires at `end` on the dot, so the last gap is a hair *under* an interval
/// about as often as it is over — an at-least rule would reach a whole extra
/// interval back on a coin flip, and the reported window would flip between one
/// and two intervals across identical runs. It also declines to measure the
/// sliver left by a duration that isn't a whole number of intervals (`-d 10.05s
/// --interval 1s` ends with a 50ms row), preferring the 1.05s window over it.
///
/// Both ends come from *published* snapshots on purpose. A connection publishes
/// its counters on its own cadence, so any snapshot lags reality by up to one
/// publish interval; differencing two of them cancels that lag, while
/// differencing the last row against the post-join live counters would charge
/// every connection's unpublished backlog to this one window and overstate it.
/// It also makes the number identical to the last `--timeseries` row whenever
/// that row covers a full interval.
fn tailWindow(ring: []const RowSample, count: usize, interval_ns: u64) ?struct {
    rate: f64,
    bytes_per_sec: f64,
    seconds: f64,
    /// Timestamp the window closed on, in the ring's own clock.
    end_ns: i128,
} {
    if (count < 2) return null;
    const last = ring[(count - 1) % ring.len];
    const want: i128 = @intCast(interval_ns);

    var base: ?RowSample = null;
    var best_miss: i128 = 0;
    var i = count -| ring.len;
    while (i + 1 < count) : (i += 1) {
        const s = ring[i % ring.len];
        const span = last.ns - s.ns;
        if (span <= 0) continue;
        const miss = @max(span - want, want - span);
        if (base == null or miss < best_miss) {
            base = s;
            best_miss = miss;
        }
    }
    const b = base orelse return null;
    const seconds = @as(f64, @floatFromInt(last.ns - b.ns)) / std.time.ns_per_s;
    return .{
        .rate = perSecond(last.completed -| b.completed, seconds),
        .bytes_per_sec = perSecond(last.bytes -| b.bytes, seconds),
        .seconds = seconds,
        .end_ns = last.ns,
    };
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

test "tailWindow measures the last full interval, not the last partial row" {
    const s_ns: i128 = std.time.ns_per_s;
    const interval: u64 = std.time.ns_per_s;

    // Rows on a 1s grid, then the end-of-run flush 0.2s past the last one — the
    // shape of any duration that isn't a whole number of intervals. That sliver
    // holds 200 requests, so measuring it alone would claim 1000 req/s off a
    // fifth of a second; the window has to reach back past the 4s row to the 3s
    // one, where the true 800-over-1.2s shows.
    var ring: [4]RowSample = .{
        .{ .ns = 2 * s_ns, .completed = 2000, .bytes = 80000 },
        .{ .ns = 3 * s_ns, .completed = 3000, .bytes = 120000 },
        .{ .ns = 4 * s_ns, .completed = 3600, .bytes = 144000 },
        .{ .ns = 4 * s_ns + s_ns / 5, .completed = 3800, .bytes = 152000 },
    };
    const partial = tailWindow(&ring, 4, interval).?;
    try testing.expectApproxEqAbs(@as(f64, 1.2), partial.seconds, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 800.0 / 1.2), partial.rate, 1e-6);

    // Rows landing exactly on the grid: one interval back is the whole window,
    // and no further — reaching back two would blend the previous second in.
    ring[3] = .{ .ns = 5 * s_ns, .completed = 4500, .bytes = 180000 };
    const aligned = tailWindow(&ring, 4, interval).?;
    try testing.expectApproxEqAbs(@as(f64, 1.0), aligned.seconds, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 900), aligned.rate, 1e-6);

    // Rows fire a wake-latency late, the end-of-run flush fires on the dot, so
    // the last gap comes in a hair *under* an interval as often as over. Both
    // sides of that coin flip must report the same one-interval window.
    ring = .{
        .{ .ns = 1 * s_ns + 200_000, .completed = 1000, .bytes = 40000 },
        .{ .ns = 2 * s_ns + 300_000, .completed = 2000, .bytes = 80000 },
        .{ .ns = 3 * s_ns + 400_000, .completed = 3000, .bytes = 120000 },
        .{ .ns = 4 * s_ns, .completed = 3900, .bytes = 156000 },
    };
    const jittered = tailWindow(&ring, 4, interval).?;
    try testing.expectApproxEqAbs(@as(f64, 0.9996), jittered.seconds, 1e-6);
    try testing.expect(jittered.rate > 890 and jittered.rate < 910);

    // A duration that isn't a whole number of intervals ends on a sliver:
    // `-d 4.05s --interval 1s` flushes 50ms after the 4s row. 50ms of traffic
    // is not a throughput measurement, so the window before it wins.
    ring = .{
        .{ .ns = 1 * s_ns, .completed = 1000, .bytes = 40000 },
        .{ .ns = 2 * s_ns, .completed = 2000, .bytes = 80000 },
        .{ .ns = 3 * s_ns, .completed = 3000, .bytes = 120000 },
        .{ .ns = 4 * s_ns + s_ns / 20, .completed = 4050, .bytes = 162000 },
    };
    const sliver = tailWindow(&ring, 4, interval).?;
    try testing.expectApproxEqAbs(@as(f64, 1.05), sliver.seconds, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 1050.0 / 1.05), sliver.rate, 1e-6);

    // A run too short to hold two rows has no window of its own; the caller
    // falls back to the whole-run average.
    try testing.expect(tailWindow(&ring, 1, interval) == null);
    try testing.expect(tailWindow(&ring, 0, interval) == null);
}

test "tailWindow reads a ramp's tail, not its average" {
    // 4s of a ramp sampled once a second: 100, 300, 500 and 700 requests per
    // second. The whole-run average (1600/4 = 400) describes no second of it;
    // the tail is the 700 the ramp actually reached.
    const s_ns: i128 = std.time.ns_per_s;
    const ring: [4]RowSample = .{
        .{ .ns = 1 * s_ns, .completed = 100, .bytes = 4000 },
        .{ .ns = 2 * s_ns, .completed = 400, .bytes = 16000 },
        .{ .ns = 3 * s_ns, .completed = 900, .bytes = 36000 },
        .{ .ns = 4 * s_ns, .completed = 1600, .bytes = 64000 },
    };
    const tail = tailWindow(&ring, 4, std.time.ns_per_s).?;
    try testing.expectApproxEqAbs(@as(f64, 700), tail.rate, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 1.0), tail.seconds, 1e-9);
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
    const result = try run(arena_state.allocator(), io, &cfg, 0, null, null, null);

    group.await(io) catch {};
    server.deinit(io);

    try testing.expectEqual(@as(u32, 1), result.launched);
    try testing.expect(result.snapshot.counters.completed > 0);
    // Elapsed must track the 0.3s duration. Generous upper bound for slow CI;
    // the quantization regression would report >= 1.0s.
    try testing.expect(result.elapsed_s >= 0.29);
    try testing.expect(result.elapsed_s < 0.9);
    // Shorter than one --interval, so there is no tail window to difference:
    // `end_rate` falls back to the whole-run average rather than reporting 0.
    try testing.expectApproxEqAbs(result.end_window_s, result.elapsed_s, 1e-9);
    try testing.expectApproxEqAbs(
        @as(f64, @floatFromInt(result.snapshot.counters.completed)) / result.elapsed_s,
        result.end_rate,
        1e-6,
    );
}

test "an interrupted run keeps its measurement and says it was cut short" {
    var rt = try zio.Runtime.init(testing.allocator, .{ .executors = .exact(2) });
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    var serve_group: Io.Group = .init;
    serve_group.async(io, testServe, .{ io, &server });
    const port = server.socket.address.getPort();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    var cfg: cli.Config = .{
        .connections = 1,
        .rate = 500,
        .duration_ns = 60 * std.time.ns_per_s,
        // Far longer than the run will last: the interrupt must not wait for a
        // stats window to come around.
        .interval_ns = 30 * std.time.ns_per_s,
        .url = try cli.parseUrl(url),
    };

    var interrupt = std.atomic.Value(bool).init(false);
    var raiser: Io.Group = .init;
    raiser.async(io, raiseAfter, .{ io, &interrupt, 200 * std.time.ns_per_ms });

    const result = try run(arena_state.allocator(), io, &cfg, 0, null, null, &interrupt);

    raiser.cancel(io);
    serve_group.cancel(io);
    server.deinit(io);

    try testing.expect(result.interrupted);
    // Stopped near the interrupt, not at the 60s duration or the 30s window.
    try testing.expect(result.elapsed_s >= 0.19);
    try testing.expect(result.elapsed_s < 5.0);
    // The whole point: the partial run's measurement survives.
    try testing.expect(result.snapshot.counters.completed > 0);
}

fn raiseAfter(io: Io, flag: *std.atomic.Value(bool), delay_ns: u64) void {
    io.sleep(Io.Duration.fromNanoseconds(delay_ns), .awake) catch return;
    flag.store(true, .monotonic);
}

/// Runs a load test to completion and stores whatever `run` returned, so a
/// canceled run's outcome can be inspected from outside the coroutine.
fn runCapturing(io: Io, gpa: std.mem.Allocator, cfg: *const cli.Config, out: *?anyerror!Report) void {
    out.* = run(gpa, io, cfg, 0, null, null, null);
}

test "a canceled run propagates instead of reporting a truncated success" {
    // `run` is the embeddable entry point, so an embedder can cancel the
    // coroutine it runs in. Swallowing that (the old `catch break`) returned a
    // Report covering a fraction of --duration with nothing marking it short,
    // which a CI gate would then happily evaluate.
    var rt = try zio.Runtime.init(testing.allocator, .{ .executors = .exact(2) });
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    var serve_group: Io.Group = .init;
    serve_group.async(io, testServe, .{ io, &server });
    const port = server.socket.address.getPort();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    var cfg: cli.Config = .{
        .connections = 1,
        .rate = 100,
        // Long enough that cancellation lands mid-sleep, well before `end`.
        .duration_ns = 60 * std.time.ns_per_s,
        .interval_ns = 1 * std.time.ns_per_s,
        .url = try cli.parseUrl(url),
    };

    var outcome: ?anyerror!Report = null;
    var run_group: Io.Group = .init;
    try run_group.concurrent(io, runCapturing, .{ io, arena_state.allocator(), &cfg, &outcome });

    // Let it reach the progress loop's sleep, then cancel out from under it.
    io.sleep(Io.Duration.fromNanoseconds(50 * std.time.ns_per_ms), .awake) catch {};
    run_group.cancel(io); // waits for the task to unwind

    serve_group.cancel(io);
    server.deinit(io);

    // Must be the error, not a short-but-successful Report.
    try testing.expectError(error.Canceled, outcome.?);
}

test {
    std.testing.refAllDecls(@This());
}
