//! A single load-generating connection: connect, then repeatedly pace-and-send
//! one request at a time, recording coordinated-omission-corrected latency.
//!
//! One request is in flight per connection at a time (like wrk/wrk2). Achieving
//! a high total rate is a matter of running many connections; each connection
//! paces its own sends to a fixed schedule so that, when the server falls
//! behind, backlogged requests still accrue latency against their *intended*
//! send time rather than their actual send time.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const hdr = @import("hdr.zig");
const httpmod = @import("http.zig");
const tlsmod = @import("tls.zig");
const pace = @import("pace.zig");
const StatusClass = httpmod.StatusClass;

/// Per-connection counters. Aggregated across connections/threads for reporting.
pub const Counters = struct {
    /// Requests that received a complete response.
    completed: u64 = 0,
    /// Total response bytes read off the wire.
    bytes: u64 = 0,
    /// Responses whose status was not 2xx or 3xx (wrk's "Non-2xx/3xx").
    status_errors: u64 = 0,
    /// Failures establishing a connection.
    connect_errors: u64 = 0,
    /// Failures while writing a request.
    write_errors: u64 = 0,
    /// Failures while reading/parsing a response.
    read_errors: u64 = 0,
    /// Requests abandoned because the response exceeded `--timeout`.
    timeouts: u64 = 0,
    /// Completed responses bucketed by status class, indexed by status/100
    /// (so [1]=1xx .. [5]=5xx; index 0 is unused). Sums to `completed`.
    status_class: [6]u64 = [_]u64{0} ** 6,

    pub fn add(self: *Counters, other: Counters) void {
        self.completed += other.completed;
        self.bytes += other.bytes;
        self.status_errors += other.status_errors;
        self.connect_errors += other.connect_errors;
        self.write_errors += other.write_errors;
        self.read_errors += other.read_errors;
        self.timeouts += other.timeouts;
        for (&self.status_class, other.status_class) |*d, s| d.* += s;
    }

    /// Record a completed response's status: bump its class bucket and, for
    /// non-2xx/3xx, the `status_errors` tally (wrk's "Non-2xx/3xx").
    pub fn recordStatus(self: *Counters, status: u16) void {
        self.status_class[@min(status / 100, 5)] += 1;
        switch (StatusClass.of(status)) {
            .success, .redirect => {},
            else => self.status_errors += 1,
        }
    }

    /// Total socket-level failures (connect + read + write + timeout).
    pub fn socketErrors(self: Counters) u64 {
        return self.connect_errors + self.read_errors + self.write_errors + self.timeouts;
    }
};

/// A double-buffer for exposing a connection's live latency/counters to the
/// dashboard thread without racing the hot path. The connection thread copies
/// its live state here at most once per publish interval, under `mutex`; the
/// dashboard reads it under the same lock. Cheap because it happens ~once/sec.
pub const Publish = struct {
    mutex: Io.Mutex = .init,
    /// Snapshot histogram (must share the live histogram's layout).
    hist: *hdr.Histogram,
    counters: Counters = .{},
    interval_ns: u64,
    /// Monotonic-ns timestamp of the next scheduled publish (0 = publish asap).
    next_ns: i128 = 0,
};

/// Everything a connection fiber needs. `histogram` and `counters` are owned by
/// the connection's thread and must not be shared across threads without
/// external synchronization (that is what `publish` is for).
pub const Params = struct {
    io: Io,
    address: net.IpAddress,
    host: []const u8,
    request: []const u8,
    /// Framing classification of the request method (HEAD responses have no
    /// body); see `http.RequestMethod`.
    method: httpmod.RequestMethod = .other,
    is_tls: bool,
    insecure: bool,
    /// Send schedule for THIS connection (constant spacing or a linear ramp).
    schedule: pace.Schedule,
    /// Per-request response timeout (0 = no timeout).
    timeout_ns: u64,
    /// Record a coordinated-omission-corrected latency sample when a request
    /// times out, instead of dropping it (which would truncate the tail).
    record_timeouts: bool = true,
    /// Monotonic timestamp at which the connection should stop sending.
    end: Io.Timestamp,
    /// Set to true (by the coordinator) to request an early graceful stop.
    stop: *std.atomic.Value(bool),
    histogram: *hdr.Histogram,
    counters: *Counters,
    /// Optional live-snapshot channel for the dashboard.
    publish: ?*Publish = null,
    /// Allocator for TLS certificate verification (borrowed).
    allocator: std.mem.Allocator = undefined,
    /// Pinned per-connection TLS buffers/client; required when `is_tls`.
    tls_state: ?*tlsmod.State = null,
    /// Shared trust store; null means verification is skipped.
    ca_store: ?*tlsmod.CaStore = null,
};

const read_buffer_size = 16 * 1024;
const write_buffer_size = 8 * 1024;

/// Run one connection until `end` (or `stop`). Never returns an error: all
/// failures are folded into `counters` and recovered from by reconnecting.
pub fn run(p: *Params) void {
    const io = p.io;

    var read_buf: [read_buffer_size]u8 = undefined;
    var write_buf: [write_buffer_size]u8 = undefined;

    // Each connection keeps its own schedule, anchored when it first connects;
    // `send_index` is the coordinated-omission-correct request counter that
    // drives it, persisting across reconnects so a stall is caught up (not reset).
    var anchor: ?Io.Timestamp = null;
    var send_index: u64 = 0;

    while (!p.stop.load(.monotonic) and now(io).nanoseconds < p.end.nanoseconds) {
        // (Re)connect.
        var stream = connect(io, p.address) catch {
            noteError(p, .connect);
            // Back off briefly so a refused port doesn't spin the CPU.
            io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
            continue;
        };

        // Establish the transport (plaintext, or a TLS session over the stream)
        // and obtain the reader/writer the HTTP layer talks to.
        var app_reader: *Io.Reader = undefined;
        var app_writer: *Io.Writer = undefined;
        var plain_reader: net.Stream.Reader = undefined;
        var plain_writer: net.Stream.Writer = undefined;
        if (p.is_tls) {
            const ts = p.tls_state.?;
            ts.handshake(io, p.allocator, stream, p.host, p.insecure, p.ca_store) catch {
                // A failed handshake counts as a connect error; try again later.
                noteError(p, .connect);
                stream.close(io);
                io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
                continue;
            };
            app_reader = ts.reader();
            app_writer = ts.writer();
        } else {
            plain_reader = stream.reader(io, &read_buf);
            plain_writer = stream.writer(io, &write_buf);
            app_reader = &plain_reader.interface;
            app_writer = &plain_writer.interface;
        }

        // The response timeout is enforced by one watchdog task per
        // *connection*, armed/disarmed with an atomic store per request.
        // The previous design raced every request against a freshly
        // spawned timer task and canceled the loser; on the Threaded
        // backend that per-request spawn/cancel pair costs milliseconds
        // (macOS especially), capping every connection near 500 req/s no
        // matter how fast the target answers.
        var watchdog: Watchdog = .{ .io = io, .stream = &stream, .timeout_ns = p.timeout_ns };
        var watchdog_group: Io.Group = .init;
        var watchdog_active = false;
        if (p.timeout_ns != 0) {
            if (watchdog_group.concurrent(io, Watchdog.watch, .{&watchdog})) |_| {
                watchdog_active = true;
            } else |_| {
                // No task available: requests run untimed, as before.
            }
        }
        var conn_open = true;
        // Teardown order matters: cancel joins the watchdog before the
        // stream closes, so the watchdog can never shut down a closed
        // (and possibly kernel-reused) fd.
        defer {
            if (watchdog_active) watchdog_group.cancel(io);
            stream.close(io);
        }

        // Serve requests on this connection until it must close or the test ends.
        while (conn_open and !p.stop.load(.monotonic)) {
            const t = now(io);
            if (t.nanoseconds >= p.end.nanoseconds) return;

            // Anchor the schedule on the first request; each send's intended
            // time is a closed-form function of its index (constant or ramp).
            if (anchor == null) anchor = t;
            const offset = p.schedule.offsetNs(send_index);
            const scheduled = anchor.?.addDuration(Io.Duration.fromNanoseconds(@intCast(offset)));

            // Pace: if we're ahead of schedule, wait; if behind, fire immediately.
            if (scheduled.nanoseconds > t.nanoseconds) {
                const wait = Io.Duration.fromNanoseconds(scheduled.nanoseconds - t.nanoseconds);
                io.sleep(wait, .awake) catch return;
            }
            send_index += 1;

            // Send the request and read its response inline on this thread;
            // the watchdog turns a stalled read into a socket shutdown, which
            // surfaces here as a read failure that `fired` reclassifies.
            if (watchdog_active) watchdog.arm(now(io));
            const work = performWork(p, app_reader, app_writer);
            if (watchdog_active) watchdog.disarm();
            const timed_out = watchdog_active and watchdog.fired.load(.acquire);

            switch (work) {
                .write_failed => {
                    if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .write);
                    conn_open = false;
                },
                .read_failed => {
                    if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .read);
                    conn_open = false;
                },
                .ok => |resp| {
                    // Coordinated-omission-corrected latency: measured from the
                    // time the request *should* have been sent, not when it
                    // actually went out.
                    const done = now(io);
                    const latency_ns = done.nanoseconds - scheduled.nanoseconds;
                    const latency_us: u64 = if (latency_ns > 0) @intCast(@divTrunc(latency_ns, std.time.ns_per_us)) else 0;
                    p.histogram.record(latency_us);

                    p.counters.completed += 1;
                    p.counters.bytes += resp.bytes;
                    p.counters.recordStatus(resp.status);

                    maybePublish(p, done.nanoseconds);

                    // A fired watchdog shut the socket down even though the
                    // response won the race; the response still counts, but
                    // the connection is dead.
                    if (timed_out or !resp.keep_alive) {
                        conn_open = false;
                    }
                },
            }
        }
    }
}

/// Result of one send+receive attempt.
const WorkResult = union(enum) {
    ok: httpmod.Response,
    write_failed,
    read_failed,
};

/// One per connection: watches the in-flight request's deadline and, on
/// expiry, shuts the stream down so the blocked read unblocks with an error
/// the request loop reclassifies as a timeout (the wrk approach, adapted to
/// blocking threads). Arming costs one atomic store on the request path —
/// no per-request task spawns.
const Watchdog = struct {
    io: Io,
    stream: *net.Stream,
    timeout_ns: u64,
    /// Monotonic-ns deadline of the in-flight request; 0 = idle. i64 (not
    /// the timestamp's native i128) because 128-bit atomics don't exist on
    /// x86_64; saturating i64 nanoseconds still spans ~292 years of uptime.
    deadline_ns: std.atomic.Value(i64) = .init(0),
    /// True once the stream has been shut down; read by the request loop
    /// to tell a timeout from a genuine transport failure.
    fired: std.atomic.Value(bool) = .init(false),

    fn arm(w: *Watchdog, t: Io.Timestamp) void {
        const deadline = std.math.lossyCast(i64, t.nanoseconds + @as(i128, w.timeout_ns));
        w.deadline_ns.store(deadline, .release);
    }

    fn disarm(w: *Watchdog) void {
        w.deadline_ns.store(0, .release);
    }

    /// Runs until it fires or is canceled at connection teardown. While a
    /// request is in flight it sleeps exactly to that deadline (successive
    /// deadlines only move forward, so it can never oversleep a later one);
    /// while idle it ticks at half the timeout, so a request armed mid-tick
    /// is caught at most 1.5x the timeout late. Deliberate slack: this
    /// guards against stalls, it is not a precision timer.
    fn watch(w: *Watchdog) void {
        const io = w.io;
        while (true) {
            const deadline = w.deadline_ns.load(.acquire);
            const t = std.math.lossyCast(i64, now(io).nanoseconds);
            if (deadline != 0 and t >= deadline) {
                // Fire only if this exact deadline is still armed: the request
                // may have completed (disarm, possibly followed by the next
                // arm) since the load above, and shutting the socket down then
                // would misclassify the *next* request as a timeout. Deadlines
                // strictly increase, so there is no ABA to worry about.
                if (w.deadline_ns.cmpxchgStrong(deadline, 0, .acq_rel, .acquire) == null) {
                    w.fired.store(true, .release);
                    w.stream.shutdown(io, .both) catch {};
                    return;
                }
                continue; // Deadline moved: re-evaluate against the new one.
            }
            const sleep_ns: i64 = if (deadline != 0)
                deadline - t
            else
                @intCast(@max(w.timeout_ns / 2, std.time.ns_per_ms));
            io.sleep(Io.Duration.fromNanoseconds(@intCast(sleep_ns)), .awake) catch return;
        }
    }
};

/// Send the fixed request and parse one response; touches only the
/// transport, never the shared counters.
fn performWork(p: *Params, app_reader: *Io.Reader, app_writer: *Io.Writer) WorkResult {
    app_writer.writeAll(p.request) catch return .write_failed;
    app_writer.flush() catch return .write_failed;
    // For TLS the app writer only encrypts into the socket writer's buffer; the
    // underlying stream writer must be flushed to actually send the ciphertext.
    if (p.is_tls) p.tls_state.?.swriter.interface.flush() catch return .write_failed;
    const resp = httpmod.parseResponse(app_reader, p.method) catch return .read_failed;
    return .{ .ok = resp };
}

fn now(io: Io) Io.Timestamp {
    return Io.Timestamp.now(io, .awake);
}

/// Record a socket error, unless we are shutting down — errors caused by
/// cancelling in-flight I/O at end-of-test are artifacts, not real failures.
/// Publishes so the live dashboard sees error-only periods (a total outage
/// produces no successful responses to publish through).
fn noteError(p: *Params, kind: enum { connect, write, read }) void {
    if (p.stop.load(.monotonic)) return;
    switch (kind) {
        .connect => p.counters.connect_errors += 1,
        .write => p.counters.write_errors += 1,
        .read => p.counters.read_errors += 1,
    }
    maybePublish(p, now(p.io).nanoseconds);
}

/// A timed-out request (the watchdog shut the socket down): count it and, unless
/// `--no-record-timeouts` is set, log a coordinated-omission-corrected latency
/// sample measured from the scheduled send time, so the tail reflects the stall
/// instead of dropping the worst samples. Skipped during shutdown, where a
/// timeout is a teardown artifact rather than a real failure.
fn noteTimeout(p: *Params, io: Io, scheduled: Io.Timestamp) void {
    if (p.stop.load(.monotonic)) return;
    p.counters.timeouts += 1;
    const done = now(io);
    if (p.record_timeouts) {
        const latency_ns = done.nanoseconds - scheduled.nanoseconds;
        const latency_us: u64 = if (latency_ns > 0) @intCast(@divTrunc(latency_ns, std.time.ns_per_us)) else 0;
        p.histogram.record(latency_us);
    }
    // Publish so a fully stalled target still surfaces on the dashboard.
    maybePublish(p, done.nanoseconds);
}

/// Publish a snapshot of this connection's live state for the dashboard, but at
/// most once per publish interval so the hot path stays essentially lock-free.
fn maybePublish(p: *Params, now_ns: i128) void {
    const pub_ptr = p.publish orelse return;
    if (now_ns < pub_ptr.next_ns) return;
    pub_ptr.mutex.lockUncancelable(p.io);
    defer pub_ptr.mutex.unlock(p.io);
    p.histogram.copyInto(pub_ptr.hist);
    pub_ptr.counters = p.counters.*;
    pub_ptr.next_ns = now_ns + @as(i128, @intCast(pub_ptr.interval_ns));
}

fn connect(io: Io, address: net.IpAddress) !net.Stream {
    // NOTE: connect-with-timeout is not implemented by the std Io backend in
    // this Zig version (it panics), so the connect itself uses the OS default.
    // The response timeout is enforced per-request by the `Watchdog`.
    return address.connect(io, .{ .mode = .stream });
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// A tiny keep-alive HTTP server used to exercise the real client path. Accepts
/// a single connection (the client holds one keep-alive connection for the whole
/// test) and answers every request with a fixed 200 response until the client
/// closes, at which point it returns.
fn testServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    serveConn(io, &stream);
    stream.close(io);
}

/// Consume one request's header lines through the terminating blank line (the
/// test client sends no bodies). Errors when the peer closes the connection.
fn discardRequestHead(r: *Io.Reader) !void {
    while (true) {
        const line = try r.takeDelimiterInclusive('\n');
        if (line.len <= 2) return; // "\r\n" or "\n": end of headers
    }
}

fn serveConn(io: Io, stream: *net.Stream) void {
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    // One response per request until the client closes the connection.
    while (true) {
        discardRequestHead(&r.interface) catch return;
        w.interface.writeAll(response) catch return;
        w.interface.flush() catch return;
    }
}

test "run drives keep-alive requests against a local server" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bind to an ephemeral port on loopback.
    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, testServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(200));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } }, // ~500 req/s
        .timeout_ns = 0,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    // The client closed its connection when `run` returned, so the server fiber
    // has finished; join it, then release the listening socket.
    group.await(io) catch {};
    server.deinit(io);

    const response_len: u64 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".len;
    try testing.expect(counters.completed > 0);
    try testing.expectEqual(@as(u64, 0), counters.status_errors);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.write_errors);
    try testing.expectEqual(counters.completed, histogram.count());
    // Every response is fully consumed and counted (headers + body).
    try testing.expectEqual(counters.completed * response_len, counters.bytes);
}

/// Serves HEAD-style responses: headers advertising a Content-Length that has
/// no body following it, as RFC 9112 §6.3 prescribes for HEAD.
fn headServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
    // One response per request until the client closes the connection.
    while (true) {
        discardRequestHead(&r.interface) catch return;
        w.interface.writeAll(response) catch return;
        w.interface.flush() catch return;
    }
}

test "run keeps HEAD responses framed despite Content-Length" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, headServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(200));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .method = .head,
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        // Short response timeout so a framing regression fails fast (as
        // timeouts) instead of hanging the test on a body that never comes.
        .timeout_ns = 100 * std.time.ns_per_ms,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Without HEAD awareness the parser would wait for 1234 body bytes that
    // never arrive: zero completions, all timeouts. With it, the keep-alive
    // connection serves many requests.
    try testing.expect(counters.completed > 1);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
}

/// Accepts one connection, reads the request, then holds the connection open
/// without ever responding (interrupted by cancellation at test end).
fn stallServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    discardRequestHead(&r.interface) catch return;
    io.sleep(Io.Duration.fromSeconds(30), .awake) catch {};
}

test "run reports timeouts against a non-responsive server" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    try group.concurrent(io, stallServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var snap_hist = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer snap_hist.deinit();
    var publish: Publish = .{ .hist = &snap_hist, .interval_ns = 10 * std.time.ns_per_ms };
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(500));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        .timeout_ns = 100 * std.time.ns_per_ms, // 100ms response timeout
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
        .publish = &publish,
    };
    run(&params);

    // Interrupt the server (blocked in accept/sleep) and join.
    group.cancel(io);
    server.deinit(io);

    // The server never responds, so nothing completes, but the response timeout
    // must fire at least once within the run.
    try testing.expectEqual(@as(u64, 0), counters.completed);
    try testing.expect(counters.timeouts > 0);
    // With record_timeouts on (the default), each timeout contributes exactly one
    // coordinated-omission-corrected latency sample so the tail isn't truncated.
    try testing.expectEqual(counters.timeouts, histogram.count());
    // The timeouts (and their latency samples) must reach the dashboard's
    // publish slot even though no request ever succeeds.
    try testing.expect(publish.counters.timeouts > 0);
    try testing.expect(publish.hist.count() > 0);
}

test "connect errors surface in the published snapshot during total outage" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bind an ephemeral port, then close the listener so connects are refused.
    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    server.deinit(io);
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var snap_hist = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer snap_hist.deinit();
    var publish: Publish = .{ .hist = &snap_hist, .interval_ns = 10 * std.time.ns_per_ms };
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(100));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        .timeout_ns = 0,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
        .publish = &publish,
    };
    run(&params);

    try testing.expect(counters.connect_errors > 0);
    // The refused connects must be visible to the dashboard: previously only
    // successful responses published, so an unreachable target showed nothing.
    try testing.expect(publish.counters.connect_errors > 0);
}

test "run with record_timeouts disabled drops timed-out samples" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    try group.concurrent(io, stallServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(500));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        .timeout_ns = 100 * std.time.ns_per_ms,
        .record_timeouts = false,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.cancel(io);
    server.deinit(io);

    try testing.expect(counters.timeouts > 0);
    try testing.expectEqual(@as(u64, 0), histogram.count());
}
