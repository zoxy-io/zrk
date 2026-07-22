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

/// Per-connection counters. Aggregated across connections for reporting.
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
    /// Requests abandoned because the response exceeded the wire `--timeout`.
    timeouts: u64 = 0,
    /// Requests that missed their coordinated-omission `--deadline`: either shed
    /// before sending (already staler than the deadline) or shut down in flight
    /// once `scheduled + deadline` passed. Distinct from wire `timeouts`, and —
    /// unlike a timeout — never recorded as a latency sample, so the histogram
    /// stays the distribution of requests served *within* the deadline.
    deadline_errors: u64 = 0,
    /// Peak observed schedule lag (`now − scheduled`) in nanoseconds: how far
    /// behind its intended send time this connection ever fell. A backlog gauge
    /// — nonzero means the client could not keep up with the offered schedule
    /// (see `--deadline`). Aggregated as a max, not a sum.
    max_behind_ns: u64 = 0,
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
        self.deadline_errors += other.deadline_errors;
        self.max_behind_ns = @max(self.max_behind_ns, other.max_behind_ns);
        for (&self.status_class, other.status_class) |*d, s| d.* += s;
    }

    /// Update the peak schedule-lag gauge with one send's observed lag (ns).
    pub fn noteBehind(self: *Counters, behind_ns: u64) void {
        if (behind_ns > self.max_behind_ns) self.max_behind_ns = behind_ns;
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
/// dashboard coroutine without racing the hot path. The connection coroutine
/// copies its live state here at most once per publish interval, under `mutex`;
/// the dashboard reads it under the same lock. The publish interval follows the
/// fastest consumer — the dashboard's `--refresh` when a live TUI is attached,
/// else the `--interval` stats window.
pub const Publish = struct {
    mutex: Io.Mutex = .init,
    /// Snapshot histogram (must share the live histogram's layout).
    hist: *hdr.Histogram,
    counters: Counters = .{},
    interval_ns: u64,
    /// Monotonic-ns timestamp of the next scheduled publish (0 = publish asap).
    next_ns: i128 = 0,
};

/// Everything a connection coroutine needs. `histogram` and `counters` are owned
/// by the connection coroutine and must not be shared across coroutines without
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
    /// Stagger phase ∈ [0, 1): this connection's sends solve the schedule at
    /// k + phase, offsetting it against the rest of the fleet so aggregate
    /// sends spread uniformly instead of firing in N-connection lockstep
    /// waves (which quantize per-interval throughput to multiples of N).
    phase: f64 = 0,
    /// Per-request wire timeout, measured from the actual send (0 = none).
    /// Bounds `done − actual_send` — the attempt on the wire — so it catches a
    /// hung socket or a dead server, but does *not* bound the coordinated-
    /// omission latency (which also includes time spent behind schedule). See
    /// `deadline_ns` for that.
    timeout_ns: u64,
    /// Coordinated-omission deadline, measured from each request's *scheduled*
    /// send time (0 = none). A request already staler than this is shed before
    /// sending (failed as a `deadline` error without touching the wire), which
    /// drains the backlog and keeps the recorded tail to roughly deadline + wire
    /// time while surfacing overload through the error path. In-flight requests
    /// that pass this age at send time are *not* aborted unless `deadline_abort`
    /// is set; see it for why.
    deadline_ns: u64 = 0,
    /// Also abort a request already on the wire once `scheduled + deadline`
    /// passes, by shutting the connection down (the only way to abandon an
    /// in-flight HTTP/1.1 request). Off by default: under saturation this resets
    /// a connection per miss, storming the target with reconnects and inflating
    /// its memory — while shed-before-send already bounds the tail. Opt in only
    /// when you need the recorded latency capped at exactly the deadline.
    deadline_abort: bool = false,
    /// Record a coordinated-omission-corrected latency sample when a request
    /// times out on the wire, instead of dropping it (which would truncate the
    /// tail). Does not apply to `deadline` misses, which are never recorded.
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
        var stream = connect(io, p.address, p.timeout_ns) catch {
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

        var conn_open = true;
        defer stream.close(io);

        // Serve requests on this connection until it must close or the test ends.
        while (conn_open and !p.stop.load(.monotonic)) {
            const t = now(io);
            if (t.nanoseconds >= p.end.nanoseconds) return;

            // Anchor the schedule on the first request; each send's intended
            // time is a closed-form function of its index (constant or ramp).
            if (anchor == null) anchor = t;
            const offset = p.schedule.offsetNs(send_index, p.phase);
            const scheduled = anchor.?.addDuration(Io.Duration.fromNanoseconds(@intCast(offset)));

            // Schedule lag: how late this send already is. Positive only under
            // load (when ahead we pace below); feeds the backlog gauge and the
            // deadline check. Both clocks are monotonic, so `behind` fits u64.
            const behind_ns: i128 = t.nanoseconds - scheduled.nanoseconds;
            if (behind_ns > 0) p.counters.noteBehind(@intCast(behind_ns));

            // Deadline shedding: a request already staler than the deadline can
            // never meet it, so fail it now — without touching the wire — and
            // move on. This lets the connection shed accumulated backlog and
            // keep measuring near-live latency instead of serializing through an
            // ever-staler queue; the misses surface as `deadline` errors.
            if (p.deadline_ns != 0 and behind_ns > p.deadline_ns) {
                noteDeadline(p);
                send_index += 1;
                continue;
            }

            // Pace: if we're ahead of schedule, wait; if behind, fire immediately.
            if (scheduled.nanoseconds > t.nanoseconds) {
                const wait = Io.Duration.fromNanoseconds(scheduled.nanoseconds - t.nanoseconds);
                io.sleep(wait, .awake) catch return;
            }
            send_index += 1;

            // Per-request timer tasks: one for the wire timeout, one for the
            // CO deadline abort. Each sleeps to its bound and, if the response
            // doesn't arrive first, shuts the stream down to unblock the read.
            // `timer_group.cancel` after performWork cancels un-fired timers and
            // joins fired ones so the flags and stream are safe to use after.
            var wire_fired: std.atomic.Value(bool) = .init(false);
            var deadline_fired: std.atomic.Value(bool) = .init(false);
            var timer_group: Io.Group = .init;
            defer timer_group.cancel(io);
            if (p.timeout_ns != 0)
                timer_group.concurrent(io, watchTimer, .{ io, &stream, p.timeout_ns, &wire_fired }) catch {};
            if (p.deadline_abort and p.deadline_ns != 0) {
                // behind_ns <= deadline_ns here (shed check above), so it fits u64.
                const behind: u64 = if (behind_ns > 0) @intCast(behind_ns) else 0;
                const remaining_ns = p.deadline_ns - behind;
                if (remaining_ns > 0)
                    timer_group.concurrent(io, watchTimer, .{ io, &stream, remaining_ns, &deadline_fired }) catch {};
            }
            const work = performWork(p, app_reader, app_writer);
            timer_group.cancel(io);
            const timed_out = wire_fired.load(.acquire) or deadline_fired.load(.acquire);
            const deadline_hit = deadline_fired.load(.acquire);

            switch (work) {
                .write_failed => {
                    if (deadline_hit) noteDeadline(p) else if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .write);
                    conn_open = false;
                },
                .read_failed => {
                    if (deadline_hit) noteDeadline(p) else if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .read);
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

                    // A timer may have fired in the same event batch as the
                    // response; the response still counts, but the socket is
                    // shut down so the connection is dead.
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

/// Sleeps for `timeout_ns` then shuts the stream down to unblock the pending
/// read in `performWork`, signaling a wire timeout or CO deadline miss.
/// Spawned per active bound per request; canceled (and joined) via its group
/// when the response arrives first — so the stream is never touched after close.
fn watchTimer(
    io: Io,
    stream: *net.Stream,
    timeout_ns: u64,
    fired: *std.atomic.Value(bool),
) void {
    io.sleep(Io.Duration.fromNanoseconds(timeout_ns), .awake) catch return;
    fired.store(true, .release);
    stream.shutdown(io, .both) catch {};
}

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

/// A request that missed its coordinated-omission `--deadline`: shed before
/// sending (already too stale) or shut down in flight at `scheduled + deadline`.
/// Counted as an error so sustained overload surfaces through `--max-error-rate`
/// instead of an unbounded latency tail, but deliberately *not* recorded as a
/// latency sample — the histogram stays the distribution of requests served
/// within the deadline. Skipped during shutdown, where it would be a teardown
/// artifact rather than a real miss.
fn noteDeadline(p: *Params) void {
    if (p.stop.load(.monotonic)) return;
    p.counters.deadline_errors += 1;
    maybePublish(p, now(p.io).nanoseconds);
}

/// Publish this connection's live state for the dashboard. Counters are
/// refreshed on EVERY call: they are a few words copied under this
/// connection's own mutex (contended only by the ~once-a-second snapshot
/// reader), and batching them to the publish interval quantized the fleet's
/// per-window request deltas to whole per-connection batches — the reader saw
/// counts advance in conns-sized steps, a staircase in the throughput
/// timeseries. The histogram copy — the expensive part — still happens at
/// most once per publish interval.
fn maybePublish(p: *Params, now_ns: i128) void {
    const pub_ptr = p.publish orelse return;
    pub_ptr.mutex.lockUncancelable(p.io);
    defer pub_ptr.mutex.unlock(p.io);
    pub_ptr.counters = p.counters.*;
    if (now_ns >= pub_ptr.next_ns) {
        p.histogram.copyInto(pub_ptr.hist);
        pub_ptr.next_ns = now_ns + @as(i128, @intCast(pub_ptr.interval_ns));
    }
}

fn connect(io: Io, address: net.IpAddress, timeout_ns: u64) !net.Stream {
    // The response timeout is enforced per-request by `watchTimer`.
    const timeout: Io.Timeout = if (timeout_ns != 0) .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(timeout_ns), .clock = .awake } } else .none;
    return address.connect(io, .{ .mode = .stream, .timeout = timeout });
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;
const zio = @import("zio");

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
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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

/// Accepts one keep-alive connection and answers every request with a fixed 200,
/// but only after a fixed per-response delay — a server slower than the client's
/// deadline, used to prove the default deadline lets slow requests finish on the
/// reused connection instead of resetting it.
fn delayServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    while (true) {
        discardRequestHead(&r.interface) catch return;
        io.sleep(Io.Duration.fromMilliseconds(60), .awake) catch return;
        w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi") catch return;
        w.interface.flush() catch return;
    }
}

test "run reports timeouts against a non-responsive server" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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

test "deadline-abort fails stale in-flight requests without recording them" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } }, // ~500 req/s
        // No wire timeout: with --deadline-abort the deadline alone must catch
        // the stall in flight, shutting each blocked request down at
        // `scheduled + deadline`. (Without abort a stalled read is not
        // interrupted at all — that is the separate wire timeout's job.)
        .timeout_ns = 0,
        .deadline_ns = 50 * std.time.ns_per_ms,
        .deadline_abort = true,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.cancel(io);
    server.deinit(io);

    // The server never responds, so nothing completes; every request misses the
    // deadline and is counted as such — never as a wire timeout.
    try testing.expectEqual(@as(u64, 0), counters.completed);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expect(counters.deadline_errors > 0);
    // Deadline misses are failures, not latencies: the histogram stays empty
    // (contrast the timeout test above, where record_timeouts fills the tail).
    try testing.expectEqual(@as(u64, 0), histogram.count());
    // The stall drives the connection a full deadline behind its schedule, so
    // the backlog gauge registers substantial lag (equilibrium sits near the
    // 50ms deadline; assert well above jitter).
    try testing.expect(counters.max_behind_ns > 20 * std.time.ns_per_ms);
}

test "default deadline sheds but never resets the connection in flight" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    // A single keep-alive connection served by a server that takes 60ms per
    // response — far longer than the 20ms deadline. With the in-flight abort
    // OFF (the default), those slow responses must still *complete* on the same
    // reused connection, never being killed mid-flight.
    var group: Io.Group = .init;
    group.async(io, delayServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(400));
    const deadline_ns = 20 * std.time.ns_per_ms;

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        // Offer far faster than the server can serve so the backlog outruns the
        // deadline and the shed path engages.
        .schedule = .{ .constant = .{ .interval_ns = 1 * std.time.ns_per_ms } }, // ~1000 req/s
        // No wire timeout and no abort: nothing may interrupt an in-flight
        // request, so a reset could only come from the deadline — and must not.
        .timeout_ns = 0,
        .deadline_ns = deadline_ns,
        .deadline_abort = false,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    stop.store(true, .monotonic);
    group.cancel(io);
    server.deinit(io);

    // Slow requests complete instead of being aborted, so the connection is
    // reused (the server accepts exactly one) — no read errors, no reconnect
    // storm — while the backlog is still drained as shed `deadline` errors.
    try testing.expect(counters.completed > 0);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expect(counters.deadline_errors > 0);
    try testing.expectEqual(counters.completed, histogram.count());
    // The tradeoff the default accepts: a completed request's recorded CO
    // latency can exceed the deadline (it is bounded by deadline + wire time,
    // not the deadline itself), because we never cut it off.
    try testing.expect(histogram.max() > deadline_ns / std.time.ns_per_us);
}

test "deadline mode sheds backlog under overload and bounds the recorded tail" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    // A fast keep-alive server: responses are instant, so the *only* thing that
    // can make the connection fall behind is an unservably high offered rate.
    var group: Io.Group = .init;
    group.async(io, testServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(300));
    const deadline_ns = 20 * std.time.ns_per_ms;

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        // 500k req/s on one blocking connection is unachievable on loopback, so
        // the connection falls behind and — once past the deadline — sheds.
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_us } },
        .timeout_ns = 0,
        .deadline_ns = deadline_ns,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Some requests are served (the connection keeps probing near-live latency)
    // and some are shed as the backlog outruns the deadline.
    try testing.expect(counters.completed > 0);
    try testing.expect(counters.deadline_errors > 0);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    // Only served requests are recorded; shed ones are not.
    try testing.expectEqual(counters.completed, histogram.count());
    // The recorded tail is bounded by the deadline: shedding keeps sends within
    // one deadline of schedule, so every recorded latency stays near/under it
    // (vs. the tens-of-seconds tail this mode exists to prevent).
    try testing.expect(histogram.max() <= 2 * deadline_ns / std.time.ns_per_us);
}

test "a generous deadline never fires against a healthy server" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

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
        .deadline_ns = 1 * std.time.ns_per_s, // far above loopback latency
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // A connection that keeps up never sheds and never expires in flight: every
    // request completes and is recorded, and the deadline path stays untouched.
    try testing.expect(counters.completed > 0);
    try testing.expectEqual(@as(u64, 0), counters.deadline_errors);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expectEqual(counters.completed, histogram.count());
}
