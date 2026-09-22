//! A single load-generating connection: connect, then repeatedly pace-and-send
//! requests, recording coordinated-omission-corrected latency.
//!
//! By default one request is in flight per connection at a time (like
//! wrk/wrk2); over HTTP/2, `--streams` lets a connection keep several open
//! (`runMultiplexed`). Achieving a high total rate is a matter of running many
//! connections; each connection paces its own sends to a fixed schedule so
//! that, when the server falls behind, backlogged requests still accrue
//! latency against their *intended* send time rather than their actual send
//! time.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const hdr = @import("hdr.zig");
const httpmod = @import("http.zig");
const tlsmod = @import("tls.zig");
const h2conn = @import("h2conn.zig");
const h3conn = @import("h3conn.zig");
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
    /// The same request as one HPACK-encoded header block, when `http2` is set.
    ///
    /// Built once at startup with `Encoder.Mode.static_only`, so it depends on
    /// no encoder state and is replayed byte-identically on every stream — the
    /// reason zrk pays no per-request HPACK cost for a request that never
    /// changes.
    request_block: []const u8 = &.{},
    /// Request body, sent as DATA after the header block. Empty for the common
    /// case, where the header block carries END_STREAM itself.
    body: []const u8 = &.{},
    /// Speak HTTP/2 with prior knowledge instead of HTTP/1.1.
    http2: bool = false,
    /// Speak HTTP/3 over QUIC. Mutually exclusive with `http2`, and nothing
    /// below this line in the TCP path runs: `run` hands the whole connection
    /// to `h3conn.run`, which owns its own UDP socket, its own TLS handshake
    /// and its own event loop. See that file for why it cannot be a codec swap.
    http3: bool = false,
    /// The same request as one QPACK-encoded HEADERS frame, plus a DATA frame
    /// when there is a body, when `http3` is set.
    ///
    /// Built once at startup against QPACK's static table alone, so it depends
    /// on no encoder state and is replayed byte-identically on every stream —
    /// the HTTP/3 half of the trade `request_block` makes for HTTP/2.
    h3_request: []const u8 = &.{},
    /// How many of this connection's scheduled sends may be on the wire at
    /// once (`--streams`). Requires `http2`.
    ///
    /// It is a depth knob and nothing more: `schedule` and `send_index` are
    /// untouched by it, so the connection offers exactly the same load at any
    /// `streams`. What changes is whether a send that is *due* has to wait for
    /// the previous response before it can go out. At 1 — the default — this
    /// file behaves exactly as it did before multiplexing existed, down to
    /// which code path runs. See docs/multiplexing.md for why `-c` and not this
    /// is the number to compare across runs.
    streams: u32 = 1,
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
    /// Close the connection after every response and reconnect for the next
    /// request (`--disable-keepalive`), regardless of what the response said
    /// about reuse. See `cli.Config.disable_keepalive` for why the decision
    /// cannot be left to the server.
    disable_keepalive: bool = false,
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
    /// Pinned per-connection QUIC/HTTP-3 transport state; required when
    /// `http3`. Megabytes rather than kilobytes, and allocated once for the
    /// run rather than per reconnect, for the same reason `tls_state` is.
    h3_state: ?*h3conn.State = null,
    /// Shared trust store; null means verification is skipped.
    ca_store: ?*tlsmod.CaStore = null,
};

const read_buffer_size = 16 * 1024;
const write_buffer_size = 8 * 1024;

/// Run one connection until `end` (or `stop`). Never returns an error: all
/// failures are folded into `counters` and recovered from by reconnecting.
pub fn run(p: *Params) void {
    const io = p.io;

    // HTTP/3 is not a codec swap. Everything below — the TCP connect, the
    // reader/writer pair, the watchdog that enforces a bound by shutting a
    // socket down — assumes a stream transport somebody else is running. QUIC
    // is the transport, so `h3conn` owns the socket, the handshake and the
    // clock, and this function's only part in it is the dispatch.
    if (p.http3) return h3conn.run(p);

    var read_buf: [read_buffer_size]u8 = undefined;
    var write_buf: [write_buffer_size]u8 = undefined;

    // Each connection keeps its own schedule, anchored when it first connects;
    // `send_index` is the coordinated-omission-correct request counter that
    // drives it, persisting across reconnects so a stall is caught up (not reset).
    var anchor: ?Io.Timestamp = null;
    var send_index: u64 = 0;
    // Whether the request at `send_index` is going out a second time, after
    // an HTTP/2 peer declined the first without processing it. A second
    // refusal is charged, so a peer declining everything is a run of errors
    // rather than a silent loop.
    var resending = false;
    // The multiplexed path's equivalent, which can hold several: see
    // `RetryQueue`.
    var retry: RetryQueue = .{};

    while (!p.stop.load(.monotonic) and now(io).nanoseconds < p.end.nanoseconds) {
        // (Re)connect, bounded by the time left in the run. A peer that accepts
        // connections but never drains its listen backlog leaves connect()
        // blocked in the TCP handshake; with no wire timeout that wait is the
        // OS connect timeout (seconds to minutes), which would drag the run far
        // past `end`. Cap it at the shorter of the wire timeout and the time
        // remaining so the loop can always re-evaluate `end`.
        const connect_remaining_ns = p.end.nanoseconds - now(io).nanoseconds;
        if (connect_remaining_ns <= 0) return;
        const connect_timeout_ns = deadlineBoundedTimeout(p.timeout_ns, @intCast(connect_remaining_ns));
        var stream = connect(io, p.address, connect_timeout_ns) catch {
            // A connect cut off by the run's own end deadline is a teardown
            // artifact, not a target failure — don't count it as a connect error.
            if (now(io).nanoseconds >= p.end.nanoseconds) return;
            noteError(p, .connect);
            // Back off briefly so a refused port doesn't spin the CPU.
            io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
            continue;
        };
        disableNagle(stream);

        // Establish the transport (plaintext, or a TLS session over the stream)
        // and obtain the reader/writer the HTTP layer talks to.
        var app_reader: *Io.Reader = undefined;
        var app_writer: *Io.Writer = undefined;
        var plain_reader: net.Stream.Reader = undefined;
        var plain_writer: net.Stream.Writer = undefined;
        if (p.is_tls) {
            const ts = p.tls_state.?;
            // Offer `h2` only when this run speaks it. A server that answers
            // `http/1.1` to an `h2` offer is a real thing to meet, so the
            // negotiated protocol is checked below rather than assumed.
            const alpn = if (p.http2) tlsmod.alpn_http2 else tlsmod.alpn_http1;
            ts.handshake(io, p.allocator, stream, p.host, p.insecure, p.ca_store, alpn) catch {
                // A failed handshake counts as a connect error; try again later.
                noteError(p, .connect);
                stream.close(io);
                io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
                continue;
            };
            // What the peer actually chose. `--http2` against a server that
            // does not speak it would otherwise send an HTTP/2 preface into an
            // HTTP/1.1 connection and report the target as broken — which is
            // exactly the failure mode the cleartext-only guard existed to
            // prevent, now that ALPN makes the question answerable.
            if (p.http2 and !alpnIs(ts.negotiatedAlpn(), "h2")) {
                noteError(p, .connect);
                stream.close(io);
                io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
                continue;
            }
            app_reader = ts.reader();
            app_writer = ts.writer();
        } else {
            plain_reader = stream.reader(io, &read_buf);
            plain_writer = stream.writer(io, &write_buf);
            app_reader = &plain_reader.interface;
            app_writer = &plain_writer.interface;
        }

        // The HTTP/2 session, if this run speaks it: preface, our SETTINGS, the
        // window we need, and the peer's SETTINGS acknowledged. A connection
        // that cannot complete that never carried a request, so it counts as a
        // connect error — the same as a TLS handshake that failed above.
        var h2_session: h2conn.Session = .init(app_reader, app_writer);
        if (p.http2) {
            // Bounded by the wire timeout, for the same reason `connect` above
            // is: a peer that accepts the connection and then never sends its
            // SETTINGS leaves this read blocked forever, and the run would sit
            // past `end` with nothing to show. `connect` already defends
            // against the listen-backlog version of this; the handshake is the
            // other half and was missing it.
            //
            // Found by mutation rather than by reading: breaking the HTTP/2
            // path made the suite *hang* instead of fail, which is how the
            // unbounded read surfaced.
            var handshake_fired: std.atomic.Value(bool) = .init(false);
            var handshake_group: Io.Group = .init;
            if (p.timeout_ns != 0)
                handshake_group.concurrent(io, watchTimer, .{ io, &stream, p.timeout_ns, &handshake_fired }) catch {};
            const opened = h2_session.open();
            handshake_group.cancel(io);

            opened catch {
                // A handshake cut off by the run's own end is a teardown
                // artifact, like the connect above.
                if (now(io).nanoseconds >= p.end.nanoseconds) return;
                noteError(p, .connect);
                stream.close(io);
                io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
                continue;
            };
        }

        // Multiplexing takes over the whole connection from here: the request
        // loop below is the serial one, and its two load-bearing assumptions —
        // one watchdog for the connection, one `send_index` consumed in place
        // — are exactly what a second open stream breaks.
        if (p.http2 and p.streams > 1) {
            runMultiplexed(p, io, &h2_session, &anchor, &send_index, &retry);
            stream.close(io);
            continue;
        }

        var conn_open = true;
        defer stream.close(io);

        // One watcher for every request this connection will serve. Registered
        // after `stream.close` so LIFO runs the cancel first — the watcher is
        // joined before the stream it may shut down goes away.
        const wd_active = p.timeout_ns != 0 or (p.deadline_abort and p.deadline_ns != 0);
        var wd: Watchdog = .{};
        var wd_group: Io.Group = .init;
        defer wd_group.cancel(io);
        if (wd_active)
            wd_group.concurrent(io, watchConnection, .{ io, &stream, &wd, p.timeout_ns }) catch {};

        // Serve requests on this connection until it must close or the test ends.
        while (conn_open and !p.stop.load(.monotonic)) {
            const t = now(io);
            if (t.nanoseconds >= p.end.nanoseconds) return;

            // RFC 9113 section 6.8: no new stream after a GOAWAY. Checked
            // before the schedule is consulted, so the request that would have
            // gone out here goes out on the next connection instead — the same
            // index, and so the same scheduled time.
            if (p.http2 and h2_session.peer_going_away) break;

            // Anchor the schedule on the first request; each send's intended
            // time is a closed-form function of its index (constant or ramp).
            // In `.closed` mode there is no independent schedule to solve —
            // the next send is intended for right now — which degenerately
            // zeroes out the pacing wait below, the deadline check (never
            // behind its own "now"), and the CO correction (latency becomes
            // actual round-trip time), without needing to special-case any of
            // that downstream logic.
            if (anchor == null) anchor = t;
            const scheduled = if (p.schedule == .closed) t else blk: {
                const offset = p.schedule.offsetNs(send_index, p.phase);
                break :blk anchor.?.addDuration(Io.Duration.fromNanoseconds(@intCast(offset)));
            };

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
            // The wire timeout runs from the *actual* send, so a send that
            // paced has to re-read the clock; one that fired immediately
            // (every send in `.closed`) reuses `t` and pays nothing.
            var send_ts = t;
            if (scheduled.nanoseconds > t.nanoseconds) {
                const wait = Io.Duration.fromNanoseconds(scheduled.nanoseconds - t.nanoseconds);
                io.sleep(wait, .awake) catch return;
                send_ts = now(io);
            }
            send_index += 1;

            // Publish this request's bound to the connection's watcher. Both
            // bounds are absolute timestamps — the wire timeout from the actual
            // send, the CO abort from `scheduled` — so the earlier one binds and
            // the two collapse into a single deadline instead of two timers.
            const wire_deadline_ns: u64 = if (p.timeout_ns != 0)
                @intCast(send_ts.nanoseconds + @as(i128, p.timeout_ns))
            else
                0;
            const co_deadline_ns: u64 = if (p.deadline_abort and p.deadline_ns != 0)
                @intCast(scheduled.nanoseconds + @as(i128, p.deadline_ns))
            else
                0;
            const co_binds = co_deadline_ns != 0 and
                (wire_deadline_ns == 0 or co_deadline_ns <= wire_deadline_ns);
            if (wd_active) wd.arm(
                if (co_binds) co_deadline_ns else wire_deadline_ns,
                co_binds,
            );

            const work = performWork(p, app_reader, app_writer, if (p.http2) &h2_session else null);
            if (wd_active) wd.disarm();
            const timed_out = wd.fired.load(.acquire);
            const deadline_hit = timed_out and wd.fired_co.load(.acquire);

            switch (work) {
                .write_failed => {
                    resending = false;
                    if (deadline_hit) noteDeadline(p) else if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .write);
                    conn_open = false;
                },
                .read_failed => {
                    resending = false;
                    if (deadline_hit) noteDeadline(p) else if (timed_out) noteTimeout(p, io, scheduled) else noteError(p, .read);
                    conn_open = false;
                },
                // The peer declined the request without processing it, so it
                // is sent again on the next connection: `send_index` steps
                // back, which gives it back its scheduled time — once.
                .refused => {
                    if (deadline_hit) {
                        noteDeadline(p);
                    } else if (timed_out) {
                        noteTimeout(p, io, scheduled);
                    } else if (!resending) {
                        send_index -= 1;
                        resending = true;
                        conn_open = false;
                        continue;
                    } else {
                        noteError(p, .read);
                    }
                    resending = false;
                    conn_open = false;
                },
                .ok => |resp| {
                    resending = false;
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
                    //
                    // `disable_keepalive` retires the connection here on our
                    // own terms rather than the server's: a server that ignores
                    // the `Connection: close` we sent would otherwise keep the
                    // socket — and its keep-alive throughput — while a
                    // compliant one paid for a connection per request, which
                    // would make the two incomparable in the one mode whose
                    // entire purpose is comparing them.
                    if (timed_out or !resp.keep_alive or p.disable_keepalive) {
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
    /// HTTP/2 only: the peer declined the request without processing it, by
    /// GOAWAY or REFUSED_STREAM, so it may be sent again.
    refused,
};

/// One connection's wire-timeout/CO-abort state, enforced by a single
/// long-lived `watchConnection` task instead of a task spawned per request.
///
/// Requests are strictly sequential on a connection — at most one is ever on
/// the wire — so one watcher can enforce every request's bound. The request
/// loop only publishes the in-flight deadline here (`arm`) and withdraws it
/// (`disarm`); both are a couple of atomic stores, where a task spawned and
/// cancelled per request would cost a spawn plus a join each time.
const Watchdog = struct {
    /// Absolute monotonic-ns deadline of the request on the wire (0 = idle).
    deadline_ns: std.atomic.Value(u64) = .init(0),
    /// Whether `deadline_ns` came from the CO abort bound rather than the wire
    /// timeout, so a fire lands in the right error class.
    co_bound: std.atomic.Value(bool) = .init(false),
    /// Seqlock counter, bumped on every `arm` and every `disarm`. A watcher
    /// that finds it unchanged across its wait knows no request started or
    /// finished meanwhile, so the one it timed is still on the wire. That is
    /// what makes firing safe without a fresh task per request — and it does
    /// not depend on consecutive deadlines being distinct, which two sends in
    /// the same nanosecond would break.
    epoch: std.atomic.Value(u64) = .init(0),
    /// Set by the watcher when it actually shut the stream down.
    fired: std.atomic.Value(bool) = .init(false),
    /// `co_bound` as of the fire, read by the request loop after `fired`.
    fired_co: std.atomic.Value(bool) = .init(false),

    /// Publish the deadline for the request about to go on the wire.
    fn arm(self: *Watchdog, deadline_ns: u64, co_bound: bool) void {
        self.co_bound.store(co_bound, .monotonic);
        self.deadline_ns.store(deadline_ns, .monotonic);
        // Release so a watcher observing this epoch also observes both stores.
        _ = self.epoch.fetchAdd(1, .release);
    }

    /// Withdraw the deadline once the request is off the wire.
    fn disarm(self: *Watchdog) void {
        self.deadline_ns.store(0, .monotonic);
        _ = self.epoch.fetchAdd(1, .release);
    }
};

/// Enforces one connection's request deadlines for the connection's whole life.
///
/// Sleeps to the in-flight deadline, then shuts the stream down to unblock the
/// pending read in `performWork` — the same abort mechanism `watchTimer` uses,
/// hoisted out of the per-request path. Canceled via its group when the
/// connection tears down, so the stream is never touched after close.
///
/// A busy connection wakes this roughly once per timeout period rather than
/// once per request: by the time the deadline of some earlier request comes
/// around, thousands may have completed, and the epoch check simply sends it
/// back to sleep on the current one.
fn watchConnection(
    io: Io,
    stream: *net.Stream,
    wd: *Watchdog,
    timeout_ns: u64,
) void {
    // How long to wait before re-checking while nothing is on the wire. Only
    // reached in the gap between two requests, and it cannot oversleep a fresh
    // deadline because that is a full `timeout_ns` out. Bounds worst-case
    // detection at deadline + slice.
    const idle_slice_ns: u64 = @max(timeout_ns / 4, std.time.ns_per_ms);

    while (true) {
        // Seqlock read: an epoch that moved across the three loads means we
        // caught a torn arm/disarm, so take the state again.
        const e1 = wd.epoch.load(.acquire);
        const deadline = wd.deadline_ns.load(.monotonic);
        const co_bound = wd.co_bound.load(.monotonic);
        if (wd.epoch.load(.acquire) != e1) continue;

        if (deadline == 0) {
            io.sleep(Io.Duration.fromNanoseconds(@intCast(idle_slice_ns)), .awake) catch return;
            continue;
        }

        const remaining: i128 = @as(i128, deadline) - now(io).nanoseconds;
        if (remaining > 0) {
            io.sleep(Io.Duration.fromNanoseconds(@intCast(remaining)), .awake) catch return;
            // A short wake leaves the deadline unblown; re-read and wait again
            // rather than aborting a request that still has time.
            if (@as(i128, deadline) > now(io).nanoseconds) continue;
        }

        // Unchanged epoch: the request we timed never left the wire, so this
        // deadline is genuinely blown. Anything else and the state moved on.
        if (wd.epoch.load(.acquire) != e1) continue;

        wd.fired_co.store(co_bound, .release);
        wd.fired.store(true, .release);
        stream.shutdown(io, .both) catch {};
        return;
    }
}

/// Sleeps for `timeout_ns` then shuts the stream down to unblock the pending
/// read in `performWork`, signaling a wire timeout or CO deadline miss.
/// Used for the once-per-connection HTTP/2 handshake bound; the per-request
/// bounds go through `Watchdog`/`watchConnection` instead.
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

// ── Multiplexing ────────────────────────────────────────────────────────────
//
// Three coroutines share one connection: `muxSend` (which runs on the
// connection's own coroutine), `muxReceive`, and `muxWatch`. They exist because
// the serial path's shape does not survive a second open stream. `performWork`
// blocks until the response arrives, so it cannot pace a send while one is
// outstanding; and one connection-wide `Watchdog` cannot time N requests that
// started at N different moments.
//
// What does *not* change is the measurement. `send_index` is still consumed
// once per send by one sender, the schedule is still solved from it, and every
// latency sample is still measured from `scheduled`. `--streams` only decides
// whether a send that is due has to wait for the previous response first.
// docs/multiplexing.md has the reasoning; `--streams 1` reaches none of this.

/// The most streams one connection will open at once.
///
/// A ceiling rather than an allocation: the slot table lives on the
/// connection's own frame, next to the read and write buffers, which is what
/// keeps a connection allocation-free for its whole life. Well past any real
/// `--streams` — servers advertise limits an order of magnitude below it — and
/// `cli.zig` refuses anything larger.
pub const streams_max: u32 = 128;

/// One in-flight request on a multiplexed connection.
const Slot = struct {
    /// Claimed by the sender, whether or not its stream is open yet. The gap
    /// between the two is deliberate: the slot is claimed and its identifier
    /// published *before* the HEADERS is written, so there is no window in
    /// which a response arrives for a stream this table does not know.
    busy: bool = false,
    /// The stream carrying the request; 0 until it is opened.
    stream: u31 = 0,
    /// When this request was *supposed* to go out. The only clock its latency
    /// is measured against — the coordinated-omission correction, unchanged.
    scheduled: Io.Timestamp = .zero,
    /// `:status`, once the response's field block has arrived.
    status: ?u16 = null,
    /// Response octets seen so far, field block included.
    bytes: u64 = 0,
    /// Absolute monotonic-ns deadline for this stream (0 = none), and whether
    /// it came from the CO abort bound rather than the wire timeout — the same
    /// collapse of two bounds into one that `Watchdog` does, per stream.
    deadline_ns: u64 = 0,
    deadline_co: bool = false,
    /// Whether this is the request's second attempt, after the peer declined
    /// the first. See `RetryQueue`.
    retried: bool = false,
};

/// Requests an HTTP/2 peer declined without processing them — streams past a
/// GOAWAY's last stream, or reset with REFUSED_STREAM (RFC 9113 sections 6.8
/// and 8.7) — and requests that lost the race with a GOAWAY and never left.
/// Sent again ahead of the schedule, at the time each was *scheduled* for, so
/// a server recycling connections costs a retry rather than a failure and a
/// retried latency still runs from when the request was due.
///
/// Oldest first, and owned by the connection loop rather than by one `Mux`:
/// the next connection is where these go out.
///
/// Never more than `streams_max`: an entry only ever comes out of a slot, and
/// the sender takes from here before it takes from the schedule.
const RetryQueue = struct {
    entries: [streams_max]Entry = undefined,
    len: usize = 0,

    const Entry = struct {
        scheduled: Io.Timestamp,
        /// Whether sending it again is a second attempt.
        retried: bool,
    };

    fn push(queue: *RetryQueue, entry: Entry) void {
        std.debug.assert(queue.len < queue.entries.len);
        var at = queue.len;
        while (at > 0 and queue.entries[at - 1].scheduled.nanoseconds > entry.scheduled.nanoseconds) : (at -= 1) {
            queue.entries[at] = queue.entries[at - 1];
        }
        queue.entries[at] = entry;
        queue.len += 1;
    }

    fn pop(queue: *RetryQueue) ?Entry {
        if (queue.len == 0) return null;
        const head = queue.entries[0];
        std.mem.copyForwards(Entry, queue.entries[0 .. queue.len - 1], queue.entries[1..queue.len]);
        queue.len -= 1;
        return head;
    }
};

/// Where a request `Mux.send` is about to put on a stream came from: the
/// schedule, which it advances, or the retry queue, which it does not.
const Origin = union(enum) {
    schedule: *u64,
    retry: RetryQueue.Entry,
};

/// State shared by one connection's three coroutines.
const Mux = struct {
    io: Io,
    p: *Params,
    session: *h2conn.Session,
    slots: []Slot,
    /// The connection loop's, not this connection's. Guarded by `state`.
    retry: *RetryQueue,

    /// Guards `slots` and the three flags below — and `p.histogram` and
    /// `p.counters`, which stop being the sender's private property the moment
    /// the receiver is the one that knows a request finished.
    state: Io.Mutex = .init,
    /// Signaled whenever a slot frees or the connection ends: the two things a
    /// sender with nowhere to put a request cares about.
    slot_free: Io.Condition = .init,
    /// Serializes the writer across all three: request HEADERS from the sender,
    /// SETTINGS and PING acks and WINDOW_UPDATE from the receiver, RST_STREAM
    /// from the watchdog.
    ///
    /// Separate from `state` so no I/O ever runs under the state lock — a flush
    /// into a full socket buffer would otherwise stall the receiver. `send` is
    /// the one place both are held, and it takes this one first; nothing takes
    /// them the other way round.
    write: Io.Mutex = .init,

    /// Slots claimed, free or not.
    active: u32 = 0,
    /// GOAWAY seen: finish what is open, start nothing new.
    no_new_streams: bool = false,
    /// The connection is finished, for any reason.
    dead: bool = false,
    /// What the peer is owed but has not been sent yet. Touched only by the
    /// receiver, so they need no lock. See `flushOwed`.
    owed_settings_ack: bool = false,
    owed_ping: ?h2conn.Reply = null,

    /// Being retired on our own terms — end of run, or a drained GOAWAY.
    /// Streams still open then are dropped rather than counted: their requests
    /// went out but the run stopped waiting, which is not a target failure. The
    /// same judgement `noteError` makes about everything after `stop`.
    retiring: bool = false,

    /// Send whatever the peer is owed — SETTINGS and PING acks, and the
    /// connection window — if the writer happens to be free. False on a write
    /// that broke.
    ///
    /// Never waits for the writer, and that is the point. The sender holds
    /// `write` across its flush, and a flush can park when the peer stops
    /// reading. If the receiver then waited for `write`, it would stop reading
    /// too — so the peer's send buffer fills, the peer stops reading, and the
    /// sender's flush never returns. The cycle closes and the connection hangs
    /// until teardown turns the rest of the run into timeouts. Reading is the
    /// only way out of it, so the receiver gives up the writer instead of the
    /// read and tries again after the next frame.
    fn flushOwed(mux: *Mux) bool {
        const window_due = mux.session.windowDue();
        if (!mux.owed_settings_ack and mux.owed_ping == null and !window_due) return true;
        if (!mux.write.tryLock()) return true;
        defer mux.write.unlock(mux.io);

        if (mux.owed_settings_ack) {
            mux.session.reply(.settings_ack) catch return false;
            mux.owed_settings_ack = false;
        }
        if (mux.owed_ping) |owed| {
            mux.session.reply(owed) catch return false;
            mux.owed_ping = null;
        }
        // Re-read rather than trusting `window_due`: a frame may have landed
        // while the lock was being taken.
        if (mux.session.windowDue()) mux.session.replenishWindow() catch return false;
        return true;
    }

    /// Take a free slot, waiting if every stream is busy. Null means the sender
    /// is done: the connection died, the peer said no new streams, or the wait
    /// was canceled.
    fn acquire(mux: *Mux) ?*Slot {
        mux.state.lockUncancelable(mux.io);
        defer mux.state.unlock(mux.io);
        while (true) {
            if (mux.dead or mux.no_new_streams) return null;
            for (mux.slots) |*slot| {
                if (slot.busy) continue;
                slot.* = .{ .busy = true };
                mux.active += 1;
                return slot;
            }
            mux.slot_free.wait(mux.io, &mux.state) catch return null;
        }
    }

    /// Free a slot and wake a sender waiting for one. Caller holds `state`.
    ///
    /// Idempotent, and that is load-bearing rather than defensive: a connection
    /// that dies while the sender is mid-`send` has its slot reclaimed by
    /// `fail` — the sender is parked inside `beginStream`'s flush at the time —
    /// and the sender then runs its own error path over the same slot. Without
    /// the guard the second call takes `active` below zero.
    fn release(mux: *Mux, slot: *Slot) void {
        if (!slot.busy) return;
        slot.* = .{};
        mux.active -= 1;
        mux.slot_free.signal(mux.io);
    }

    /// The slot carrying `stream`, or null if it has already been retired.
    /// Caller holds `state`.
    ///
    /// An optional rather than an error because a late frame for a completed,
    /// timed-out or reset stream is expected, not exceptional: identifiers are
    /// never reused, so a frame naming one this table has forgotten is simply
    /// past.
    fn find(mux: *Mux, stream: u31) ?*Slot {
        if (stream == 0) return null;
        for (mux.slots) |*slot| {
            if (slot.stream == stream) return slot;
        }
        return null;
    }

    /// Record a finished response and free its slot. Caller holds `state`.
    fn complete(mux: *Mux, slot: *Slot) void {
        const p = mux.p;
        const done = now(mux.io);
        // A stream that ended without `:status` is malformed (RFC 9113 section
        // 8.3.2), and there is no honest latency sample for a request that
        // never answered — the same call `finish` makes on the serial path.
        const status = slot.status orelse {
            mux.release(slot);
            noteError(p, .read);
            return;
        };
        // Coordinated-omission-corrected latency: from the time the request
        // *should* have been sent, not when it actually went out.
        const latency_ns = done.nanoseconds - slot.scheduled.nanoseconds;
        const latency_us: u64 = if (latency_ns > 0) @intCast(@divTrunc(latency_ns, std.time.ns_per_us)) else 0;
        p.histogram.record(latency_us);
        p.counters.completed += 1;
        p.counters.bytes += slot.bytes;
        p.counters.recordStatus(status);
        mux.release(slot);
        maybePublish(p, done.nanoseconds);
    }

    /// The connection is finished. Every stream still open loses its request
    /// with it: the serial path counts exactly one error for the one request it
    /// had in flight, and N streams means N.
    fn fail(mux: *Mux, kind: ErrorKind) void {
        mux.state.lockUncancelable(mux.io);
        defer mux.state.unlock(mux.io);
        if (!mux.retiring) {
            for (mux.slots) |*slot| {
                if (!slot.busy) continue;
                // A slot claimed but not yet opened carries no request: the
                // sender has it and has written nothing, so freeing it is right
                // and charging it an error would invent a failure.
                const carried = slot.stream != 0;
                mux.release(slot);
                if (carried) noteError(mux.p, kind);
            }
        }
        mux.dead = true;
        mux.slot_free.broadcast(mux.io);
    }

    /// A request the peer declined without processing: freed without an
    /// error and queued to go out again — once. Declined a second time, it is
    /// a read error like any other refusal. Caller holds `state`.
    fn requeue(mux: *Mux, slot: *Slot) void {
        const entry: RetryQueue.Entry = .{ .scheduled = slot.scheduled, .retried = true };
        const again = slot.retried;
        mux.release(slot);
        if (again) {
            noteError(mux.p, .read);
            return;
        }
        mux.retry.push(entry);
    }

    /// GOAWAY: open nothing more, and retry what the peer will not process.
    /// Caller holds `state`.
    fn goAway(mux: *Mux) void {
        mux.no_new_streams = true;
        const last = mux.session.peer_last_stream;
        for (mux.slots) |*slot| {
            // 0 is a slot the sender has claimed but not opened; `send` finds
            // the GOAWAY when it tries.
            if (!slot.busy or slot.stream == 0 or slot.stream <= last) continue;
            mux.requeue(slot);
        }
        mux.slot_free.broadcast(mux.io);
    }

    /// Whether a declined request is waiting to go out again.
    fn hasRetry(mux: *Mux) bool {
        mux.state.lockUncancelable(mux.io);
        defer mux.state.unlock(mux.io);
        return mux.retry.len > 0;
    }

    /// Stop on our own terms; see `retiring`.
    fn retire(mux: *Mux) void {
        mux.state.lockUncancelable(mux.io);
        defer mux.state.unlock(mux.io);
        mux.retiring = true;
        mux.dead = true;
        mux.slot_free.broadcast(mux.io);
    }

    /// Charge this send's schedule lag, and shed it if `--deadline` is already
    /// blown. Verbatim the serial path's rule: a request staler than the
    /// deadline can never meet it, so it is failed here without touching the
    /// wire, which drains backlog instead of serializing through it.
    fn shed(mux: *Mux, scheduled: Io.Timestamp, t: Io.Timestamp, origin: Origin) bool {
        const p = mux.p;
        mux.state.lockUncancelable(mux.io);
        defer mux.state.unlock(mux.io);
        const behind_ns: i128 = t.nanoseconds - scheduled.nanoseconds;
        if (behind_ns > 0) p.counters.noteBehind(@intCast(behind_ns));
        if (p.deadline_ns == 0 or behind_ns <= p.deadline_ns) return false;
        noteDeadline(p);
        switch (origin) {
            .schedule => |send_index| send_index.* += 1,
            // Already off the queue; shedding it is dropping it.
            .retry => {},
        }
        return true;
    }

    /// Publish the stream, arm its deadline, and write the request on it.
    /// False when the connection can carry nothing more.
    fn send(mux: *Mux, slot: *Slot, origin: Origin) bool {
        const p = mux.p;
        const io = mux.io;

        // Held across the registration as well as the write. The receiver needs
        // `state` to act on a frame, and `state` is taken here before the
        // HEADERS leaves — so the response to this stream cannot be read back
        // before the table knows whose it is.
        mux.write.lockUncancelable(io);
        defer mux.write.unlock(io);

        const sent = now(io);
        const stream = blk: {
            mux.state.lockUncancelable(io);
            defer mux.state.unlock(io);
            // The connection can die between acquiring this slot and reaching
            // here — `shed` yields, and `fail` reclaims every open slot. Then
            // this slot is somebody else's (or nobody's) and must not be
            // written into.
            if (!slot.busy or mux.dead) {
                // A retry is already off the queue, and the schedule has no
                // index to resume it from: put it back for the next connection.
                switch (origin) {
                    .retry => |entry| mux.retry.push(entry),
                    .schedule => {},
                }
                break :blk 0;
            }
            slot.stream = mux.session.peekStream();
            // Both bounds are absolute timestamps — the wire timeout from the
            // actual send, the CO abort from `scheduled` — so the earlier one
            // binds and the two collapse into a single deadline.
            const wire: u64 = if (p.timeout_ns != 0)
                @as(u64, @intCast(sent.nanoseconds)) + p.timeout_ns
            else
                0;
            const co: u64 = if (p.deadline_abort and p.deadline_ns != 0)
                @as(u64, @intCast(slot.scheduled.nanoseconds)) + p.deadline_ns
            else
                0;
            slot.deadline_co = co != 0 and (wire == 0 or co <= wire);
            slot.deadline_ns = if (slot.deadline_co) co else wire;
            break :blk slot.stream;
        };
        // Nothing was sent and no index was consumed, so the schedule simply
        // resumes here on the next connection.
        if (stream == 0) return false;

        switch (origin) {
            .schedule => |send_index| send_index.* += 1,
            .retry => {},
        }

        _ = mux.session.beginStream(p.request_block, p.body) catch |err| {
            mux.state.lockUncancelable(io);
            defer mux.state.unlock(io);
            // The stream never opened, so nothing will ever close it — unless
            // `fail` already reclaimed the slot while this write was parked, in
            // which case the request has been charged once already and charging
            // it again would double-count one send as two errors.
            if (slot.busy and slot.stream == stream) {
                // A refusal to open — a GOAWAY that landed after `acquire` —
                // sent no request, so it goes out on the next connection
                // rather than being dropped. A broken write is a failure.
                if (err == error.Closed) {
                    mux.retry.push(.{ .scheduled = slot.scheduled, .retried = slot.retried });
                    mux.release(slot);
                } else {
                    mux.release(slot);
                    if (!mux.retiring) noteError(p, .write);
                }
            }
            mux.dead = true;
            mux.slot_free.broadcast(io);
            return false;
        };
        return true;
    }
};

/// Drive one multiplexed connection until it dies or the run ends.
///
/// `anchor` and `send_index` are the connection's, not this call's: they
/// survive a reconnect so a stall is caught up rather than reset, exactly as
/// they do around the serial loop.
fn runMultiplexed(
    p: *Params,
    io: Io,
    session: *h2conn.Session,
    anchor: *?Io.Timestamp,
    send_index: *u64,
    retry: *RetryQueue,
) void {
    // The peer's SETTINGS arrived during `open`, so its concurrency limit is
    // known before the first send instead of discovered by overshooting it.
    // Honouring it is not politeness: streams past the limit do not fail, they
    // queue inside the connection, and a client that believes it has N in
    // flight while the peer allows ten is timing its own queue and calling it
    // the server's. (h2load does not honour it; see docs/multiplexing.md.)
    const depth = @min(@min(p.streams, streams_max), @max(session.peer_max_concurrent_streams, 1));

    var slot_storage: [streams_max]Slot = @splat(.{});
    var mux: Mux = .{
        .io = io,
        .p = p,
        .session = session,
        .slots = slot_storage[0..depth],
        .retry = retry,
    };

    var group: Io.Group = .init;
    defer group.cancel(io);
    // Without a receiver nothing can ever complete, so a connection that cannot
    // start one is not worth sending on.
    group.concurrent(io, muxReceive, .{&mux}) catch return;
    // No bound to enforce, no watcher.
    if (p.timeout_ns != 0 or (p.deadline_abort and p.deadline_ns != 0))
        group.concurrent(io, muxWatch, .{&mux}) catch {};

    muxSend(&mux, anchor, send_index);

    // Stop sending, then let what is already on the wire land. Every open
    // stream ends one of three ways — a response, its wire timeout, or its CO
    // deadline — so this terminates on its own. The run's own teardown cancels
    // it sooner, and the few streams still open then are dropped; see
    // `Mux.retiring`.
    {
        while (true) {
            {
                mux.state.lockUncancelable(io);
                defer mux.state.unlock(io);
                if (mux.active == 0 or mux.dead) break;
            }
            io.sleep(Io.Duration.fromMicroseconds(200), .awake) catch break;
        }
    }
    mux.retire();
}

/// The sender: solve the schedule, pace to it, and put the request on a stream.
///
/// Structurally the serial request loop with the blocking exchange taken out of
/// the middle. Every step it shares with that loop — anchoring, the closed-form
/// offset, the lag gauge, deadline shedding, the pacing sleep — means what it
/// meant there.
fn muxSend(mux: *Mux, anchor: *?Io.Timestamp, send_index: *u64) void {
    const p = mux.p;
    const io = mux.io;

    while (!p.stop.load(.monotonic)) {
        const t = now(io);
        if (t.nanoseconds >= p.end.nanoseconds) return;

        // A request the peer declined goes first, at the time it was scheduled
        // for: it is older than anything the schedule has due. Only this
        // coroutine takes from the queue, so what it saw there is still there
        // once it holds a slot.
        if (mux.hasRetry()) {
            const slot = mux.acquire() orelse return;
            const entry = blk: {
                mux.state.lockUncancelable(io);
                defer mux.state.unlock(io);
                break :blk mux.retry.pop().?;
            };
            if (mux.shed(entry.scheduled, now(io), .{ .retry = entry })) {
                mux.state.lockUncancelable(io);
                defer mux.state.unlock(io);
                mux.release(slot);
                continue;
            }
            slot.scheduled = entry.scheduled;
            slot.retried = entry.retried;
            if (!mux.send(slot, .{ .retry = entry })) return;
            continue;
        }

        // Closed loop has no schedule to solve: the send is intended for
        // whenever a stream frees, so the slot is taken first and `scheduled`
        // read off the clock after. That degenerately zeroes the pacing wait,
        // the deadline check and the CO correction, leaving genuine round-trip
        // latency — the same trick the serial path plays, now with N loops per
        // connection instead of one.
        if (p.schedule == .closed) {
            const slot = mux.acquire() orelse return;
            slot.scheduled = now(io);
            if (!mux.send(slot, .{ .schedule = send_index })) return;
            continue;
        }

        // Anchor on the first send; each send's intended time is a closed-form
        // function of its index (constant or ramp), never of any response.
        if (anchor.* == null) anchor.* = t;
        const offset = p.schedule.offsetNs(send_index.*, p.phase);
        const scheduled = anchor.*.?.addDuration(Io.Duration.fromNanoseconds(@intCast(offset)));

        if (mux.shed(scheduled, t, .{ .schedule = send_index })) continue;

        // Pace: ahead of schedule, wait; behind, fire immediately.
        if (scheduled.nanoseconds > t.nanoseconds) {
            const wait = Io.Duration.fromNanoseconds(scheduled.nanoseconds - t.nanoseconds);
            io.sleep(wait, .awake) catch return;
        }

        const slot = mux.acquire() orelse return;

        // Waiting for a stream is itself schedule lag, and it is precisely the
        // lag `--streams` exists to remove: at 1 every send waits for the
        // previous response, at N only a connection already N deep waits at
        // all. Charge it, and re-test the deadline against it — a request that
        // spent its whole deadline queued here is shed rather than sent stale.
        if (mux.shed(scheduled, now(io), .{ .schedule = send_index })) {
            mux.state.lockUncancelable(io);
            defer mux.state.unlock(io);
            mux.release(slot);
            continue;
        }

        slot.scheduled = scheduled;
        if (!mux.send(slot, .{ .schedule = send_index })) return;
    }
}

/// The receiver: read every frame the peer sends and fold it into the stream it
/// belongs to. The only coroutine that touches the reader.
fn muxReceive(mux: *Mux) void {
    const io = mux.io;
    const session = mux.session;

    // The connection-level replacement for `frames_per_exchange_max`: this loop
    // never finishes, so what it bounds is frames that finish *nothing*. An
    // endless SETTINGS or PING flood is the case it exists for.
    var idle_frames: u32 = 0;

    while (idle_frames < h2conn.frames_without_progress_max) {
        const incoming = session.receive() catch {
            mux.fail(.read);
            return;
        };

        const progressed = switch (incoming) {
            .headers => |head| deliverToSlot(mux, head.stream, head.status, head.bytes, head.end_stream),
            .data => |data| deliverToSlot(mux, data.stream, null, data.bytes, data.end_stream),
            .reset => |stream| blk: {
                resetOneSlot(mux, stream);
                break :blk true;
            },
            .refused => |stream| blk: {
                mux.state.lockUncancelable(io);
                defer mux.state.unlock(io);
                if (mux.find(stream)) |slot| mux.requeue(slot);
                break :blk true;
            },
            // Recorded, not sent: `flushOwed` below decides whether the
            // writer can be had without stalling the read.
            .reply => |owed| blk: {
                switch (owed) {
                    .settings_ack => mux.owed_settings_ack = true,
                    .ping_ack => mux.owed_ping = owed,
                }
                break :blk false;
            },
            // Open streams up to the last one the peer took may still finish;
            // the rest are retried, and the sender stops opening new ones.
            .going_away => blk: {
                mux.state.lockUncancelable(io);
                defer mux.state.unlock(io);
                mux.goAway();
                break :blk false;
            },
            .idle => false,
        };
        idle_frames = if (progressed) 0 else idle_frames + 1;

        // Acks the peer is waiting on, and the connection window before its
        // budget runs out. Outside the state lock, and outside the read that
        // produced the debt.
        if (!mux.flushOwed()) {
            mux.fail(.write);
            return;
        }
    }
    mux.fail(.read);
}

/// The watchdog: abandon each stream that outlives its bound, and *only* that
/// stream.
///
/// This is the whole difference from the serial path. There, a timeout is a
/// `stream.shutdown` — abandoning the request and the connection in one act,
/// which is exact when they hold one request between them. Here the same act
/// would take every other in-flight sample with it, so the bound is spent on a
/// RST_STREAM instead and the other N − 1 responses go on arriving.
fn muxWatch(mux: *Mux) void {
    const io = mux.io;
    const p = mux.p;

    // How long to wait before re-checking with nothing on the wire. A quarter
    // of the shortest bound this watcher can be asked to enforce, so an idle
    // stretch can never oversleep a deadline armed just after it began. Taking
    // the wire timeout alone would not do: `--timeout 30s --deadline 100ms
    // --deadline-abort` would idle for 7.5 s and overshoot the bound it is
    // there to hold by seventy-five times.
    const wire_bound = p.timeout_ns;
    const co_bound = if (p.deadline_abort) p.deadline_ns else 0;
    const bound = if (wire_bound != 0 and co_bound != 0)
        @min(wire_bound, co_bound)
    else if (wire_bound != 0)
        wire_bound
    else
        co_bound;
    const idle_slice_ns: u64 = @max(bound / 4, std.time.ns_per_ms);

    var expired: [streams_max]u31 = undefined;

    while (true) {
        var earliest: u64 = 0;
        {
            mux.state.lockUncancelable(io);
            defer mux.state.unlock(io);
            if (mux.dead) return;
            for (mux.slots) |*slot| {
                if (slot.stream == 0 or slot.deadline_ns == 0) continue;
                if (earliest == 0 or slot.deadline_ns < earliest) earliest = slot.deadline_ns;
            }
        }

        const t = now(io);
        const wait_ns: u64 = if (earliest == 0)
            idle_slice_ns
        else if (@as(i128, earliest) > t.nanoseconds)
            @intCast(@as(i128, earliest) - t.nanoseconds)
        else
            0;
        if (wait_ns > 0) io.sleep(Io.Duration.fromNanoseconds(wait_ns), .awake) catch return;

        var count: usize = 0;
        {
            mux.state.lockUncancelable(io);
            defer mux.state.unlock(io);
            if (mux.dead) return;
            const at = now(io).nanoseconds;
            for (mux.slots) |*slot| {
                if (slot.stream == 0 or slot.deadline_ns == 0) continue;
                if (@as(i128, slot.deadline_ns) > at) continue;
                expired[count] = slot.stream;
                count += 1;
                // Freed before the reset goes out, which is what keeps the
                // other samples intact: the receiver carries on delivering
                // their frames, and this stream's own late frames now find no
                // slot and are ignored.
                const scheduled = slot.scheduled;
                const co = slot.deadline_co;
                mux.release(slot);
                if (co) noteDeadline(p) else noteTimeout(p, io, scheduled);
            }
        }

        for (expired[0..count]) |stream| {
            mux.write.lockUncancelable(io);
            defer mux.write.unlock(io);
            mux.session.resetStream(stream) catch {
                mux.fail(.write);
                return;
            };
        }
    }
}

/// Fold one frame into the stream it belongs to. Returns whether it belonged to
/// a stream still open, which is what `muxReceive`'s no-progress bound counts.
///
/// Belonging, not finishing. A 16 KiB-framed response of any size is hundreds
/// of DATA frames that end nothing, and counting only completions would make
/// the bound scale as 1/depth: at `-s 8`, eight interleaved multi-megabyte
/// responses reach it before any of them ends, and a healthy connection would
/// be killed for being busy. What the bound is actually for is a peer that
/// sends endlessly and delivers nothing — SETTINGS, PING, frames for streams
/// long retired — and none of those land in a slot.
fn deliverToSlot(mux: *Mux, stream: u31, status: ?u16, bytes: u64, end_stream: bool) bool {
    mux.state.lockUncancelable(mux.io);
    defer mux.state.unlock(mux.io);
    const slot = mux.find(stream) orelse return false;
    if (status) |code| {
        // Two blocks each carrying a `:status` is malformed (RFC 9113 section
        // 8.3.2): one stream's request is lost, and only that one — the
        // connection and every other stream on it are fine.
        if (slot.status != null) {
            mux.release(slot);
            noteError(mux.p, .read);
            return true;
        }
        slot.status = code;
    }
    slot.bytes += bytes;
    if (end_stream) mux.complete(slot);
    return true;
}

/// The peer reset one stream (section 6.4). That request is lost; the
/// connection and every other stream on it are not — which is the difference
/// from the serial path, where the same frame ends the connection because there
/// is nothing else on it to keep.
fn resetOneSlot(mux: *Mux, stream: u31) void {
    mux.state.lockUncancelable(mux.io);
    defer mux.state.unlock(mux.io);
    const slot = mux.find(stream) orelse return;
    mux.release(slot);
    noteError(mux.p, .read);
}

/// Send the fixed request and parse one response; touches only the
/// transport, never the shared counters.
fn performWork(
    p: *Params,
    app_reader: *Io.Reader,
    app_writer: *Io.Writer,
    session: ?*h2conn.Session,
) WorkResult {
    if (session) |active| return performWorkHttp2(p, active);
    app_writer.writeAll(p.request) catch return .write_failed;
    // One flush is enough: the TLS writer in `tls.zig` seals *and* writes the
    // records to the socket handle itself, where `std.crypto.tls` only
    // encrypted into the socket writer's buffer and needed a second flush
    // behind it.
    app_writer.flush() catch return .write_failed;
    const resp = httpmod.parseResponse(app_reader, p.method) catch return .read_failed;
    return .{ .ok = resp };
}

/// The HTTP/2 half of `performWork`.
///
/// Same shape and the same two failure kinds, because the caller's accounting
/// is the same: a write that never left is a write error, and a response that
/// never arrived is a read error. Which of h2's protocol failures is which
/// matters only for the counter it lands in, and a `Protocol` error is a
/// response we could not read.
fn performWorkHttp2(p: *Params, session: *h2conn.Session) WorkResult {
    const resp = session.exchange(p.request_block, p.body) catch |err| switch (err) {
        error.Io => return .read_failed,
        // GOAWAY, or a stream the peer reset: the connection is finished but
        // the transport did not fail. Counted as a read error for the same
        // reason an HTTP/1.1 server closing mid-response is.
        error.Closed => return .read_failed,
        error.Refused => return .refused,
        error.Protocol, error.TooLarge => return .read_failed,
    };
    return .{ .ok = resp };
}

/// Whether ALPN settled on `want`. Null means the peer selected nothing, which
/// for an `h2` offer is a refusal rather than a default.
fn alpnIs(selected: ?[]const u8, want: []const u8) bool {
    const chosen = selected orelse return false;
    return std.mem.eql(u8, chosen, want);
}

pub fn now(io: Io) Io.Timestamp {
    return Io.Timestamp.now(io, .awake);
}

/// Which socket-level counter a failure lands in. Named rather than anonymous
/// because the multiplexed path decides the kind in one place and reports it in
/// another.
pub const ErrorKind = enum { connect, write, read };

/// Record a socket error, unless we are shutting down — errors caused by
/// cancelling in-flight I/O at end-of-test are artifacts, not real failures.
/// Publishes so the live dashboard sees error-only periods (a total outage
/// produces no successful responses to publish through).
pub fn noteError(p: *Params, kind: ErrorKind) void {
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
pub fn noteTimeout(p: *Params, io: Io, scheduled: Io.Timestamp) void {
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
pub fn noteDeadline(p: *Params) void {
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
pub fn maybePublish(p: *Params, now_ns: i128) void {
    const pub_ptr = p.publish orelse return;
    pub_ptr.mutex.lockUncancelable(p.io);
    defer pub_ptr.mutex.unlock(p.io);
    pub_ptr.counters = p.counters.*;
    if (now_ns >= pub_ptr.next_ns) {
        p.histogram.copyInto(pub_ptr.hist);
        pub_ptr.next_ns = now_ns + @as(i128, @intCast(pub_ptr.interval_ns));
    }
}

/// The connect timeout to apply: the shorter of the per-request wire timeout
/// (`0` = none) and the time left until the run's `end`. Always nonzero given a
/// positive `remaining_ns`, so connect can never outlast the test even when no
/// wire timeout is configured.
fn deadlineBoundedTimeout(wire_timeout_ns: u64, remaining_ns: u64) u64 {
    if (wire_timeout_ns != 0 and wire_timeout_ns < remaining_ns) return wire_timeout_ns;
    return remaining_ns;
}

/// Turn Nagle's algorithm off on a socket zrk measures through.
///
/// Nagle holds a small write back until the previous one has been
/// acknowledged, and Linux delays that acknowledgement by up to 40 ms. With one
/// request in flight the two can barely collide: nothing of ours is
/// unacknowledged at the moment the next request is written, because the
/// response that acknowledged it is what released the next send. Multiplexing
/// makes them collide by design — a second request written while the first is
/// still outstanding is the entire point of `--streams` — and Nagle answers it
/// by parking that request until a delayed-ACK timer expires. Left on, it puts
/// 40 ms of the client's own transport behaviour into the target's latency,
/// which is the exact failure this tool exists not to have.
///
/// Best effort: a transport that will not take the option is not a reason to
/// abandon the connection.
fn disableNagle(stream: net.Stream) void {
    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        &std.mem.toBytes(@as(c_int, 1)),
    ) catch {};
}

fn connect(io: Io, address: net.IpAddress, timeout_ns: u64) !net.Stream {
    // The response timeout is enforced per-request by `watchTimer`.
    const timeout: Io.Timeout = if (timeout_ns != 0) .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(timeout_ns), .clock = .awake } } else .none;
    return address.connect(io, .{ .mode = .stream, .timeout = timeout });
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;
const zio = @import("zio");
const h2 = @import("h2");
const cli = @import("cli.zig");

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

/// A minimal h2c server: read the preface and SETTINGS, then answer every
/// request stream with a 200 and a two-octet body.
///
/// Built on the same `h2` codec the client uses, which is the point — this test
/// is about whether `run` drives a real socket end to end under `--http2`, not
/// about whether the codec agrees with itself. The unit tests in `h2conn.zig`
/// cover the protocol; this covers the wiring.
fn h2Serve(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    disableNagle(stream);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const reader = &r.interface;
    const writer = &w.interface;

    // The client sends the preface first (RFC 9113 section 3.4).
    const magic = reader.take(h2conn.preface.len) catch return;
    if (!std.mem.eql(u8, magic, h2conn.preface)) return;

    // Our SETTINGS, empty: the defaults are fine for a test server.
    writeTestFrame(writer, .settings, 0, 0, &.{}) catch return;
    writer.flush() catch return;

    // One 200 response block, encoded once — the same trick the client uses.
    var block: [64]u8 = undefined;
    var storage: h2.hpack.Encoder.Storage(0) = .{};
    var encoder = storage.encoder(.static_only);
    const encoded = encoder.encode(&block, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    });

    while (true) {
        const octets = reader.take(h2.frame.Header.octets) catch return;
        const header = h2.frame.Header.parse(octets) catch return;
        const payload = if (header.length > 0)
            reader.take(header.length) catch return
        else
            &[_]u8{};
        _ = payload;

        switch (header.frame_type) {
            .settings => if (!header.has(.ack)) {
                writeTestFrame(writer, .settings, h2.frame.Flag.ack.bit(), 0, &.{}) catch return;
                writer.flush() catch return;
            },
            .headers => {
                // Answer on the stream the request opened.
                writeTestFrame(
                    writer,
                    .headers,
                    h2.frame.Flag.end_headers.bit(),
                    header.stream_identifier,
                    block[0..encoded.written],
                ) catch return;
                writeTestFrame(
                    writer,
                    .data,
                    h2.frame.Flag.end_stream.bit(),
                    header.stream_identifier,
                    "hi",
                ) catch return;
                writer.flush() catch return;
            },
            // Window updates and everything else need no answer from a server
            // that sends two octets per response.
            else => {},
        }
    }
}

fn writeTestFrame(
    writer: *Io.Writer,
    frame_type: h2.frame.Type,
    flags: u8,
    stream: u31,
    payload: []const u8,
) !void {
    const header: h2.frame.Header = .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_identifier = stream,
    };
    var octets: [h2.frame.Header.octets]u8 = undefined;
    _ = try header.render(&octets);
    try writer.writeAll(&octets);
    if (payload.len > 0) try writer.writeAll(payload);
}

test "run drives HTTP/2 requests against a local h2c server" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, h2Serve, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    // The request block, built the way the runner builds it.
    var cfg: cli.Config = .{ .http2 = true };
    cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
    const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
    defer testing.allocator.free(block);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(200));

    var params: Params = .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "",
        .request_block = block,
        .http2 = true,
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        // A wire timeout, unlike the HTTP/1.1 tests above, and for a reason
        // worth stating: those drive a server that always answers, so a broken
        // client would fail on the assertions. A client that stops speaking
        // HTTP/2 correctly gets no answer at all, and with no timeout the read
        // blocks until the process is killed. Discovered by mutating
        // `performWork` to ignore the session: the suite hung instead of
        // failing. A gate that hangs is worse than one that fails.
        .timeout_ns = 20 * std.time.ns_per_ms,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    try testing.expect(counters.completed > 0);
    // Nothing timed out on the happy path, which is what makes the timeout
    // above a safety net rather than part of the measurement.
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.status_errors);
    try testing.expectEqual(@as(u64, 0), counters.write_errors);
    try testing.expectEqual(@as(u64, 0), counters.connect_errors);
    // Every completed request is a recorded latency sample, exactly as over
    // HTTP/1.1 — which is the property the HTTP/2 path exists to preserve.
    try testing.expectEqual(counters.completed, histogram.count());
    // Two octets of body plus the response header block, per request.
    try testing.expect(counters.bytes >= counters.completed * 2);
    try testing.expectEqual(counters.completed, counters.status_class[2]);
}

/// Read the preface and answer SETTINGS, leaving the caller the frame loop.
/// Shared by the three h2c test servers below.
fn h2Greet(reader: *Io.Reader, writer: *Io.Writer) bool {
    const magic = reader.take(h2conn.preface.len) catch return false;
    if (!std.mem.eql(u8, magic, h2conn.preface)) return false;
    // Our SETTINGS, empty: the defaults are fine for a test server.
    writeTestFrame(writer, .settings, 0, 0, &.{}) catch return false;
    writer.flush() catch return false;
    return true;
}

/// Answer one stream with a 200 and two octets of body.
fn h2Answer(writer: *Io.Writer, block: []const u8, stream: u31) bool {
    writeTestFrame(writer, .headers, h2.frame.Flag.end_headers.bit(), stream, block) catch return false;
    writeTestFrame(writer, .data, h2.frame.Flag.end_stream.bit(), stream, "hi") catch return false;
    writer.flush() catch return false;
    return true;
}

/// The 200 response block every test server sends, encoded once.
fn h2ResponseBlock(buffer: []u8) []const u8 {
    var storage: h2.hpack.Encoder.Storage(0) = .{};
    var encoder = storage.encoder(.static_only);
    const encoded = encoder.encode(buffer, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    });
    return buffer[0..encoded.written];
}

/// An h2c server that answers request *k* only once request *k+1* has arrived.
///
/// A client that cannot hold two streams open at once therefore never gets a
/// single response out of it: it sends, waits, and the answer it is waiting for
/// is gated on a request it cannot send until the answer comes. That deadlock
/// is the point — it makes "two requests really were in flight at once" a thing
/// a test can assert without measuring time.
fn h2LockstepServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    disableNagle(stream);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const reader = &r.interface;
    const writer = &w.interface;
    if (!h2Greet(reader, writer)) return;

    var block_buf: [64]u8 = undefined;
    const block = h2ResponseBlock(&block_buf);

    var held: ?u31 = null;
    while (true) {
        const octets = reader.take(h2.frame.Header.octets) catch return;
        const header = h2.frame.Header.parse(octets) catch return;
        if (header.length > 0) _ = reader.take(header.length) catch return;

        switch (header.frame_type) {
            .settings => if (!header.has(.ack)) {
                writeTestFrame(writer, .settings, h2.frame.Flag.ack.bit(), 0, &.{}) catch return;
                writer.flush() catch return;
            },
            .headers => {
                if (held) |earlier| {
                    if (!h2Answer(writer, block, earlier)) return;
                }
                held = header.stream_identifier;
            },
            else => {},
        }
    }
}

/// An h2c server that answers every stream except the client's first, which it
/// holds open forever — and counts the RST_STREAMs it is sent.
///
/// The multiplexed timeout path in one server. With one stream per connection
/// the only way to abandon a stalled request is to drop the connection, and
/// every other in-flight sample goes with it; the whole of what `--streams`
/// changes here is that the bound is spent on a RST_STREAM instead.
fn h2StallServe(io: Io, server: *net.Server, resets: *std.atomic.Value(u32)) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    disableNagle(stream);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const reader = &r.interface;
    const writer = &w.interface;
    if (!h2Greet(reader, writer)) return;

    var block_buf: [64]u8 = undefined;
    const block = h2ResponseBlock(&block_buf);

    while (true) {
        const octets = reader.take(h2.frame.Header.octets) catch return;
        const header = h2.frame.Header.parse(octets) catch return;
        if (header.length > 0) _ = reader.take(header.length) catch return;

        switch (header.frame_type) {
            .settings => if (!header.has(.ack)) {
                writeTestFrame(writer, .settings, h2.frame.Flag.ack.bit(), 0, &.{}) catch return;
                writer.flush() catch return;
            },
            // Section 5.1.1: the client's first stream is 1. Held open, never
            // answered, never reset from this side.
            .headers => if (header.stream_identifier != 1) {
                if (!h2Answer(writer, block, header.stream_identifier)) return;
            },
            .rst_stream => _ = resets.fetchAdd(1, .monotonic),
            else => {},
        }
    }
}

/// The `Params` the multiplexed tests share, minus the parts each one varies.
fn muxParams(
    io: Io,
    server_addr: net.IpAddress,
    block: []const u8,
    streams: u32,
    end: Io.Timestamp,
    timeout_ns: u64,
    stop: *std.atomic.Value(bool),
    histogram: *hdr.Histogram,
    counters: *Counters,
) Params {
    return .{
        .io = io,
        .address = server_addr,
        .host = "127.0.0.1",
        .request = "",
        .request_block = block,
        .http2 = true,
        .streams = streams,
        .is_tls = false,
        .insecure = false,
        .schedule = .{ .constant = .{ .interval_ns = 2 * std.time.ns_per_ms } },
        .timeout_ns = timeout_ns,
        .end = end,
        .stop = stop,
        .histogram = histogram,
        .counters = counters,
    };
}

test "streams put more than one request on the wire at once" {
    // The assertion is structural, not timed: `h2LockstepServe` will not answer
    // a request until the *next* one has arrived, so a completed response is
    // proof that two streams were open together. At `--streams 1` this same
    // server produces nothing but timeouts, which is the case below it.
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, h2LockstepServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    var cfg: cli.Config = .{ .http2 = true };
    cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
    const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
    defer testing.allocator.free(block);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(300));
    var params = muxParams(io, server_addr, block, 4, end, 50 * std.time.ns_per_ms, &stop, &histogram, &counters);
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    try testing.expect(counters.completed > 1);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.write_errors);
    try testing.expectEqual(@as(u64, 0), counters.status_errors);
    // The server holds one request back by construction, so the stream still
    // open when the run ends has nothing to answer it: exactly one bound blows.
    try testing.expect(counters.timeouts <= 1);
    // Timed-out requests are recorded too (`record_timeouts` defaults on), so
    // they count here.
    try testing.expectEqual(counters.completed + counters.timeouts, histogram.count());
}

test "a stalled stream is reset alone, leaving the other samples intact" {
    // The whole difference between the multiplexed path and the serial one.
    // The serial path answers a stalled request by shutting the socket down,
    // which is exact when the connection holds one request and destroys N − 1
    // innocent samples when it holds N. Here the bound is spent on a RST_STREAM
    // for the one stream that blew it, and the connection carries on measuring.
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var resets = std.atomic.Value(u32).init(0);
    var group: Io.Group = .init;
    group.async(io, h2StallServe, .{ io, &server, &resets });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    var cfg: cli.Config = .{ .http2 = true };
    cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
    const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
    defer testing.allocator.free(block);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(400));
    var params = muxParams(io, server_addr, block, 4, end, 40 * std.time.ns_per_ms, &stop, &histogram, &counters);
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Exactly one stream stalled, so exactly one bound blew.
    try testing.expectEqual(@as(u64, 1), counters.timeouts);
    // And it was abandoned by resetting that stream, not the connection: the
    // server saw the RST_STREAM, and never had to re-accept.
    try testing.expectEqual(@as(u32, 1), resets.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), counters.connect_errors);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.write_errors);
    // The samples that had nothing to do with it survived — many of them, and
    // still arriving after the reset.
    try testing.expect(counters.completed > 5);
    // `record_timeouts` is on by default, so the abandoned request is a sample
    // too; every other completion is one, and nothing else is.
    try testing.expectEqual(counters.completed + counters.timeouts, histogram.count());
}

/// An h2c server that ends every response with a trailers section.
///
/// Legal (RFC 9113 section 8.1) and routine — gRPC does nothing else — and a
/// shape that has to be handled on its own terms: a second field block carries
/// no `:status`, and decoding it as though it must would fail the whole
/// connection and take every other in-flight stream's sample with it.
fn h2TrailerServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    disableNagle(stream);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const reader = &r.interface;
    const writer = &w.interface;
    if (!h2Greet(reader, writer)) return;

    var block_buf: [64]u8 = undefined;
    const block = h2ResponseBlock(&block_buf);

    var trailer_buf: [64]u8 = undefined;
    var storage: h2.hpack.Encoder.Storage(0) = .{};
    var encoder = storage.encoder(.static_only);
    const encoded = encoder.encode(&trailer_buf, &.{
        .{ .name = "grpc-status", .value = "0" },
    });
    const trailers = trailer_buf[0..encoded.written];

    while (true) {
        const octets = reader.take(h2.frame.Header.octets) catch return;
        const header = h2.frame.Header.parse(octets) catch return;
        if (header.length > 0) _ = reader.take(header.length) catch return;

        switch (header.frame_type) {
            .settings => if (!header.has(.ack)) {
                writeTestFrame(writer, .settings, h2.frame.Flag.ack.bit(), 0, &.{}) catch return;
                writer.flush() catch return;
            },
            .headers => {
                const id = header.stream_identifier;
                const end_headers = h2.frame.Flag.end_headers.bit();
                writeTestFrame(writer, .headers, end_headers, id, block) catch return;
                writeTestFrame(writer, .data, 0, id, "hi") catch return;
                // The trailers section, ending the stream.
                writeTestFrame(
                    writer,
                    .headers,
                    end_headers | h2.frame.Flag.end_stream.bit(),
                    id,
                    trailers,
                ) catch return;
                writer.flush() catch return;
            },
            else => {},
        }
    }
}

test "a response ending in trailers completes, and takes no other stream down" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, h2TrailerServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    var cfg: cli.Config = .{ .http2 = true };
    cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
    const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
    defer testing.allocator.free(block);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(200));
    var params = muxParams(io, server_addr, block, 4, end, 50 * std.time.ns_per_ms, &stop, &histogram, &counters);
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Trailers end the stream normally: the status from the first block stands.
    try testing.expect(counters.completed > 5);
    try testing.expectEqual(counters.completed, counters.status_class[2]);
    try testing.expectEqual(@as(u64, 0), counters.read_errors);
    try testing.expectEqual(@as(u64, 0), counters.status_errors);
    try testing.expectEqual(@as(u64, 0), counters.timeouts);
    try testing.expectEqual(counters.completed, histogram.count());
}

/// An h2c server that answers a dozen requests and then drops the connection,
/// serving one connection and returning.
///
/// Kills a connection with several streams open and the sender very likely
/// parked inside a write, so the receiver's teardown and the sender's own error
/// path race over the same slot. Getting that wrong takes `active` below zero
/// (a panic under ReleaseSafe) or charges one send as two errors.
///
/// One connection and then return, rather than an accept loop: a coroutine
/// parked in `accept` has to be cancelled to be joined, and a test that has to
/// cancel its own server is a test that hangs when cancellation does not reach
/// that far.
fn h2DropServe(io: Io, server: *net.Server) void {
    var stream = server.accept(io) catch return;
    defer stream.close(io);
    disableNagle(stream);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var w = stream.writer(io, &wbuf);
    const reader = &r.interface;
    const writer = &w.interface;
    if (!h2Greet(reader, writer)) return;

    var block_buf: [64]u8 = undefined;
    const block = h2ResponseBlock(&block_buf);

    var served: u32 = 0;
    while (served < 12) {
        const octets = reader.take(h2.frame.Header.octets) catch return;
        const header = h2.frame.Header.parse(octets) catch return;
        if (header.length > 0) _ = reader.take(header.length) catch return;
        switch (header.frame_type) {
            .settings => if (!header.has(.ack)) {
                writeTestFrame(writer, .settings, h2.frame.Flag.ack.bit(), 0, &.{}) catch return;
                writer.flush() catch return;
            },
            .headers => {
                if (!h2Answer(writer, block, header.stream_identifier)) return;
                served += 1;
            },
            else => {},
        }
    }
}

test "a connection dying with streams open charges each request once" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    var group: Io.Group = .init;
    group.async(io, h2DropServe, .{ io, &server });

    var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer histogram.deinit();
    var counters: Counters = .{};
    var stop = std.atomic.Value(bool).init(false);

    var cfg: cli.Config = .{ .http2 = true };
    cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
    const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
    defer testing.allocator.free(block);

    const start = Io.Timestamp.now(io, .awake);
    const end = start.addDuration(Io.Duration.fromMilliseconds(250));
    var params = muxParams(io, server_addr, block, 8, end, 40 * std.time.ns_per_ms, &stop, &histogram, &counters);
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Reaching here at all is most of the assertion: releasing one slot twice
    // takes `active` below zero, which panics under ReleaseSafe.
    try testing.expect(counters.completed > 0);
    try testing.expectEqual(counters.completed + counters.timeouts, histogram.count());
    // The drop strands whatever was open, and each stranded request is charged
    // once. More read errors than the connection could hold streams would mean
    // the receiver and the sender both charged the same send.
    try testing.expect(counters.read_errors <= 8);
}

test "streams leave the offered load alone" {
    // `--streams` is a depth knob: it changes whether a due send has to wait
    // for the previous response, never what is due or when. Against a server
    // that answers instantly there is nothing to wait for, so the same schedule
    // must produce the same number of sends at any depth.
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var completed: [2]u64 = undefined;
    for ([_]u32{ 1, 8 }, 0..) |streams, index| {
        const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
        var server = try bind_addr.listen(io, .{ .reuse_address = true });
        const port = server.socket.address.getPort();
        const server_addr = try net.IpAddress.parse("127.0.0.1", port);

        var group: Io.Group = .init;
        group.async(io, h2Serve, .{ io, &server });

        var histogram = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
        defer histogram.deinit();
        var counters: Counters = .{};
        var stop = std.atomic.Value(bool).init(false);

        var cfg: cli.Config = .{ .http2 = true };
        cfg.url = .{ .scheme = .http, .host = "127.0.0.1", .port = port, .target = "/" };
        const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
        defer testing.allocator.free(block);

        const start = Io.Timestamp.now(io, .awake);
        const end = start.addDuration(Io.Duration.fromMilliseconds(200));
        var params = muxParams(io, server_addr, block, streams, end, 50 * std.time.ns_per_ms, &stop, &histogram, &counters);
        run(&params);

        group.await(io) catch {};
        server.deinit(io);

        try testing.expect(counters.completed > 0);
        try testing.expectEqual(counters.completed, histogram.count());
        try testing.expectEqual(@as(u64, 0), counters.read_errors);
        completed[index] = counters.completed;
    }

    // A 2 ms schedule over 200 ms is ~100 sends either way. Loose enough for a
    // loaded CI box, tight enough that a depth knob quietly become a rate knob
    // — the `-c × -s` reading this design rejected — would fail it.
    const serial: f64 = @floatFromInt(completed[0]);
    const deep: f64 = @floatFromInt(completed[1]);
    try testing.expect(deep < serial * 1.5);
    try testing.expect(deep > serial * 0.5);
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

test "closed schedule sends as fast as the server answers, never behind" {
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
        .schedule = .closed,
        .timeout_ns = 0,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    try testing.expect(counters.completed > 0);
    // testServe answers instantly over loopback, so an unthrottled connection
    // clears far more than the ~40 requests a 2ms-interval (~500 req/s)
    // schedule would allow in this same 200ms window (the sibling keep-alive
    // test above uses exactly that schedule) -- this is the property .closed
    // exists for: finding the real ceiling instead of being capped by one.
    try testing.expect(counters.completed > 40);
    // No independent schedule to fall behind: the backlog gauge stays at its
    // zero value, and no request is ever shed or aborted on that basis.
    try testing.expectEqual(@as(u64, 0), counters.max_behind_ns);
    try testing.expectEqual(@as(u64, 0), counters.deadline_errors);
    try testing.expectEqual(@as(u64, 0), counters.status_errors);
    // Every completed response is a recorded (round-trip, not CO-adjusted-
    // backward) latency sample, same invariant as the paced schedules above.
    try testing.expectEqual(counters.completed, histogram.count());
}

test "disable_keepalive retires the connection a keep-alive response would keep" {
    // `serveConn` answers with no `Connection` header at all, which over
    // HTTP/1.1 means keep-alive (zurl's parser defaults `keep_alive` to
    // `version == .@"1.1"`). It is therefore the exact case `-H 'Connection:
    // close'` cannot reach: a server that will happily go on reusing the
    // socket no matter what the request asked for. The flag has to win anyway,
    // or it does nothing for precisely the servers it was added to measure.
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    const port = server.socket.address.getPort();
    const server_addr = try net.IpAddress.parse("127.0.0.1", port);

    // One accepted connection for the whole test, as in the sibling tests: so
    // the SECOND request, if the client reconnects, has nobody to answer it.
    // That is what makes "did it reuse the socket?" a counter and not a guess.
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
        .request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        .is_tls = false,
        .insecure = false,
        .schedule = .closed,
        // Bounds the reconnects that follow the first response, so the run
        // reaches `end` instead of parking on a socket nobody is serving.
        .timeout_ns = 20 * std.time.ns_per_ms,
        .disable_keepalive = true,
        .end = end,
        .stop = &stop,
        .histogram = &histogram,
        .counters = &counters,
    };
    run(&params);

    group.await(io) catch {};
    server.deinit(io);

    // Exactly one: the connection the server served. Without the flag this
    // same setup completes dozens (see "closed schedule sends as fast as the
    // server answers", which is this test minus `disable_keepalive`).
    try testing.expectEqual(@as(u64, 1), counters.completed);
    // And it did keep going — it reconnected rather than stopping — which is
    // what distinguishes a retired connection from a dead run. The reconnects
    // land on a listener nobody is accepting from any more, so they time out
    // on the wire; that they are timeouts and not connect errors is the proof
    // the socket was re-established each time.
    try testing.expect(counters.timeouts > 0);
    try testing.expectEqual(@as(u64, 0), counters.connect_errors);
    // `record_timeouts` is on by default, so the histogram holds the timed-out
    // attempts alongside the one response — the tail is not silently dropped
    // just because the connection is being cycled.
    try testing.expectEqual(counters.completed + counters.timeouts, histogram.count());
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
    // The refused connects must be visible to the dashboard: if only successful
    // responses published, an unreachable target would show nothing.
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

test "the HTTP/2 retry queue gives requests back oldest first" {
    var queue: RetryQueue = .{};
    // Handed over in slot-table order, which a GOAWAY walks and which is not
    // the order the requests were scheduled in.
    queue.push(.{ .scheduled = .{ .nanoseconds = 300 }, .retried = true });
    queue.push(.{ .scheduled = .{ .nanoseconds = 100 }, .retried = true });
    queue.push(.{ .scheduled = .{ .nanoseconds = 200 }, .retried = false });

    try testing.expectEqual(@as(i96, 100), queue.pop().?.scheduled.nanoseconds);
    const second = queue.pop().?;
    try testing.expectEqual(@as(i96, 200), second.scheduled.nanoseconds);
    try testing.expect(!second.retried);
    try testing.expectEqual(@as(i96, 300), queue.pop().?.scheduled.nanoseconds);
    try testing.expectEqual(@as(?RetryQueue.Entry, null), queue.pop());
}
