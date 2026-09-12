//! One HTTP/3 connection, driven as a single-coroutine QUIC event loop.
//!
//! ## Why this is not `connection.zig` with a different codec
//!
//! The HTTP/1.1 and HTTP/2 paths share a shape: a `net.Stream`, a
//! `*Io.Reader`/`*Io.Writer` pair, and a request loop that blocks on the read
//! it is waiting for. Everything about that shape assumes the transport is
//! somebody else's problem — the kernel's TCP, and zssl's TLS over it.
//!
//! QUIC is the transport. `h3` is sans-I/O in the same way h2 and zssl are, but
//! what it declines is larger: it opens no socket, reads no clock, draws no
//! randomness and runs no TLS handshake. That means this file owns the loss
//! detector's timer, the acknowledgement schedule, and the deadline arithmetic
//! that decides when to wake — and none of that can sit behind a blocking read,
//! because a connection with nothing to receive still has to *send*: ACKs,
//! probes, retransmissions. A blocked read is a stalled congestion controller.
//!
//! So the loop here is the inversion of `connection.zig`'s. Rather than
//! blocking on a response and pacing between them, it computes the earliest of
//!
//!   * the next request's scheduled send time,
//!   * the QUIC loss/PTO timer,
//!   * the earliest in-flight request's `--timeout`/`--deadline` bound,
//!   * the run's own end,
//!
//! and sleeps in `receiveTimeout` until then. One coroutine per connection,
//! and no locks: unlike the HTTP/2 multiplexed path there is no second
//! coroutine to race with, because the socket read and the pacing wait are the
//! *same* wait.
//!
//! That is also why the numbers should be comparable. Every step the serial
//! path takes — anchoring the schedule, the closed-form offset, the lag gauge,
//! deadline shedding, the coordinated-omission correction measured from
//! `scheduled` rather than from the actual send — means exactly what it means
//! there, and is written here in the same order.
//!
//! ## What a prototype does not have yet
//!
//! * **No certificate verification.** `quic_tls.zig` says why, and `cli.zig`
//!   makes `--http3` require `--insecure` so no run can believe otherwise.
//!   Accepted rather than outstanding: a load generator is pointed at a target
//!   its operator chose, and the other two transports keep verification on by
//!   default for the case where that is not enough.
//! * **One datagram per syscall on the way out.** `flush` calls `socket.send`
//!   once per datagram. The way *in* is batched — see `enableOffload` — but
//!   the two are duals and only one of them is done: segmentation offload on
//!   this endpoint's send side is what would let a peer read a burst per
//!   syscall, and it is also the half that would cut *this* endpoint's own
//!   syscalls, which is the thing zoxy-io/zrk#74 asked about. It is not done
//!   because the mechanism is the easy part and the policy is not: offload
//!   only batches datagrams of equal size, and a QUIC client's egress is small
//!   request packets whose lengths jitter as varint widths change. Making the
//!   runs long means padding, and a load generator that inflates its own
//!   traffic is answering a different question than the one it was asked.
//!   zoxy-io/zrk#76 carries the argument and the measurement that settles it.
//! * **No connection migration, no 0-RTT, no session resumption.** A run that
//!   reconnects pays a full handshake every time.
//!
//! And one thing that *was* a gap and is not any more, kept here because the
//! symptom looked like this file's and was not: a multiplexed connection ran at
//! full rate for about a second and then went to zero req/s, with no errors, for
//! the rest of the run. `Connection.receiveAck` handed `Recovery` a fixed
//! 32-entry array for the acknowledged packets' contexts while `Recovery` tracks
//! `sent_max` of them and clamps its writes to the caller's slice, so an
//! acknowledgement retiring more than 32 packets — routine once the congestion
//! window has grown — reported a prefix. `Streams.acknowledge` was then never
//! called for the streams that did not fit: their send half stayed in "Data
//! Sent" for ever, they never retired, and since retirement walks a contiguous
//! watermark, one stranded stream pinned every stream above it until the table
//! was full. Fixed upstream by sizing the report from `sent_max`, which is the
//! only number that can bound it; the regression test is
//! `src/quic/Connection.zig`'s "one acknowledgement settles every stream it
//! retires, not the first 32", and the row is docs/VERIFICATION.md §1.
//! * **Fixed comptime limits.** `Connection` is a comptime-sized value —
//!   `footprint_octets` below is what one costs — so `--streams` cannot exceed
//!   `requests_max` and a request body cannot exceed the stream send buffer.
//!   `cli.zig` enforces both rather than letting them fail on the wire.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = std.Io.net;
const h3 = @import("h3");
const quic = h3.quic;

const cli = @import("cli.zig");
const conn = @import("connection.zig");
const httpmod = @import("http.zig");
const quic_tls = @import("quic_tls.zig");

/// Request streams this endpoint tracks at once, which is the ceiling on
/// `--streams` for an HTTP/3 run.
///
/// A limit rather than a policy: `Connection` and `Http3` are comptime-sized
/// values, so this number is spent whether or not a run uses it. See
/// `footprint_octets`.
pub const requests_max: u32 = 16;

/// RFC 9114 §6.2 and RFC 9204 §4.2: a control stream and QPACK's two, each
/// way, plus room for §6.2.3's reserved types to arrive without being an
/// error.
const unidirectional_max: u32 = 4;

/// The QUIC stream table, which is **not** `requests_max` and is not `2 ×` it
/// either.
///
/// Two things are being sized at once. RFC 9000 §3.2 makes an identifier at
/// index N mean N+1 streams of that kind exist, so whatever this endpoint
/// advertises is a claim the peer may make on the table all at once, and the
/// same again for what it opens itself; a table smaller than that answers a
/// conforming peer with `STREAM_LIMIT_ERROR`, which is this endpoint's sizing
/// mistake reported as the peer's protocol error.
///
/// The other thing is retirement lag, and it is the one that bites. A stream
/// leaves the table only when *both* halves are finished, and `Streams`
/// retires in identifier order from a contiguous watermark — so a response
/// that completed on stream 40 frees nothing while stream 4's own FIN is still
/// waiting to be acknowledged. Under load the set of "finished but not yet
/// retired" streams is several times the set of in-flight ones, and a table
/// sized for the in-flight set alone fills, refuses every new request, and
/// never drains: a 20-second soak at depth 32 collapsed from 60k req/s to zero
/// in about a second, and stayed there.
///
/// Four times the request ceiling is that headroom. It is a bound, not a
/// guarantee, which is why `issue` treats `TooManyStreams` as backpressure
/// rather than as a failed request — the table filling is this endpoint
/// running out of room, not the target doing anything wrong.
const streams_max: u32 = 4 * requests_max + 2 * unidirectional_max;

/// The two flow-control windows, per stream.
///
/// Deliberately smaller than `h3`'s own defaults (64 KiB and 16 KiB), because
/// they are multiplied by `streams_max` and then by `-c`. A response larger
/// than the receive window is not refused — the window slides as `consume`
/// releases octets — it just takes more round trips, which is the right trade
/// for a tool whose common case is a small response measured a million times.
const stream_receive_octets: u32 = 16 * 1024;

/// The send window is the hard one: a request has to *fit*, because zrk writes
/// it in a single `write` and treats a short write as a failed request rather
/// than resuming it. `cli.zig` bounds `--body` against `request_octets_max`
/// below for that reason.
const stream_send_octets: u32 = 4 * 1024;

/// A certificate chain with an intermediate is comfortably past `h3`'s 8 KiB
/// default, and RFC 9001 §4.4 makes running out of room a connection error
/// rather than a stall — so a default that is too small fails as
/// `CRYPTO_BUFFER_EXCEEDED` on the handshake of a server that did nothing wrong.
const crypto_octets: u32 = 32 * 1024;

const Connection = quic.Connection(.{
    .crypto_octets = crypto_octets,
    .streams_max = streams_max,
    .stream_receive_octets = stream_receive_octets,
    .stream_send_octets = stream_send_octets,
    .connection_receive_octets = 1 << 20,
    .sent_max = 256,
});

const Http3 = h3.Http3(.{
    .requests_max = requests_max,
    .unidirectional_max = unidirectional_max,
});

/// What one connection's transport state costs, exported so a `-c` that would
/// not fit in memory can be refused before it is launched rather than after.
pub const footprint_octets: usize = @sizeOf(State);

/// The largest request this file can put on a stream: the QPACK HEADERS frame,
/// and a DATA frame carrying `--body` after it, both of which have to fit in
/// one `Connection.write`.
pub const request_octets_max: usize = stream_send_octets;

/// Datagrams built per flush before the loop goes back to the socket. A bound
/// rather than "until `wantsSend` is false", because a connection that always
/// wants to send is a bug this loop should not turn into a hang.
const flush_datagrams_max: u32 = 32;

/// One read's buffer.
///
/// Far past a datagram, because with generic receive offload one read is a
/// *burst*: the kernel coalesces consecutive datagrams of one flow into a
/// single buffer and reports the segment size out of band. 64 KiB is the
/// kernel's own ceiling on that, so a larger buffer could not be filled and a
/// smaller one would cap the batch below what the path offers.
///
/// It is spent per connection whether or not the kernel does any coalescing —
/// 64 KiB against the megabyte-and-a-half of stream windows beside it, so a
/// `-c 100` run pays about six megabytes for the whole fleet. See
/// `footprint_octets`.
const receive_octets: usize = 64 * 1024;

/// Room for the control messages one read can carry. `UDP_GRO` is a single
/// cmsg of twenty-four octets; this is an order of magnitude of slack so that
/// a kernel with something else to say cannot truncate it.
const control_octets: usize = 256;

/// RFC 3542's `CMSG_ALIGN`: a control message header begins on a boundary of
/// its first field, which is a `usize`.
fn cmsgAlign(len: usize) usize {
    return (len + @sizeOf(usize) - 1) & ~(@as(usize, @sizeOf(usize)) - 1);
}

/// Eight octets is what most implementations use and is well inside RFC 9000
/// §17.2's twenty.
const connection_id_octets: usize = 8;

/// Events taken from `Http3.receive` per stream, per pass.
const events_per_stream_max: usize = 16;

/// Events taken from `Connection.poll` per pass. Larger than the connection's
/// own queue, so a pass always empties it.
const events_per_poll_max: u32 = 256;

/// How long the loop may sleep with nothing else to wait for. Not a protocol
/// bound: it is how often `stop` is re-read, so a `SIGINT` or a finished run
/// is noticed promptly on an idle connection.
const idle_slice_ns: u64 = 20 * std.time.ns_per_ms;

/// A field section decodes to several times the octets it arrived as, and the
/// buffer for that is the caller's — `Http3` holds no per-stream storage.
/// Only `:status` is read out of it, but the decoder still needs room for the
/// whole list.
const field_buffer_octets: usize = 8 * 1024;

/// `SETTINGS_MAX_FIELD_SECTION_SIZE`, offered to the peer and enforced here.
const field_section_octets_max: u64 = 64 * 1024;

/// How long the handshake is given before the connection is abandoned as a
/// connect error, when no `--timeout` says otherwise. A server that answers
/// nothing at all would otherwise hold the connection until the run ended.
const handshake_deadline_ns: u64 = 10 * std.time.ns_per_s;

/// How long an established connection may go without hearing anything from the
/// peer before it is abandoned and rebuilt, as a multiple of `--timeout`.
///
/// Two rather than one, so that a single request outliving its bound does not
/// retire a connection the peer is still answering on every other stream —
/// which is the churn `--deadline-abort` is off by default to avoid.
const progress_bound_multiple: u64 = 2;

/// The two SHA-256 suites `quic_tls.zig` can negotiate, in preference order.
const offered_suites = [_]quic_tls.CipherSuite{
    .aes_128_gcm_sha256,
    .chacha20_poly1305_sha256,
};

/// RFC 9000 §2.1: client-initiated unidirectional streams are 2, 6, 10. Fixed
/// rather than allocated, because there are exactly three and their order is
/// this endpoint's choice.
const control_stream: u64 = 2;
const qpack_encoder_stream: u64 = 6;
const qpack_decoder_stream: u64 = 10;

/// RFC 9114 §8.1's `H3_REQUEST_CANCELLED`, which is what a request abandoned
/// on its own `--timeout` or `--deadline` is.
const h3_request_cancelled: u64 = 0x010c;

/// One request in flight on this connection.
///
/// Deliberately the same fields as `connection.Slot`, and for the same reasons:
/// `scheduled` is the only clock a latency is measured against, and the two
/// bounds collapse into one absolute deadline so a slot needs one comparison
/// rather than two.
const Slot = struct {
    /// Claimed by the loop when the request goes out, freed when the response
    /// completes or the slot's deadline passes.
    busy: bool = false,
    /// The bidirectional stream carrying it.
    stream: u64 = 0,
    /// When this request was *supposed* to go out.
    scheduled: Io.Timestamp = .zero,
    /// `:status`, once the response's field section has arrived.
    status: ?u16 = null,
    /// Response octets seen so far, field section included.
    bytes: u64 = 0,
    /// Absolute monotonic-ns deadline for this request (0 = none), and whether
    /// it came from the coordinated-omission abort bound rather than the wire
    /// timeout.
    deadline_ns: u64 = 0,
    deadline_co: bool = false,
};

/// Everything one connection needs that is too large for a coroutine stack.
///
/// Allocated once per connection by `stats.Fleet`, exactly like `tls.State`,
/// and reused across every reconnect that connection makes. `Connection` is a
/// fixed-size value whose buffers are sized at comptime, so this block is the
/// whole of the transport's memory: there is no allocator below it.
pub const State = struct {
    connection: Connection = undefined,
    http3: Http3 = undefined,
    client: quic_tls.Client = undefined,

    slots: [requests_max]Slot = @splat(.{}),
    /// Streams the connection has reported data on, so a pass can drain each
    /// of them once. A response arrives on a stream this endpoint opened, but
    /// the peer's control stream is one only an event can announce.
    readable: [streams_max]u64 = @splat(0),
    readable_len: usize = 0,
    /// The next client-initiated bidirectional identifier: 0, 4, 8, ...
    next_stream: u64 = 0,
    /// Whether this endpoint's control and QPACK streams have gone out.
    http3_started: bool = false,

    datagram: [Connection.datagram_octets]u8 = undefined,
    incoming: [receive_octets]u8 = undefined,
    /// Where the kernel writes the control messages that came with a read.
    ///
    /// Aligned rather than merely sized: the first thing done with it is to
    /// read a `cmsghdr` out of the front, and a `[N]u8` is aligned to one. The
    /// first version of the probe that established this path panicked on
    /// exactly that, which is cheaper to remember than to rediscover.
    control: [control_octets]u8 align(@alignOf(usize)) = undefined,
    fields: [field_buffer_octets]u8 = undefined,

    /// The block arrives from `allocator.alloc` undefined, and nothing may read
    /// a field before this runs.
    pub fn init(self: *State) void {
        self.* = .{};
    }
};

/// The request as the octets that go on a stream: a QPACK HEADERS frame, and a
/// DATA frame carrying the body when there is one.
///
/// Built once for the whole run and replayed byte-identically on every stream
/// of every connection, which is the same trade `buildRequestBlock` makes for
/// HTTP/2 and is legal for the same reason: this endpoint advertises
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so the encoding touches no dynamic
/// table and depends on no encoder state.
///
/// The result is the caller's to free.
pub fn buildRequest(allocator: std.mem.Allocator, cfg: *const cli.Config) ![]u8 {
    var scratch: std.heap.ArenaAllocator = .init(allocator);
    defer scratch.deinit();
    const tmp = scratch.allocator();

    const fields = try httpmod.buildRequestFields(tmp, cfg);
    // Into h3's field type at the last moment; see `http.Field`.
    const qpack_fields = try tmp.alloc(h3.qpack.Field, fields.len);
    for (qpack_fields, fields) |*out, in| out.* = .{ .name = in.name, .value = in.value };

    var buffer: [request_octets_max]u8 = undefined;
    // `writeHeaders` reads nothing off the instance — it is a method only
    // because the rest of the frame writers are — so a throwaway one encodes
    // the block that every real connection will replay.
    var encoder: Http3 = .init(.client);
    var written = encoder.writeHeaders(&buffer, qpack_fields) catch return error.RequestTooLarge;

    if (cfg.body.len > 0) {
        const header = Http3.writeData(buffer[written..], cfg.body.len) catch
            return error.RequestTooLarge;
        written += header;
        if (written + cfg.body.len > buffer.len) return error.RequestTooLarge;
        @memcpy(buffer[written..][0..cfg.body.len], cfg.body);
        written += cfg.body.len;
    }

    return allocator.dupe(u8, buffer[0..written]);
}

/// Run one HTTP/3 connection until `end` (or `stop`). Never returns an error:
/// every failure is folded into `counters` and recovered from by reconnecting,
/// exactly as `connection.run` does for TCP.
pub fn run(p: *conn.Params) void {
    const io = p.io;
    const state = p.h3_state orelse {
        // Unreachable through `runner.zig`, which allocates the block whenever
        // `--http3` is set. Counted rather than asserted so a wiring mistake
        // shows up as a run that failed instead of a process that died.
        conn.noteError(p, .connect);
        return;
    };

    // The schedule is the connection's, not the attempt's: `send_index` is the
    // coordinated-omission-correct request counter, and it persists across
    // reconnects so a stall is caught up rather than reset.
    var anchor: ?Io.Timestamp = null;
    var send_index: u64 = 0;

    while (!p.stop.load(.monotonic) and conn.now(io).nanoseconds < p.end.nanoseconds) {
        serve(p, state, &anchor, &send_index);
        if (p.stop.load(.monotonic)) return;
        if (conn.now(io).nanoseconds >= p.end.nanoseconds) return;
        // Back off briefly so a target that refuses everything does not spin
        // the CPU building handshakes.
        io.sleep(Io.Duration.fromMilliseconds(5), .awake) catch return;
    }
}

/// One connection attempt: bind, handshake, serve requests, close.
fn serve(p: *conn.Params, state: *State, anchor: *?Io.Timestamp, send_index: *u64) void {
    const io = p.io;

    // A fresh ephemeral port per attempt. QUIC identifies a connection by its
    // connection ID rather than its 4-tuple, so this is not required — but
    // rebinding is what makes a reconnect unambiguous to a server that is still
    // holding the old connection's state.
    const any: net.IpAddress = switch (p.address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    var socket = any.bind(io, .{ .mode = .dgram }) catch {
        conn.noteError(p, .connect);
        return;
    };
    defer socket.close(io);
    enableOffload(&socket);

    // The clock. `h3` takes `now_ns` as a parameter and reads none, so this is
    // the owner of one; the origin is this attempt's start, which keeps every
    // value the transport sees inside a `u64` of nanoseconds.
    const origin = conn.now(io);

    if (!begin(p, state)) return;

    // A handshake that never completes is a connect error, and it has to be
    // bounded by something: a peer that answers no datagram at all would
    // otherwise hold this coroutine until the run ended, contributing one
    // failure where it should contribute a stream of them.
    const handshake_bound_ns: u64 = if (p.timeout_ns != 0) p.timeout_ns else handshake_deadline_ns;

    // And the same question for a connection that *did* handshake and then
    // stopped hearing anything.
    //
    // TCP answers this for the serial path: a wire timeout shuts the socket
    // down, and the request and the connection die together. QUIC has no such
    // coupling — a request is a stream, `expire` resets that one stream, and a
    // connection whose peer has gone away silently is a connection this loop
    // will happily keep paying `--timeout` on, one request at a time, until the
    // run ends. Stopping the target mid-run and starting it again is what
    // showed it: the server came back after three seconds and the run did not,
    // spending its remaining eight seconds timing out against a connection that
    // could never answer.
    //
    // Progress is anything from the peer, not a completed response: a server
    // that is merely slow is still there, and retiring a live connection would
    // throw away the streams already on it.
    const progress_bound_ns: u64 = if (p.timeout_ns != 0)
        progress_bound_multiple * p.timeout_ns
    else
        handshake_deadline_ns;
    var progress_ns: u64 = 0;

    while (true) {
        if (p.stop.load(.monotonic)) return;
        const t = conn.now(io);
        if (t.nanoseconds >= p.end.nanoseconds) return;
        const now_ns: u64 = @intCast(t.nanoseconds - origin.nanoseconds);

        if (!pumpCrypto(p, state)) return;

        if (state.connection.state == .handshaking and now_ns > handshake_bound_ns) {
            conn.noteError(p, .connect);
            return;
        }
        // Requests whose own bound already fired were counted and freed by
        // `expire`, so they are not busy any more and `abandonAll` cannot
        // charge them twice. What it does charge is the requests that were
        // still inside their timeout when the connection was given up, and
        // those are real failures: they were on the wire and no answer is
        // coming.
        if (state.connection.state == .established and now_ns - progress_ns > progress_bound_ns) {
            abandonAll(p, state, .read);
            return;
        }

        // Poll before draining, not after. `poll` is what says a stream has
        // data; draining first would read the streams the *previous* datagram
        // announced and leave this one's until something else woke the loop —
        // an acknowledgement timer, usually, which turns a response that has
        // fully arrived into one that lands a max-ack-delay late. Every
        // latency this tool reports would carry that.
        if (!pollTransport(p, state)) return;
        if (!drain(p, state)) return;

        if (state.connection.state == .established) {
            if (!state.http3_started and !startHttp3(p, state)) return;
            issue(p, state, anchor, send_index);
        }

        expire(p, state);

        if (!flush(p, state, &socket, now_ns)) return;

        // A CONNECTION_CLOSE from the peer ends the attempt. Requests still in
        // flight are the peer's answer to them, so they count as read errors —
        // the same judgement the TCP path makes when a server hangs up mid
        // response.
        switch (state.connection.state) {
            .draining, .closing => {
                abandonAll(p, state, .read);
                return;
            },
            else => {},
        }

        const wait_ns = waitFor(p, state, anchor, send_index.*, origin);
        const timeout: Io.Timeout = .{ .duration = .{
            .raw = Io.Duration.fromNanoseconds(wait_ns),
            .clock = .awake,
        } };
        // `receiveManyTimeout` rather than `receiveTimeout`, for the control
        // buffer and nothing else: `receiveTimeout` builds its own
        // `IncomingMessage` with an empty `control`, so the segment size the
        // kernel reports would have nowhere to land. One message either way.
        var incoming = [_]net.IncomingMessage{.init};
        incoming[0].control = &state.control;
        const maybe_error, const count = socket.receiveManyTimeout(
            io,
            &incoming,
            &state.incoming,
            .{},
            timeout,
        );
        if (maybe_error) |err| switch (err) {
            error.Timeout => {
                state.connection.onTimeout(elapsed(io, origin));
                continue;
            },
            else => {
                abandonAll(p, state, .read);
                conn.noteError(p, .read);
                return;
            },
        };
        if (count == 0) continue;
        progress_ns = elapsed(io, origin);

        // What arrived is one datagram, or — where the kernel coalesced a
        // burst — several laid end to end. `Burst` is the only thing that can
        // tell the two apart, because from the buffer alone a coalesced read
        // looks exactly like one large datagram.
        var burst = burstOf(incoming[0]);
        // Bounded: every pass consumes at least one octet of a buffer that
        // cannot exceed `receive_octets`.
        while (burst.next()) |datagram| {
            state.connection.receive(datagram, elapsed(io, origin)) catch {
                // A datagram that does not parse or does not authenticate is
                // discarded inside the connection; what reaches here is a
                // protocol error, and RFC 9000 §10.2 says close rather than
                // ignore.
                abandonAll(p, state, .read);
                conn.noteError(p, .read);
                return;
            };
        }
    }
}

/// Ask the kernel to hand this socket a burst per read rather than a datagram.
///
/// Generic receive offload coalesces consecutive datagrams of one flow into a
/// single buffer and reports the segment size as a control message, which turns
/// the response to a request — three or four full-size datagrams for a body of
/// any size — into one syscall instead of four. zrk reads far more than it
/// writes, so this is the side that pays.
///
/// Worth about 40%: against a server that segments its sends, a read carries
/// 3.3 datagrams rather than one, and a 4 KiB-body workload goes from 14.9k to
/// 20.5k requests a second. That figure took two attempts to get, and the
/// first one said zero — the target was reached through a published container
/// port, and `docker-proxy` relays every datagram through userspace one at a
/// time, so the bursts were taken apart before they arrived. A benchmark rig
/// with a userspace relay in the path cannot see this feature at all.
///
/// Best effort, and deliberately silent. It is Linux-only (macOS has no
/// equivalent), it wants a kernel from 5.0, and a container or a sandbox may
/// refuse it. Every one of those is a *performance* answer, not a correctness
/// one: without it `segmentOctets` finds no control message, the read is one
/// datagram, and the loop behaves exactly as it did before this existed. There
/// is nothing for a caller to do about a refusal, so there is nothing to
/// report.
fn enableOffload(socket: *net.Socket) void {
    if (builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const on: c_int = 1;
    std.posix.setsockopt(
        socket.handle,
        linux.IPPROTO.UDP,
        linux.UDP.GRO,
        std.mem.asBytes(&on),
    ) catch {};
}

/// The datagrams one read carries, in order.
///
/// A coalesced read is several laid end to end, every one the reported segment
/// size except the last; an ordinary read is one datagram, which is the same
/// shape with a segment size of the whole buffer. One shape rather than two is
/// the point — the receive loop has no branch for "did the kernel coalesce".
const Burst = struct {
    rest: []u8,
    segment: usize,

    fn next(self: *Burst) ?[]u8 {
        if (self.rest.len == 0) return null;
        std.debug.assert(self.segment > 0);
        const take = @min(self.segment, self.rest.len);
        const datagram = self.rest[0..take];
        self.rest = self.rest[take..];
        return datagram;
    }
};

fn burstOf(message: net.IncomingMessage) Burst {
    const coalesced = segmentOctets(message.control);
    var data = message.data;
    const segment = coalesced orelse data.len;

    if (message.flags.trunc) {
        // The buffer was too small for what arrived and the kernel dropped the
        // tail, so the last piece is half a datagram. `receive_octets` is sized
        // at the kernel's *default* ceiling on a coalesced read and a device's
        // `gro_max_size` can be tuned above it, so this is reachable rather
        // than theoretical. QUIC would discard the fragment anyway — silently,
        // as a packet that does not authenticate — so it goes here instead,
        // where the reason for dropping it is known.
        data = if (coalesced) |size| data[0 .. data.len - data.len % size] else data[0..0];
    }

    return .{ .rest = data, .segment = @max(segment, 1) };
}

/// The segment size a coalesced read was built from, or null when the kernel
/// coalesced nothing and the buffer is one datagram.
///
/// Every segment is exactly this long except the last, which carries whatever
/// remains — the same rule in both directions, and what makes splitting the
/// buffer a division rather than a parse.
fn segmentOctets(control: []const u8) ?usize {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    const header_octets = cmsgAlign(@sizeOf(linux.cmsghdr));

    var offset: usize = 0;
    // Bounded by the control buffer: every pass either returns or advances
    // `offset` by at least a header, and the step is checked against what is
    // left before it is taken.
    while (control.len - offset >= @sizeOf(linux.cmsghdr)) {
        std.debug.assert(offset <= control.len);
        const header: *align(@alignOf(usize)) const linux.cmsghdr =
            @ptrCast(@alignCast(&control[offset]));

        // Written as a subtraction from what remains rather than an addition
        // to `offset`, because `len` is the kernel's number and the sum of two
        // `usize`s wraps in the build that ships — which would turn this guard
        // into the thing it is guarding against.
        if (header.len < @sizeOf(linux.cmsghdr)) return null;
        if (header.len > control.len - offset) return null;

        if (header.level == linux.IPPROTO.UDP and header.type == linux.UDP.GRO) {
            // `udp_cmsg_recv` puts an `int` here, so the payload is four
            // octets. Reading two of them yields the right answer on a
            // little-endian machine and zero on a big-endian one, where the
            // whole burst would then be handed on as a single datagram, fail
            // to authenticate, and be discarded without a word.
            const payload = @sizeOf(u32);
            // Against *this* message's length, not the buffer's. A header
            // claiming less than it should, followed by a second message,
            // would otherwise read that one's `len` field as a segment size.
            if (header.len - header_octets < payload) return null;
            var octets: u32 = 0;
            @memcpy(std.mem.asBytes(&octets), control[offset + header_octets ..][0..payload]);
            // Zero would make the split consume nothing and spin. The kernel
            // does not send it; this is what says so rather than trusting it.
            if (octets == 0) return null;
            return octets;
        }

        const step = cmsgAlign(header.len);
        // Rounding up can pass the end even when `len` did not.
        if (step > control.len - offset) return null;
        offset += step;
    }
    return null;
}

/// Draw this attempt's identifiers and entropy, build the connection and the
/// TLS client, and put the ClientHello on the Initial crypto stream. False on
/// anything that makes the attempt impossible; the failure is already counted.
fn begin(p: *conn.Params, state: *State) bool {
    const io = p.io;

    var seed: [64]u8 = undefined;
    io.randomSecure(&seed) catch {
        conn.noteError(p, .connect);
        return false;
    };
    var identifiers: [2 * connection_id_octets]u8 = undefined;
    io.randomSecure(&identifiers) catch {
        conn.noteError(p, .connect);
        return false;
    };

    const destination = quic.ConnectionId.init(identifiers[0..connection_id_octets]) catch unreachable;
    const source = quic.ConnectionId.init(identifiers[connection_id_octets..]) catch unreachable;

    state.connection = .init(.{
        .side = .client,
        .original_destination = destination,
        .source = source,
    });
    // The same numbers the transport parameters below carry. Without this the
    // stream layer enforces the *table's* size instead, which is larger than
    // what was offered — so a peer opening past the advertised limit would be
    // admitted, and RFC 9000 §3.2's implicit creation would then spend table
    // slots this endpoint had promised to nobody.
    state.connection.streams.setAdvertisedStreamLimits(requests_max, unidirectional_max);
    state.http3 = .init(.client);
    state.http3_started = false;
    state.slots = @splat(.{});
    state.readable_len = 0;
    state.next_stream = 0;

    // What this endpoint advertises: its comptime limits, not a policy. A
    // `Connection` enforces what it was built with, so advertising anything
    // else would be advertising a window it will not honour.
    var parameters: [512]u8 = undefined;
    const parameters_len = quic.transport_parameters.encode(&parameters, &.{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = stream_receive_octets,
        .initial_max_stream_data_bidi_remote = stream_receive_octets,
        .initial_max_stream_data_uni = stream_receive_octets,
        .initial_max_streams_bidi = requests_max,
        // Zero here refuses the peer's control stream, which is how an HTTP/3
        // run fails before it starts: a server that cannot open one cannot send
        // SETTINGS, and a client that never sees SETTINGS is talking to nobody.
        .initial_max_streams_uni = unidirectional_max,
        .max_udp_payload_size = Connection.datagram_octets,
        .active_connection_id_limit = 2,
        .initial_source_connection_id = source,
    }) catch {
        conn.noteError(p, .connect);
        return false;
    };

    state.client = .init(.{
        .server_name = p.host,
        .alpn = "h3",
        .transport_parameters = parameters[0..parameters_len],
        .offer = &offered_suites,
        .random = seed[0..32].*,
        .key_seed = seed[32..64].*,
    });

    var hello: [2048]u8 = undefined;
    const client_hello = state.client.clientHello(&hello) catch {
        conn.noteError(p, .connect);
        return false;
    };
    state.connection.cryptoIn(.initial, client_hello) catch {
        conn.noteError(p, .connect);
        return false;
    };
    return true;
}

/// Move handshake octets between the connection and the TLS client in both
/// directions, and install whatever the key schedule produced.
fn pumpCrypto(p: *conn.Params, state: *State) bool {
    for ([_]quic.crypto.Level{ .initial, .handshake, .one_rtt }) |level| {
        const available = state.connection.cryptoOut(level);
        if (available.len == 0) continue;
        const consumed = state.client.read(level, available) catch {
            // A handshake this endpoint could not follow. Before the connection
            // is established that is a connect failure; after it, a
            // post-handshake message we could not read, which kills the
            // connection and every request on it.
            failHandshakeOrRead(p, state);
            return false;
        };
        state.connection.cryptoConsumed(level, consumed);
    }

    for (state.client.drainInstalls()) |one| {
        var secret = quic.crypto.Secret.init(&one.secret) catch {
            failHandshakeOrRead(p, state);
            return false;
        };
        // Switched rather than forwarded: `installSecret`'s direction is an
        // anonymous enum declared in its own signature, so the two types are
        // distinct even though the tags are the same.
        const installed = switch (one.direction) {
            .send => state.connection.installSecret(one.level, .send, &secret, one.suite),
            .receive => state.connection.installSecret(one.level, .receive, &secret, one.suite),
        };
        installed catch {
            failHandshakeOrRead(p, state);
            return false;
        };
    }

    if (state.client.drainTransportParameters()) |octets| {
        state.connection.transportParametersIn(octets) catch {
            failHandshakeOrRead(p, state);
            return false;
        };
    }

    const finished = state.client.drainFinished();
    if (finished.len > 0) {
        state.connection.cryptoIn(.handshake, finished) catch {
            failHandshakeOrRead(p, state);
            return false;
        };
    }
    return true;
}

/// A TLS or key-schedule failure, charged to whichever phase it happened in.
fn failHandshakeOrRead(p: *conn.Params, state: *State) void {
    if (state.connection.state == .handshaking) {
        conn.noteError(p, .connect);
    } else {
        abandonAll(p, state, .read);
        conn.noteError(p, .read);
    }
}

/// RFC 9114 §6.2: this endpoint's three unidirectional streams, sent as soon as
/// there are 1-RTT keys to send them under.
///
/// The QPACK streams carry their type octet and nothing else, ever. This
/// endpoint advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so it will never
/// encode a dynamic table instruction — but RFC 9204 §4.2 still expects the
/// streams to exist, and a server that waits for them before answering is a
/// server this client would otherwise hang on.
fn startHttp3(p: *conn.Params, state: *State) bool {
    var buffer: [256]u8 = undefined;
    const control = state.http3.writeControl(&buffer) catch {
        conn.noteError(p, .connect);
        return false;
    };
    const written = state.connection.write(control_stream, buffer[0..control], false) catch {
        conn.noteError(p, .connect);
        return false;
    };
    if (written != control) {
        conn.noteError(p, .connect);
        return false;
    }
    inline for (.{
        .{ qpack_encoder_stream, h3.stream.Type.qpack_encoder },
        .{ qpack_decoder_stream, h3.stream.Type.qpack_decoder },
    }) |pair| {
        const octets = h3.stream.write(&buffer, pair[1]) catch {
            conn.noteError(p, .connect);
            return false;
        };
        _ = state.connection.write(pair[0], buffer[0..octets], false) catch {
            conn.noteError(p, .connect);
            return false;
        };
    }
    state.http3_started = true;
    return true;
}

/// Open as many requests as the schedule, the slot table and the peer's stream
/// limit allow — and no more.
///
/// Structurally `connection.zig`'s serial request loop with the blocking
/// exchange taken out of the middle. Every step it shares with that loop means
/// what it means there; a send that is not due yet simply returns, and the
/// wait `waitFor` computes is what brings the loop back at the right moment.
fn issue(
    p: *conn.Params,
    state: *State,
    anchor: *?Io.Timestamp,
    send_index: *u64,
) void {
    const io = p.io;
    const depth = @min(p.streams, requests_max);

    // Bounded by the slot table: every pass either sends (consuming a slot),
    // sheds (consuming an index and continuing), or returns.
    for (0..requests_max) |_| {
        if (busySlots(state) >= depth) return;
        const slot = freeSlot(state) orelse return;
        // The peer decides how many identifiers this endpoint may use; writing
        // to one it has not permitted is a connection error at the far end
        // rather than a short write here.
        if (!state.connection.streams.peerPermits(state.next_stream)) return;

        const t = conn.now(io);
        if (t.nanoseconds >= p.end.nanoseconds) return;

        // Closed loop has no schedule to solve: the send is intended for
        // whenever a stream frees, which degenerately zeroes the pacing wait,
        // the deadline check and the coordinated-omission correction, leaving
        // genuine round-trip latency.
        if (anchor.* == null) anchor.* = t;
        const scheduled = if (p.schedule == .closed) t else blk: {
            const offset = p.schedule.offsetNs(send_index.*, p.phase);
            break :blk anchor.*.?.addDuration(Io.Duration.fromNanoseconds(@intCast(offset)));
        };

        // Not due yet. Nothing to shed and nothing to send; the loop sleeps.
        if (scheduled.nanoseconds > t.nanoseconds) return;

        const behind_ns: i128 = t.nanoseconds - scheduled.nanoseconds;
        if (behind_ns > 0) p.counters.noteBehind(@intCast(behind_ns));

        // Deadline shedding: a request already staler than the deadline can
        // never meet it, so fail it now — without touching the wire — and move
        // on. This is what lets the connection drain a backlog and keep
        // measuring near-live latency instead of serializing through an
        // ever-staler queue.
        if (p.deadline_ns != 0 and behind_ns > p.deadline_ns) {
            conn.noteDeadline(p);
            send_index.* += 1;
            continue;
        }

        const id = state.next_stream;
        const written = state.connection.write(id, p.h3_request, true) catch |err| switch (err) {
            // Backpressure, not a failure. The stream table is full of streams
            // that have finished and are waiting their turn to retire (see
            // `streams_max`), or the peer's connection-level window is spent.
            // Neither is the target answering wrongly, and neither is
            // permanent: `send_index` is deliberately *not* advanced, so this
            // request goes out on a later pass and its coordinated-omission
            // latency carries the wait — which is exactly what a client-side
            // queue should do to the numbers.
            error.TooManyStreams, error.FlowControl => return,
            else => {
                conn.noteError(p, .write);
                return;
            },
        };
        if (written != p.h3_request.len) {
            // The stream send buffer could not take the whole request. A fresh
            // stream's buffer is empty and `cli.zig` bounds `--body` against
            // it, so this is unreachable for a well-formed run — and a
            // half-written request is not one this file can resume, so the
            // stream is abandoned rather than left for the peer to parse.
            state.connection.resetStream(id, h3_request_cancelled) catch {};
            state.next_stream += 4;
            conn.noteError(p, .write);
            return;
        }

        // RFC 9000 §2.1: client-initiated bidirectional streams are 0, 4, 8 —
        // the two least significant bits are the type, and this assertion is
        // what keeps that a fact rather than a comment.
        std.debug.assert(state.next_stream % 4 == 0);
        state.next_stream += 4;
        send_index.* += 1;

        // Both bounds are absolute timestamps — the wire timeout from the
        // actual send, the coordinated-omission abort from `scheduled` — so the
        // earlier one binds and the two collapse into a single deadline.
        const wire_deadline_ns: u64 = if (p.timeout_ns != 0)
            @intCast(t.nanoseconds + @as(i128, p.timeout_ns))
        else
            0;
        const co_deadline_ns: u64 = if (p.deadline_abort and p.deadline_ns != 0)
            @intCast(scheduled.nanoseconds + @as(i128, p.deadline_ns))
        else
            0;
        const co_binds = co_deadline_ns != 0 and
            (wire_deadline_ns == 0 or co_deadline_ns <= wire_deadline_ns);

        slot.* = .{
            .busy = true,
            .stream = id,
            .scheduled = scheduled,
            .deadline_ns = if (co_binds) co_deadline_ns else wire_deadline_ns,
            .deadline_co = co_binds,
        };
    }
}

/// Drive `Http3` over every stream the connection has reported data on, and
/// fold what comes out into the slot it belongs to.
fn drain(p: *conn.Params, state: *State) bool {
    var index: usize = 0;
    // Bounded by `readable_len`, which is bounded by the stream table.
    while (index < state.readable_len) : (index += 1) {
        const id = state.readable[index];

        // A request stream whose slot is gone is one this connection has
        // finished with: the response was recorded, or the request's bound
        // expired and the stream was reset. It must not be handed to `Http3`
        // again.
        //
        // Not a tidiness rule. A stream stays live in the transport after its
        // response is complete — our own send side is not retired until it is
        // acknowledged — so `fin` stays true and `receive` reports `finished`
        // again on every pass. The second report finds no slot and is dropped,
        // but `receive` allocates a request-table entry for whatever identifier
        // it is given *before* deciding what to say about it, and that entry is
        // only ever freed by `release`, which the dropped event never reaches.
        // The table fills, and a load generator that is working perfectly
        // starts answering `H3_EXCESSIVE_LOAD` to itself: 1.9% of requests on
        // the run that found this.
        //
        // RFC 9000 §2.1: a client-initiated bidirectional stream is `id % 4 ==
        // 0`, which is every stream this endpoint opens for a request. The
        // peer's unidirectional streams are not filtered — the control stream
        // has no slot and never will, and it is where SETTINGS and GOAWAY come
        // from.
        if (id % 4 == 0 and slotFor(state, id) == null) continue;

        // A stream the connection has already given up is handled by the sweep
        // at the end of this function, not here — see it for why the sweep and
        // not this branch is the one that has to be right.
        const stream = state.connection.findStream(id) orelse continue;
        if (stream.receive_state == .reset) {
            if (slotFor(state, id)) |slot| {
                release(state, slot);
                conn.noteError(p, .read);
            }
            continue;
        }

        const data = state.connection.readable(id);
        // Whether the FIN sits at the end of what is readable now. A
        // half-arrived frame followed by a FIN is a truncated message, and
        // `Http3` has to be told which it is looking at.
        const fin = if (stream.received.final_size) |size|
            size == stream.consumed + data.len
        else
            false;
        if (data.len == 0 and !fin) continue;

        var events: [events_per_stream_max]h3.http3.Event = undefined;
        const result = state.http3.receive(id, data, fin, &events) catch {
            // A malformed HTTP/3 message. RFC 9114 §8 makes most of these
            // connection errors, and this endpoint has no reason to be lenient
            // about a response it is measuring.
            abandonAll(p, state, .read);
            conn.noteError(p, .read);
            return false;
        };
        for (events[0..result.events]) |event| apply(p, state, event);
        if (result.consumed > 0) {
            state.connection.consume(id, result.consumed) catch {
                abandonAll(p, state, .read);
                conn.noteError(p, .read);
                return false;
            };
        }
    }

    // A stream the transport has retired is one both halves have finished
    // with: every octet delivered, the FIN consumed, nothing more coming. That
    // is a complete response, and it is *only* visible as an absence — the
    // last octets of a body and the end of the stream can land in the same
    // pass, in which case the stream is gone before any code here reads a
    // `Http3` event off it, and there is no `finished` to wait for.
    //
    // A sweep over the slots rather than a branch inside the loop above,
    // because a stream can be retired without ever having been announced as
    // readable, and a request whose slot was only freed by its own `--timeout`
    // is a response this tool measured as a failure and the peer sent
    // correctly. This was the whole of the first prototype's stall: a 17-octet
    // response completed and a 4 KiB one hung, because only the small one
    // arrived whole enough to produce a `finished` before the retire.
    //
    // Ordered after the drain so that a response finishing in *this* pass has
    // already had its HEADERS and DATA folded into the slot.
    for (&state.slots) |*slot| {
        if (!slot.busy) continue;
        if (state.connection.findStream(slot.stream) != null) continue;
        complete(p, state, slot);
    }

    compactReadable(state);
    return true;
}

/// One HTTP/3 event, applied to the request it belongs to.
fn apply(p: *conn.Params, state: *State, event: h3.http3.Event) void {
    switch (event) {
        // The peer's SETTINGS and its GOAWAY are both connection-level facts
        // this prototype has nothing to do with: it opens one stream per
        // request and never more than `--streams` of them, and a run that is
        // told to go away simply reconnects when the peer closes.
        .settings, .goaway => {},
        .headers => |value| {
            const slot = slotFor(state, value.stream) orelse return;
            slot.bytes += value.section.len;
            if (value.trailers) return;
            slot.status = statusOf(state, value.section);
        },
        .data => |value| {
            const slot = slotFor(state, value.stream) orelse return;
            slot.bytes += value.payload.len;
        },
        .finished => |id| {
            const slot = slotFor(state, id) orelse return;
            complete(p, state, slot);
        },
    }
}

/// `:status` out of a QPACK field section, or null if it is not there.
///
/// Decoded rather than trusted: `Http3` hands the section over encoded because
/// the buffer a decode needs is many times the section's size and belongs to
/// the caller. Only `:status` is kept — zrk deliberately retains no header
/// content, on any transport.
fn statusOf(state: *State, section: []const u8) ?u16 {
    var iterator = h3.qpack.field_line.iterate(
        section,
        &state.fields,
        field_section_octets_max,
    ) catch return null;
    // Bounded by the section, which `Http3` bounded by the advertised maximum.
    while (iterator.next() catch return null) |field| {
        if (!std.mem.eql(u8, field.name, ":status")) continue;
        return std.fmt.parseInt(u16, field.value, 10) catch null;
    }
    return null;
}

/// A response that arrived whole: record it exactly as the serial path does.
fn complete(p: *conn.Params, state: *State, slot: *Slot) void {
    const io = p.io;

    // Coordinated-omission-corrected latency: measured from the time the
    // request *should* have been sent, not from when it actually went out.
    const done = conn.now(io);
    const latency_ns = done.nanoseconds - slot.scheduled.nanoseconds;
    const latency_us: u64 = if (latency_ns > 0)
        @intCast(@divTrunc(latency_ns, std.time.ns_per_us))
    else
        0;
    p.histogram.record(latency_us);

    p.counters.completed += 1;
    p.counters.bytes += slot.bytes;
    // A response whose HEADERS never carried a readable `:status` is not a
    // response this tool can classify. `Http3` and `fields.MessageValidator`
    // between them make that unreachable for a conforming peer; 0 lands in the
    // "non-2xx/3xx" bucket, which is the honest answer if it ever happens.
    p.counters.recordStatus(slot.status orelse 0);

    conn.maybePublish(p, done.nanoseconds);
    release(state, slot);
}

/// Give a slot and its stream back to both layers.
fn release(state: *State, slot: *Slot) void {
    state.http3.release(slot.stream);
    slot.* = .{};
}

/// Abandon a request that outlived its bound, and *only* that request.
///
/// This is the whole difference from the serial TCP path. There a timeout is a
/// socket shutdown — abandoning the request and the connection in one act,
/// which is exact when they hold one request between them. Here the same act
/// would take every other in-flight sample with it, so the bound is spent on
/// RESET_STREAM and STOP_SENDING and the other responses go on arriving.
fn expire(p: *conn.Params, state: *State) void {
    const io = p.io;
    const nanoseconds = conn.now(io).nanoseconds;

    for (&state.slots) |*slot| {
        if (!slot.busy or slot.deadline_ns == 0) continue;
        if (nanoseconds < slot.deadline_ns) continue;

        // Best effort: a peer that will not take the frames is a peer this
        // request was already lost to.
        state.connection.resetStream(slot.stream, h3_request_cancelled) catch {};
        state.connection.stopSending(slot.stream, h3_request_cancelled) catch {};

        if (slot.deadline_co) {
            conn.noteDeadline(p);
        } else {
            conn.noteTimeout(p, io, slot.scheduled);
        }
        release(state, slot);
    }
}

/// Every in-flight request, charged to one error kind. The connection is going
/// away and these responses are never arriving.
fn abandonAll(p: *conn.Params, state: *State, kind: conn.ErrorKind) void {
    for (&state.slots) |*slot| {
        if (!slot.busy) continue;
        conn.noteError(p, kind);
        release(state, slot);
    }
}

/// Empty the transport's event queue. The one event this loop must act on is
/// `stream_readable`; the rest are recorded by the connection itself.
fn pollTransport(p: *conn.Params, state: *State) bool {
    // Bounded rather than "until null": a queue that refills as fast as it is
    // drained is a bug this loop should not turn into a hang.
    for (0..events_per_poll_max) |_| {
        const event = state.connection.poll() orelse return true;
        switch (event) {
            .stream_readable => |id| noteReadable(state, id),
            .stream_reset => |value| {
                if (slotFor(state, value.stream)) |slot| {
                    release(state, slot);
                    conn.noteError(p, .read);
                }
            },
            .stream_stopped => |value| {
                if (slotFor(state, value.stream)) |slot| {
                    release(state, slot);
                    conn.noteError(p, .write);
                }
            },
            .closed => {
                abandonAll(p, state, .read);
                conn.noteError(p, .read);
                return false;
            },
            // `overflowed` means events were produced faster than this loop
            // polled, which cannot happen while the queue is drained every
            // pass. A dropped `stream_readable` would strand a response, so
            // the connection is retired rather than left to time out one
            // request at a time.
            .overflowed => {
                abandonAll(p, state, .read);
                conn.noteError(p, .read);
                return false;
            },
            .handshake_confirmed, .stream_delivered, .key_updated, .packets_lost => {},
        }
    }
    return true;
}

/// Build and send datagrams until the connection has nothing more.
fn flush(p: *conn.Params, state: *State, socket: *net.Socket, now_ns: u64) bool {
    for (0..flush_datagrams_max) |_| {
        const octets = state.connection.send(&state.datagram, now_ns) catch {
            abandonAll(p, state, .write);
            conn.noteError(p, .write);
            return false;
        };
        if (octets == 0) return true;
        socket.send(p.io, &p.address, state.datagram[0..octets]) catch {
            // A datagram the kernel would not take — a full socket buffer under
            // load, most often — is a lost packet, which is the one failure
            // QUIC is built to absorb: `Recovery` will declare it lost and send
            // it again. Killing the connection over it would turn a moment of
            // local backpressure into every in-flight request failing, and
            // counting it as a write error would report the target as failing
            // when the send never left this machine.
            return true;
        };
    }
    return true;
}

/// How long the loop may sleep: the earliest of the next scheduled send, the
/// transport's own timer, the earliest in-flight bound, the run's end, and the
/// idle slice that keeps `stop` responsive.
fn waitFor(
    p: *conn.Params,
    state: *State,
    anchor: *?Io.Timestamp,
    send_index: u64,
    origin: Io.Timestamp,
) u64 {
    const io = p.io;
    const t = conn.now(io);

    var wake: i128 = t.nanoseconds + idle_slice_ns;
    if (p.end.nanoseconds < wake) wake = p.end.nanoseconds;

    if (state.connection.timeout()) |at| {
        const absolute = origin.nanoseconds + @as(i128, at);
        if (absolute < wake) wake = absolute;
    }

    // The next send, but only if there is somewhere to put it. A schedule that
    // has run ahead of the slot table is not a reason to spin: the wake that
    // matters then is the one that frees a slot, which is a response or a
    // deadline, both of which are below.
    const depth = @min(p.streams, requests_max);
    if (state.connection.state == .established and
        busySlots(state) < depth and
        p.schedule != .closed)
    {
        if (anchor.*) |base| {
            const offset = p.schedule.offsetNs(send_index, p.phase);
            const scheduled = base.nanoseconds + @as(i128, @intCast(offset));
            if (scheduled < wake) wake = scheduled;
        } else {
            // Nothing has been anchored yet, so the first send is due the
            // moment the connection is usable.
            wake = t.nanoseconds;
        }
    }

    for (&state.slots) |*slot| {
        if (!slot.busy or slot.deadline_ns == 0) continue;
        if (@as(i128, slot.deadline_ns) < wake) wake = slot.deadline_ns;
    }

    if (wake <= t.nanoseconds) return 0;
    return @intCast(wake - t.nanoseconds);
}

// ------------------------------------------------------------- slot plumbing

fn freeSlot(state: *State) ?*Slot {
    for (&state.slots) |*slot| {
        if (!slot.busy) return slot;
    }
    return null;
}

fn busySlots(state: *State) u32 {
    var count: u32 = 0;
    for (&state.slots) |*slot| {
        if (slot.busy) count += 1;
    }
    return count;
}

fn slotFor(state: *State, id: u64) ?*Slot {
    for (&state.slots) |*slot| {
        if (slot.busy and slot.stream == id) return slot;
    }
    return null;
}

/// Remember a stream the transport says has data, without letting the list
/// grow past the table it indexes.
fn noteReadable(state: *State, id: u64) void {
    for (state.readable[0..state.readable_len]) |seen| {
        if (seen == id) return;
    }
    if (state.readable_len == state.readable.len) return;
    state.readable[state.readable_len] = id;
    state.readable_len += 1;
}

/// Drop the identifiers whose streams are gone, so the list does not fill up
/// and start refusing new ones.
fn compactReadable(state: *State) void {
    var kept: usize = 0;
    // Bounded by `readable_len`.
    for (state.readable[0..state.readable_len]) |id| {
        if (state.connection.findStream(id) == null) continue;
        state.readable[kept] = id;
        kept += 1;
    }
    state.readable_len = kept;
}

fn elapsed(io: Io, origin: Io.Timestamp) u64 {
    const t = conn.now(io);
    const delta = t.nanoseconds - origin.nanoseconds;
    return if (delta > 0) @intCast(delta) else 0;
}

const testing = std.testing;

/// Build one control message the way the kernel actually does.
///
/// "The way a kernel would" is the whole point and was previously not true:
/// this built `CMSG_LEN(2)` because the parser read two octets, so the two
/// agreed with each other and with nothing else. `udp_cmsg_recv` puts an `int`
/// here — verified against a live socket: `cmsg_len=20`, payload `b0 04 00 00`
/// for a segment size of 1200 — and a fixture that says otherwise is a test
/// asserting the bug.
fn testControl(
    buffer: []align(@alignOf(usize)) u8,
    level: i32,
    kind: i32,
    payload: u32,
    /// Overridden so a test can express a length the kernel would never write.
    length: ?usize,
) []u8 {
    const linux = std.os.linux;
    const header: *align(@alignOf(usize)) linux.cmsghdr = @ptrCast(@alignCast(buffer.ptr));
    const real = cmsgAlign(@sizeOf(linux.cmsghdr)) + @sizeOf(u32);
    header.* = .{ .len = length orelse real, .level = level, .type = kind };
    @memcpy(
        buffer[cmsgAlign(@sizeOf(linux.cmsghdr))..][0..@sizeOf(u32)],
        std.mem.asBytes(&payload),
    );
    return buffer[0..cmsgAlign(real)];
}

/// An `IncomingMessage` as a read would leave it.
fn testMessage(data: []u8, control: []u8, truncated: bool) net.IncomingMessage {
    return .{
        .from = undefined,
        .data = data,
        .control = control,
        .flags = .{
            .eor = false,
            .trunc = truncated,
            .ctrunc = false,
            .oob = false,
            .errqueue = false,
        },
    };
}

test "a coalesced read reports the size its segments were built from" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var buffer: [control_octets]u8 align(@alignOf(usize)) = @splat(0);

    const control = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 1452, null);
    try testing.expectEqual(@as(?usize, 1452), segmentOctets(control));

    // The octets a live kernel wrote, byte for byte, so this test fails if the
    // payload is ever read at the wrong width again — including on a
    // big-endian target, where taking the low half would read zero.
    var raw: [24]u8 align(@alignOf(usize)) = .{
        0x14, 0, 0, 0, 0, 0, 0, 0, // cmsg_len = 20
        0x11, 0, 0, 0, //             level = IPPROTO_UDP
        0x68, 0, 0, 0, //             type  = UDP_GRO
        0xb0, 0x04, 0, 0, //          gso_size = 1200, as an int
        0xaa, 0xaa, 0xaa, 0xaa, //    padding
    };
    if (builtin.cpu.arch.endian() == .little) {
        try testing.expectEqual(@as(?usize, 1200), segmentOctets(&raw));
    }

    // And a payload whose high octets are not zero, which is the only way a
    // little-endian machine can tell a four-octet read from a two-octet one:
    // the low half of this is 4464. Not a size any kernel sends — the point is
    // the width this parser reads, not the value.
    const wide = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 70_000, null);
    try testing.expectEqual(@as(?usize, 70_000), segmentOctets(wide));

    // No control message is the ordinary case — a kernel that does not
    // coalesce, or one that declined the socket option — and has to read as
    // "one datagram" rather than as an error.
    try testing.expectEqual(@as(?usize, null), segmentOctets(&.{}));
}

test "a control message this loop cannot trust is no segment size" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var buffer: [control_octets]u8 align(@alignOf(usize)) = @splat(0);

    // Somebody else's message, walked past rather than misread.
    const other = testControl(&buffer, linux.IPPROTO.IP, 8, 1452, null);
    try testing.expectEqual(@as(?usize, null), segmentOctets(other));

    // A length that does not cover its own header, which is the step that
    // would not advance — a walk trusting it would never terminate.
    const short = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 1452, 4);
    try testing.expectEqual(@as(?usize, null), segmentOctets(short));

    // A header claiming room for a two-octet payload where four are read. The
    // bound has to come from *this* message rather than from the buffer, or
    // the read reaches into whatever follows.
    const narrow = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 1452, cmsgAlign(@sizeOf(linux.cmsghdr)) + 2);
    try testing.expectEqual(@as(?usize, null), segmentOctets(narrow));

    // A length running past the buffer, which is how a cmsg walk reads its way
    // off the end of what the kernel wrote.
    const over = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 1452, control_octets * 2);
    try testing.expectEqual(@as(?usize, null), segmentOctets(over));

    // And a length near the top of the range, where `offset + len` wraps in
    // the build that ships and the guard becomes the defect it guards against.
    const huge = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 1452, std.math.maxInt(usize) - 3);
    try testing.expectEqual(@as(?usize, null), segmentOctets(huge));

    // Zero would make the split consume nothing and spin.
    const zero = testControl(&buffer, linux.IPPROTO.UDP, linux.UDP.GRO, 0, null);
    try testing.expectEqual(@as(?usize, null), segmentOctets(zero));

    // And a buffer too short to hold a header at all.
    try testing.expectEqual(@as(?usize, null), segmentOctets(buffer[0..4]));
}

test "a burst splits into the datagrams it was coalesced from" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var control: [control_octets]u8 align(@alignOf(usize)) = @splat(0);
    var data: [9600]u8 = @splat(0);

    const segment: usize = 1200;
    const encoded = testControl(&control, linux.IPPROTO.UDP, linux.UDP.GRO, @intCast(segment), null);

    for ([_]usize{ 1, 1200, 1201, 8800, 9600 }) |total| {
        var burst = burstOf(testMessage(data[0..total], encoded, false));
        var count: usize = 0;
        var seen: usize = 0;
        while (burst.next()) |datagram| {
            try testing.expect(datagram.len > 0);
            try testing.expect(datagram.len <= segment);
            seen += datagram.len;
            count += 1;
            // Every segment but the last is exactly the reported size.
            if (seen < total) try testing.expectEqual(segment, datagram.len);
        }
        try testing.expectEqual(total, seen);
        try testing.expectEqual((total + segment - 1) / segment, count);
    }

    // No control message: the whole buffer is one datagram.
    var single = burstOf(testMessage(data[0..1500], &.{}, false));
    try testing.expectEqual(@as(usize, 1500), single.next().?.len);
    try testing.expectEqual(@as(?[]u8, null), single.next());
}

test "a truncated read gives up the fragment rather than passing it on" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const linux = std.os.linux;
    var control: [control_octets]u8 align(@alignOf(usize)) = @splat(0);
    var data: [9600]u8 = @splat(0);
    const segment: usize = 1200;
    const encoded = testControl(&control, linux.IPPROTO.UDP, linux.UDP.GRO, @intCast(segment), null);

    // Three whole segments and half of a fourth. The half is not a datagram,
    // and handing it on would be handing QUIC a packet that cannot
    // authenticate — discarded there without a word, rather than here with a
    // reason.
    var burst = burstOf(testMessage(data[0 .. 3 * segment + 600], encoded, true));
    var count: usize = 0;
    while (burst.next()) |datagram| : (count += 1) {
        try testing.expectEqual(segment, datagram.len);
    }
    try testing.expectEqual(@as(usize, 3), count);

    // And an uncoalesced read that was truncated is one incomplete datagram,
    // so there is nothing to keep at all.
    var lone = burstOf(testMessage(data[0..900], &.{}, true));
    try testing.expectEqual(@as(?[]u8, null), lone.next());
}

test "a connection's transport state is a bounded, allocation-free block" {
    // The whole point of `h3` being comptime-sized: `-c 100` costs exactly a
    // hundred of these and nothing else, so a run's memory is knowable before
    // it starts. The bound is generous — this is a guard against a limit above
    // being raised without anyone noticing what it multiplies by.
    try testing.expect(footprint_octets < 4 * 1024 * 1024);
}

test "the request frame is a HEADERS frame that fits one stream write" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const parsed = try cli.parse(arena.allocator(), &[_][]const u8{
        "--http3", "--insecure", "https://example.com/hello",
    });
    const frame = try buildRequest(arena.allocator(), &parsed.config);

    try testing.expect(frame.len <= request_octets_max);
    // RFC 9114 §7.2.2: a HEADERS frame's type is 0x01, and it is the first
    // octet here because the frame's own header comes first.
    try testing.expectEqual(@as(u8, 0x01), frame[0]);
}

test "a request body rides in a DATA frame after the header block" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const parsed = try cli.parse(arena.allocator(), &[_][]const u8{
        "--http3", "--insecure", "-m", "POST", "-b", "hello", "https://example.com/",
    });
    const frame = try buildRequest(arena.allocator(), &parsed.config);

    // The body's octets are on the wire verbatim, after a DATA header the
    // frame layer wrote; finding them is enough to say the two frames were
    // concatenated rather than one overwriting the other.
    try testing.expect(std.mem.indexOf(u8, frame, "hello") != null);
}
