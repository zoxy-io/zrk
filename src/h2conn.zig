//! One HTTP/2 connection over an established byte stream.
//!
//! The transport is the caller's: `connection.zig` hands in a reader/writer
//! pair, either cleartext (h2c prior knowledge) or the plaintext side of
//! `tls.zig` once ALPN has chosen `h2`. This module speaks the protocol and
//! nothing more: preface, settings, streams, and the flow control that keeps a
//! long run from stalling.
//!
//! Two callers share the seam. `exchange` is the serial path — one request in
//! flight, the response returned whole — and it keeps every measurement
//! semantic this tool has over HTTP/1.1: latency is recorded from a request's
//! *scheduled* time, and a late request is aborted by shutting the socket
//! down, which is only equivalent to aborting one request while exactly one is
//! in flight. `beginStream`, `receive` and `resetStream` are the multiplexed
//! path, where `connection.zig` keeps several streams open and the abort is a
//! RST_STREAM for the one stream that blew its bound. docs/multiplexing.md has
//! the reasoning.
//!
//! ## What it does not do
//!
//! No server push: we advertise `SETTINGS_ENABLE_PUSH = 0`, and a peer that
//! sends `PUSH_PROMISE` anyway is a protocol error rather than something to
//! handle. No priority: RFC 9113 deprecates the scheme and a load generator
//! has nothing to say about it.

const std = @import("std");
const Io = std.Io;

const h2 = @import("h2");
const httpmod = @import("http.zig");

const frame = h2.frame;
const hpack = h2.hpack;

/// RFC 9113 section 3.4: the octets a client sends before anything else.
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// RFC 9113 section 6.5.2's identifiers. Taken from `h2` rather than spelled
/// again here: two copies of a wire enum is one copy that can go stale, and
/// this one is already non-exhaustive there because the section requires an
/// unknown identifier to be ignored rather than refused.
const Setting = frame.payload.Settings.Identifier;

/// What we advertise, and why each value is what it is.
///
/// `header_table_size = 0` is the load-bearing one. It forbids the peer from
/// using the dynamic table at all, which makes our decode stateless: no arena,
/// no eviction accounting, and no per-connection HPACK state to carry. HPACK
/// makes header decoding mandatory where HTTP/1.1 was a scan for CRLF, and this
/// is what keeps that off the hot path of a tool that sells not adding
/// client-side noise to the measurement.
const advertised_header_table_size: u32 = 0;

/// Push is refused rather than handled. A promised stream is response bytes
/// nobody asked for, arriving on a stream with no scheduled send time — there
/// is no honest latency sample to record for one.
const advertised_enable_push: u32 = 0;

/// Our receive window, per stream and for the connection, set as high as RFC
/// 9113 section 6.9.1 allows. A load generator reads every response in full and
/// immediately; the window exists to protect a slow reader, and we are not one.
/// Raising it as far as it goes is what keeps `WINDOW_UPDATE` off the common
/// path entirely.
const advertised_window_size: u32 = window_max;

/// Section 6.9.1: a flow-control window is a 31-bit signed quantity.
const window_max: u32 = (1 << 31) - 1;

/// Section 6.9.2: every flow-control window starts at 65,535 octets, and
/// `SETTINGS_INITIAL_WINDOW_SIZE` moves only the *stream* windows. The
/// connection window stays here until a `WINDOW_UPDATE` says otherwise, which
/// is why `open` sends one immediately — a load generator would otherwise stall
/// inside the first large response.
///
/// Defined here rather than taken from `h2`: that package is framing only and
/// holds no connection state. This is arguably a constant of the format in the
/// same way `max_frame_size_min` is, and worth proposing there if a second
/// consumer needs it.
const window_initial_default: u32 = 65_535;

/// The largest frame we are willing to receive. The floor from section 6.5.2,
/// because a bigger one buys a load generator nothing: response bodies arrive
/// in whatever frames the peer chooses and we consume them as they come.
const advertised_max_frame_size: u32 = frame.Header.max_frame_size_min;

/// Response headers we are willing to decode. Generous — a benchmark target is
/// not hostile — but bounded, because an unbounded one is a memory bug waiting
/// for a misbehaving server.
const header_list_max: u32 = 64 * 1024;

/// Room for one field block's fragments, and for the decoded field text.
///
/// Both are the caller's buffers in h2's API. The block bound is what stops a
/// peer that never sends END_HEADERS: `BlockAssembler`'s buffer length *is* the
/// limit on a field block, so this number is the CONTINUATION-flood defence.
const block_buffer_size: u32 = 32 * 1024;
const field_buffer_size: u32 = 32 * 1024;

comptime {
    // A block that cannot hold what we said we would accept would reject
    // conforming responses.
    std.debug.assert(block_buffer_size >= advertised_max_frame_size);
    std.debug.assert(field_buffer_size >= advertised_max_frame_size);
    std.debug.assert(header_list_max >= advertised_max_frame_size);
    std.debug.assert(advertised_window_size <= window_max);
}

/// Frames a single exchange may see before its response completes.
///
/// A bound rather than a trust: a peer that answers every request with an
/// endless stream of SETTINGS or PING would otherwise keep one connection's
/// coroutine busy forever, and the run's wall clock would silently become the
/// only thing stopping it. Generous enough that no conforming server reaches it
/// — a 16 KiB-framed megabyte response is 64 DATA frames.
const frames_per_exchange_max: u32 = 4096;

/// The same bound, moved to the connection for a multiplexing caller.
///
/// `frames_per_exchange_max` works because a serial exchange either finishes or
/// gives up. A receive loop that serves N streams never finishes, so what it
/// bounds instead is frames *without progress*: an endless SETTINGS or PING
/// flood completes no stream, and a connection that completes nothing after
/// this many frames is not one worth measuring through.
pub const frames_without_progress_max: u32 = frames_per_exchange_max;

/// Connection-window debt at which we hand the peer its credit back.
///
/// `open` raises the connection window to the 31-bit maximum, which reads as
/// "flow control off" and is what it amounts to for one response at a time. It
/// is not: the window is a budget for the connection's *whole life*, and every
/// DATA octet spends it. One reader taking one response at a time still spends
/// it — just slowly enough that a short run finishes first — and N streams
/// share the same budget. Replenishing at half keeps a WINDOW_UPDATE off the
/// hot path (one per gibibyte) while making the budget genuinely unbounded.
const window_replenish_at: u32 = window_max / 2;

/// Section 6.7: a PING payload is eight octets.
const ping_octets: usize = 8;

/// Section 6.5.2's default for `SETTINGS_MAX_CONCURRENT_STREAMS`: no limit
/// until the peer sends one. Sentinel rather than an optional because every
/// caller wants the number, and "unlimited" is a number here — no run opens
/// four billion streams on one connection.
pub const concurrent_streams_unlimited: u32 = std.math.maxInt(u32);

pub const Error = error{
    /// The peer spoke something that is not HTTP/2, or broke a rule this client
    /// is unwilling to continue past.
    Protocol,
    /// The peer sent GOAWAY, or closed. Not an error in itself — the caller
    /// reconnects — but this exchange did not complete.
    Closed,
    /// The peer did not process this request, and said so: its stream is past
    /// the last one a GOAWAY accepted (section 6.8), or it was reset with
    /// REFUSED_STREAM (section 8.7). Either way it is safe to send again.
    Refused,
    /// A response exceeded a bound we advertised or hold.
    TooLarge,
    /// The transport failed.
    Io,
};

/// What one received frame means to a caller. See `Session.receive`.
///
/// Deliberately per-frame and per-stream rather than per-response: once several
/// streams are open, "the response" is not something the connection layer can
/// return — which stream belongs to which request is the caller's bookkeeping.
/// What stays behind this seam is everything that needs connection-scoped state
/// to decide: field-block assembly, HPACK, the peer's settings, flow control.
pub const Incoming = union(enum) {
    /// A complete field block ended on `stream`. `status` is its `:status`, or
    /// null for a block that carries none — a trailers section (RFC 9113
    /// section 8.1), which is legal and routine for gRPC and for any response
    /// declaring `Trailer`. `bytes` is the block's own size, counted like any
    /// other response octets.
    headers: struct { stream: u31, status: ?u16, bytes: u64, end_stream: bool },
    /// DATA arrived on `stream`.
    data: struct { stream: u31, bytes: u64, end_stream: bool },
    /// The peer reset `stream` (section 6.4). That stream is over; the
    /// connection is not.
    reset: u31,
    /// The peer reset `stream` with REFUSED_STREAM: section 8.7 guarantees
    /// none of the request was processed, so it may be sent again.
    refused: u31,
    /// The peer is owed an answer. Sent with `Session.reply` by whoever holds
    /// the writer.
    reply: Reply,
    /// GOAWAY: no new stream may be opened. Open streams up to
    /// `Session.peer_last_stream` may still finish; the rest were not
    /// processed.
    going_away,
    /// Nothing a caller can act on — a field-block fragment mid-assembly, or a
    /// frame the RFC says to ignore.
    idle,
};

/// An answer the peer is owed, deferred to whoever owns the writer.
pub const Reply = union(enum) {
    settings_ack,
    ping_ack: [ping_octets]u8,
};

/// Per-connection state, pinned by the caller for the connection's lifetime.
///
/// No allocator: every buffer is a field here, sized by the constants above,
/// which is the same discipline `tls.State` follows and the reason h2 forbids
/// an allocator in its own seam.
pub const Session = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,

    /// Next client stream identifier. Section 5.1.1: clients use odd numbers,
    /// ascending, and never reuse one.
    next_stream: u31 = 1,

    /// The peer's `SETTINGS_MAX_FRAME_SIZE`, which bounds what we may send.
    /// Section 6.5.2's default until the peer says otherwise.
    peer_max_frame_size: u32 = frame.Header.max_frame_size_min,

    /// The peer's `SETTINGS_MAX_CONCURRENT_STREAMS`. A multiplexing client has
    /// to honour it — the effective depth is `min(--streams, this)` — and
    /// ignoring it is not harmless: the surplus does not fail, it queues, and a
    /// client that thinks it has N in flight while the peer allows ten is
    /// measuring a queue it cannot see. (h2load ignores it; see
    /// docs/multiplexing.md.)
    peer_max_concurrent_streams: u32 = concurrent_streams_unlimited,

    /// Set when the peer has sent GOAWAY. The exchange in flight may still
    /// complete; no new stream may be opened.
    peer_going_away: bool = false,
    /// The last stream the peer's GOAWAY said it may process. Section 6.8:
    /// anything above it was not processed and can be retried. Only meaningful
    /// once `peer_going_away` is set; a second GOAWAY can only lower it.
    peer_last_stream: u31 = std.math.maxInt(u31),

    /// DATA octets received since the last connection-level `WINDOW_UPDATE`.
    /// See `window_replenish_at`.
    window_debt: u32 = 0,

    /// Field-block assembly and HPACK decoding, both connection-scoped.
    ///
    /// Per-connection rather than per-response because that is what the RFC
    /// makes them. Section 6.10 forbids any frame between a HEADERS and its
    /// CONTINUATIONs, on any stream, so at most one block is ever in flight and
    /// one assembler serves every stream. The decoder's dynamic table is
    /// per-connection by definition — ours is empty, since we advertise
    /// `SETTINGS_HEADER_TABLE_SIZE = 0`, which is what lets it be sized zero
    /// rather than what lets it be per-response.
    ///
    /// Both point into this struct's own buffers, so they are established by
    /// `open` (where the session is pinned) rather than by `init` (which
    /// returns by value and would hand back dangling pointers).
    assembler: frame.BlockAssembler = undefined,
    decoder: hpack.Decoder = undefined,
    table_storage: hpack.DynamicTable.Storage(0) = .{},

    assembler_buffer: [block_buffer_size]u8 = undefined,
    field_buffer: [field_buffer_size]u8 = undefined,
    /// Scratch for one outbound frame header, and for settings payloads.
    scratch: [frame.Header.octets + 6 * settings_entries_max]u8 = undefined,

    /// Settings we send in one frame.
    const settings_entries_max = 6;

    pub fn init(reader: *Io.Reader, writer: *Io.Writer) Session {
        return .{ .reader = reader, .writer = writer };
    }

    /// Send the preface and our SETTINGS, and read the peer's.
    ///
    /// Section 3.4 lets both sides send immediately without waiting, so this
    /// does not block on the peer's SETTINGS before returning — it reads frames
    /// until it has seen one SETTINGS from the peer, acknowledging it, which is
    /// the first thing any conforming server sends.
    pub fn open(session: *Session) Error!void {
        // The session is pinned from here on, so the two buffer-borrowing
        // pieces of state can finally be built. See their declarations.
        session.assembler = .init(
            &session.assembler_buffer,
            frame.BlockAssembler.frames_max_default,
        );
        session.decoder = .init(session.table_storage.table(), header_list_max);

        session.writer.writeAll(preface) catch return error.Io;
        try session.writeSettings();
        // Raise the connection-level window as far as it goes. `SETTINGS`
        // initial-window applies per stream only (section 6.9.2), so the
        // connection window stays at the 65535 default until told otherwise —
        // and a load generator would stall on it within one large response.
        try session.writeWindowUpdate(0, window_max - window_initial_default);
        session.writer.flush() catch return error.Io;

        // The peer's SETTINGS is the first frame it must send (section 3.4).
        // Everything before it that is legal is handled and skipped.
        var frames: u32 = 0;
        while (frames < frames_per_exchange_max) : (frames += 1) {
            const header = try session.readHeader();
            if (header.frame_type == .settings and !header.has(.ack)) {
                try session.applySettings(header);
                session.writer.flush() catch return error.Io;
                return;
            }
            try session.answer(try session.classify(header));
        }
        return error.Protocol;
    }

    /// One request and its response, which is the whole exchange model of this
    /// slice: open a stream, send the prebuilt block with END_STREAM, and read
    /// frames until that stream ends.
    ///
    /// `block` is the HPACK-encoded header block, built once at startup with
    /// `Encoder.Mode.static_only` so it depends on no encoder state and can be
    /// replayed byte-identically on every stream. That guarantee is why this
    /// function takes bytes rather than fields.
    pub fn exchange(session: *Session, block: []const u8, body: []const u8) Error!httpmod.Response {
        return session.readResponse(try session.beginStream(block, body));
    }

    /// Open one stream and send the request on it, without waiting for the
    /// response. Returns the stream identifier the answer will arrive on.
    ///
    /// Split out of `exchange` for the multiplexing caller, which has to be
    /// able to send while earlier streams are still open. Writes and flushes,
    /// so a caller sharing the writer with a receive loop holds its write lock
    /// across this.
    pub fn beginStream(session: *Session, block: []const u8, body: []const u8) Error!u31 {
        if (session.peer_going_away) return error.Closed;

        const stream = session.next_stream;
        // Section 5.1.1: ascending odd identifiers, never reused. Two per
        // request, so the space allows about a billion requests per connection
        // — far past any run, but the check is here because wrapping would
        // reuse an identifier rather than fail.
        if (stream > std.math.maxInt(u31) - 2) return error.Closed;
        session.next_stream = stream + 2;

        try session.writeHeaders(stream, block, body.len == 0);
        if (body.len > 0) try session.writeData(stream, body);
        session.writer.flush() catch return error.Io;
        return stream;
    }

    /// The identifier `beginStream` will use next.
    ///
    /// For a caller that must publish a stream in its own bookkeeping *before*
    /// the HEADERS is on the wire: without it there is a window in which the
    /// response arrives for a stream nobody has claimed, and its latency sample
    /// is lost. Valid only while the caller holds whatever serializes
    /// `beginStream`.
    pub fn peekStream(session: *const Session) u31 {
        return session.next_stream;
    }

    /// Abandon one stream without touching the connection (section 6.4).
    ///
    /// This is the whole of what multiplexing changes about aborting a request.
    /// With one stream open, "abort this request" and "abort this connection"
    /// are the same act, and `connection.zig` implements the first as the
    /// second by shutting the socket down. With N open, that would take N − 1
    /// innocent latency samples with it, so a timeout has to be spent here
    /// instead.
    pub fn resetStream(session: *Session, stream: u31) Error!void {
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, @intFromEnum(frame.ErrorCode.cancel), .big);
        try session.writeFrame(.rst_stream, 0, stream, &payload);
        session.writer.flush() catch return error.Io;
    }

    /// Read one frame and say what it means, without writing anything.
    ///
    /// The no-writing part is the point: a multiplexing caller reads on one
    /// coroutine and sends on another, so a frame the peer is owed an answer to
    /// comes back as `Incoming.reply` for the caller to send once it holds the
    /// write lock, rather than being answered from under a blocking read.
    pub fn receive(session: *Session) Error!Incoming {
        return session.classify(try session.readHeader());
    }

    /// Send an answer `receive` reported as owed.
    pub fn reply(session: *Session, owed: Reply) Error!void {
        switch (owed) {
            // Section 6.5.3: acknowledged whether or not we act on it.
            .settings_ack => try session.writeFrame(.settings, frame.Flag.ack.bit(), 0, &.{}),
            // Section 6.7: a PING we did not send must be echoed with ACK.
            .ping_ack => |data| try session.writeFrame(.ping, frame.Flag.ack.bit(), 0, &data),
        }
        session.writer.flush() catch return error.Io;
    }

    /// Whether enough DATA has arrived to be worth giving the connection window
    /// back. See `window_replenish_at`.
    pub fn windowDue(session: *const Session) bool {
        return session.window_debt >= window_replenish_at;
    }

    /// Credit the peer with every DATA octet consumed since the last call.
    /// Writes, so the same write-lock rule as `beginStream` applies.
    pub fn replenishWindow(session: *Session) Error!void {
        const debt = session.window_debt;
        if (debt == 0) return;
        session.window_debt = 0;
        try session.writeWindowUpdate(0, debt);
        session.writer.flush() catch return error.Io;
    }

    /// Perform whatever `incoming` obliges us to, for a caller that owns the
    /// writer outright. The single-threaded paths — `open`, `readResponse` —
    /// answer inline; a multiplexing caller takes its write lock instead.
    fn answer(session: *Session, incoming: Incoming) Error!void {
        switch (incoming) {
            .reply => |owed| try session.reply(owed),
            else => {},
        }
    }

    /// Read frames until `stream` carries END_STREAM, handling everything else
    /// the connection may interleave.
    ///
    /// The serial half of the client: one stream is open, so every frame naming
    /// another stream is a late one from a stream already finished, and
    /// ignorable rather than fatal.
    fn readResponse(session: *Session, stream: u31) Error!httpmod.Response {
        var status: ?u16 = null;
        var bytes: u64 = 0;
        var frames: u32 = 0;

        while (frames < frames_per_exchange_max) : (frames += 1) {
            if (session.windowDue()) try session.replenishWindow();
            switch (try session.receive()) {
                .headers => |head| {
                    if (head.stream != stream) continue;
                    if (head.status) |code| {
                        // Two blocks each carrying a `:status` is malformed
                        // (RFC 9113 section 8.3.2). A second block *without*
                        // one is trailers, and just adds its octets.
                        if (status != null) return error.Protocol;
                        status = code;
                    }
                    bytes += head.bytes;
                    if (head.end_stream) return finish(status, bytes);
                },
                .data => |data| {
                    if (data.stream != stream) continue;
                    bytes += data.bytes;
                    if (data.end_stream) return finish(status, bytes);
                },
                .reset => |reset| if (reset == stream) return error.Closed,
                .refused => |refused| if (refused == stream) return error.Refused,
                .reply => |owed| try session.reply(owed),
                // Recorded on the session. The exchange in flight may still
                // finish — unless it is past the last stream the peer took.
                .going_away => if (stream > session.peer_last_stream) return error.Refused,
                .idle => {},
            }
        }
        return error.Protocol;
    }

    /// What one frame means, once the connection-scoped state — field-block
    /// assembly, HPACK, the peer's settings, the flow-control debt — has had
    /// its say. Reads the payload; writes nothing.
    fn classify(session: *Session, header: frame.Header) Error!Incoming {
        const payload_bytes = try session.readPayload(header);
        const payload = frame.payload.parse(header, payload_bytes) catch return error.Protocol;

        // Before the assembler, which would otherwise assemble a PUSH_PROMISE's
        // field block as if it were a response. We advertised
        // `SETTINGS_ENABLE_PUSH = 0`; section 8.4 makes one a connection error,
        // and there is no honest latency sample for a stream nobody scheduled.
        if (payload == .push_promise) return error.Protocol;

        // The CONTINUATION state machine's refusals are all reasons to stop
        // using this connection: an interleaved frame or an unbounded block
        // means the peer is not framing the way section 6.10 requires.
        const accepted = session.assembler.accept(header, &payload) catch return error.Protocol;
        switch (accepted) {
            .fragment => return .idle,
            .block => |complete| return .{ .headers = .{
                .stream = header.stream_identifier,
                .status = try decodeStatus(&session.decoder, &session.field_buffer, complete.fragment),
                .bytes = complete.fragment.len,
                .end_stream = complete.end_stream,
            } },
            .passthrough => {},
        }

        switch (payload) {
            .data => |data| {
                // Consumed the moment it arrives — this client never stalls a
                // reader — so the only flow control left is giving the
                // connection window back before the budget runs out.
                session.window_debt +|= @intCast(data.data.len);
                return .{ .data = .{
                    .stream = header.stream_identifier,
                    .bytes = data.data.len,
                    .end_stream = header.has(.end_stream),
                } };
            },
            .rst_stream => |reset| return if (reset.error_code == .refused_stream)
                .{ .refused = header.stream_identifier }
            else
                .{ .reset = header.stream_identifier },
            // Section 6.5: take what we are told, and acknowledge.
            .settings => {
                if (header.has(.ack)) return .idle;
                try session.takeSettings(payload);
                return .{ .reply = .settings_ack };
            },
            .ping => |ping| {
                if (header.has(.ack)) return .idle;
                return .{ .reply = .{ .ping_ack = ping.opaque_data.* } };
            },
            // Section 6.8: no new stream after this. Streams already open may
            // still finish, so this is recorded rather than raised.
            .goaway => |goaway| {
                session.peer_going_away = true;
                // A later GOAWAY may lower the bound but not raise it: section
                // 6.8 forbids the increase, and taking the minimum means a
                // peer that sends one anyway cannot un-refuse a stream.
                session.peer_last_stream = @min(session.peer_last_stream, goaway.last_stream_identifier);
                return .going_away;
            },
            // Window updates only matter to a sender, and the only thing this
            // client sends is a request block. Ignorable rather than tracked.
            .window_update => return .idle,
            // Section 5.3.1 allows PRIORITY on any stream at any time, and
            // section 4.1 says to skip an unknown type by its length — which
            // the payload read already did.
            .priority, .unknown => return .idle,
            // Rejected above; field-block frames never reach here.
            .push_promise, .headers, .continuation => return .idle,
        }
    }

    fn readHeader(session: *Session) Error!frame.Header {
        return readHeaderImpl(session);
    }

    fn readPayload(session: *Session, header: frame.Header) Error![]const u8 {
        return readPayloadImpl(session, header);
    }

    fn writeSettings(session: *Session) Error!void {
        var payload: [6 * settings_entries_max]u8 = undefined;
        var used: usize = 0;
        const entries = [_]struct { Setting, u32 }{
            .{ .header_table_size, advertised_header_table_size },
            .{ .enable_push, advertised_enable_push },
            .{ .initial_window_size, advertised_window_size },
            .{ .max_frame_size, advertised_max_frame_size },
            .{ .max_header_list_size, header_list_max },
        };
        comptime std.debug.assert(entries.len <= settings_entries_max);
        for (entries) |entry| {
            std.mem.writeInt(u16, payload[used..][0..2], @intFromEnum(entry[0]), .big);
            std.mem.writeInt(u32, payload[used + 2 ..][0..4], entry[1], .big);
            used += 6;
        }
        try session.writeFrame(.settings, 0, 0, payload[0..used]);
    }

    fn applySettings(session: *Session, header: frame.Header) Error!void {
        const payload_bytes = try session.readPayload(header);
        const payload = frame.payload.parse(header, payload_bytes) catch return error.Protocol;
        try session.takeSettings(payload);
        try session.reply(.settings_ack);
    }

    /// Take the peer's settings. Acknowledging them is the caller's, via
    /// `Incoming.reply` — see `receive` for why that is not done here.
    ///
    /// Two of them change what this client does. `SETTINGS_MAX_FRAME_SIZE`
    /// bounds what we may send, and our send is a header block that could
    /// exceed the default if a caller passes enough `-H`.
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` bounds how many streams `--streams`
    /// may actually open. The rest describe limits on a sender we are not: we
    /// send no body large enough to meet a window.
    fn takeSettings(session: *Session, payload: frame.Payload) Error!void {
        var entries = payload.settings.iterate();
        while (entries.next()) |entry| {
            // Section 6.5.2: an identifier we do not know must be ignored, not
            // refused, so extensions stay deployable.
            switch (entry.identifier) {
                .max_frame_size => {
                    if (entry.value < frame.Header.max_frame_size_min) return error.Protocol;
                    if (entry.value > frame.Header.max_frame_size_max) return error.Protocol;
                    session.peer_max_frame_size = entry.value;
                },
                .max_concurrent_streams => session.peer_max_concurrent_streams = entry.value,
                // Section 6.5.3: acknowledged whether or not we act on it, and
                // section 6.5.2 requires an unrecognized identifier to be
                // ignored rather than refused.
                else => {},
            }
        }
    }

    fn writeWindowUpdate(session: *Session, stream: u31, increment: u32) Error!void {
        std.debug.assert(increment >= 1);
        std.debug.assert(increment <= window_max);
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment, .big);
        try session.writeFrame(.window_update, 0, stream, &payload);
    }

    /// Send one header block, split across CONTINUATION frames if the peer's
    /// `SETTINGS_MAX_FRAME_SIZE` demands it.
    ///
    /// The split is not hypothetical: the block is built from the user's `-H`
    /// arguments, and the peer may advertise the 16 KiB floor.
    fn writeHeaders(session: *Session, stream: u31, block: []const u8, end_stream: bool) Error!void {
        std.debug.assert(session.peer_max_frame_size >= frame.Header.max_frame_size_min);
        const chunk = session.peer_max_frame_size;

        var offset: usize = 0;
        const first_len = @min(block.len, chunk);
        const end_headers_on_first = first_len == block.len;
        var flags: u8 = 0;
        if (end_stream) flags |= frame.Flag.end_stream.bit();
        if (end_headers_on_first) flags |= frame.Flag.end_headers.bit();
        try session.writeFrame(.headers, flags, stream, block[0..first_len]);
        offset = first_len;

        // Bounded by the block, which every pass shortens by a full frame.
        while (offset < block.len) {
            const len = @min(block.len - offset, chunk);
            const last = offset + len == block.len;
            try session.writeFrame(
                .continuation,
                if (last) frame.Flag.end_headers.bit() else 0,
                stream,
                block[offset..][0..len],
            );
            offset += len;
        }
    }

    fn writeData(session: *Session, stream: u31, body: []const u8) Error!void {
        var offset: usize = 0;
        while (offset < body.len) {
            const len = @min(body.len - offset, session.peer_max_frame_size);
            const last = offset + len == body.len;
            try session.writeFrame(
                .data,
                if (last) frame.Flag.end_stream.bit() else 0,
                stream,
                body[offset..][0..len],
            );
            offset += len;
        }
    }

    fn writeFrame(
        session: *Session,
        frame_type: frame.Type,
        flags: u8,
        stream: u31,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(payload.len <= frame.Header.max_frame_size_max);
        const header: frame.Header = .{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = flags,
            .stream_identifier = stream,
        };
        var octets: [frame.Header.octets]u8 = undefined;
        _ = header.render(&octets) catch return error.Protocol;
        session.writer.writeAll(&octets) catch return error.Io;
        if (payload.len > 0) session.writer.writeAll(payload) catch return error.Io;
    }
};

fn finish(status: ?u16, bytes: u64) Error!httpmod.Response {
    // A response with no `:status` is malformed (RFC 9113 section 8.3.2), and
    // counting it as a completed request would put a latency sample in the
    // histogram for something that never answered.
    const code = status orelse return error.Protocol;
    return .{
        .status = code,
        .bytes = bytes,
        // HTTP/2 has no `Connection: close`; a connection stays usable until
        // GOAWAY or the transport ends, both of which surface as `error.Closed`
        // rather than as a flag on a successful response.
        .keep_alive = true,
    };
}

/// Pull one field block's `:status` out, and check the rest is a well-formed
/// response while we are already walking it.
///
/// Null when the block has no `:status`. That is not an error here: a response
/// may end with a trailers section, which carries no pseudo-headers at all.
/// Whether a *first* block without one is malformed is the caller's to decide,
/// and `finish` is where it is decided.
///
/// The validation is not ceremony: `h2.fields` is the package's answer to RFC
/// 9113 section 8.2, and a load generator that reported a 200 for a response
/// carrying a CR in a header value would be reporting a success the target
/// should have been failed for.
fn decodeStatus(decoder: *hpack.Decoder, buffer: []u8, block: []const u8) Error!?u16 {
    var validator: h2.fields.MessageValidator = .init(.{
        .kind = .response,
        // The floor of section 8.2.1 rather than RFC 9110's full grammar. zrk
        // benchmarks servers it was pointed at, and refusing a response for a
        // header name that is legal-but-not-a-token would turn a measurement
        // into an argument. The rules that matter for a *client* — CR, LF, NUL,
        // pseudo-header placement — are in both readings.
        .rules = .minimal,
    });

    var status: ?u16 = null;
    var iterator = decoder.iterate(buffer, block);
    while (iterator.next() catch return error.Protocol) |field| {
        validator.field(&field) catch return error.Protocol;
        if (!std.mem.eql(u8, field.name, ":status")) continue;
        if (status != null) return error.Protocol;
        status = std.fmt.parseInt(u16, field.value, 10) catch return error.Protocol;
    }
    // No `:status` means this is a trailer section (section 8.3), and the
    // response validator's one closing rule is that a response must have one.
    // Every per-field rule it applied above holds for a trailer section too —
    // section 8.3 constrains it further, not less — so stopping short of
    // `finish` here validates exactly what `Kind.trailer` would.
    if (status == null) return null;
    validator.finish() catch return error.Protocol;
    return status;
}

/// Read the nine octets of a frame header and check what they alone decide.
fn readHeaderImpl(session: *Session) Error!frame.Header {
    const octets = session.reader.take(frame.Header.octets) catch return error.Io;
    const header = frame.Header.parse(octets) catch return error.Protocol;
    // Our own advertised bound, which is what makes every buffer here sized.
    header.validate(advertised_max_frame_size) catch return error.Protocol;
    return header;
}

/// One frame's payload, borrowed from the reader's buffer.
///
/// Valid until the next read, which is exactly how far it is used: every caller
/// parses it and either copies what it needs or finishes with it.
fn readPayloadImpl(session: *Session, header: frame.Header) Error![]const u8 {
    if (header.length == 0) return &.{};
    return session.reader.take(header.length) catch return error.Io;
}

// ── Tests ───────────────────────────────────────────────────────────────────
//
// Driven over fixed buffers rather than sockets: the question these ask is
// whether this module speaks the protocol, and a socket would add a second
// thing that can fail. The server side is built with `h2`'s own renderer, so a
// frame this client accepts is one the codec produced.

const testing = std.testing;

/// Build one frame the way a server would.
fn renderFrame(
    buffer: []u8,
    frame_type: frame.Type,
    flags: u8,
    stream: u31,
    payload: []const u8,
) usize {
    const header: frame.Header = .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_identifier = stream,
    };
    const octets = header.render(buffer) catch unreachable;
    @memcpy(buffer[octets..][0..payload.len], payload);
    return octets + payload.len;
}

/// A response header block, HPACK-encoded the way a server would send one.
fn renderResponseBlock(buffer: []u8, fields: []const hpack.Field) usize {
    // `.static_only` because we advertise `SETTINGS_HEADER_TABLE_SIZE = 0` and
    // this stands in for a server honouring that. A server that ignored it
    // would produce a block our decoder rejects, which is the correct outcome
    // and is what the malformed cases below check.
    var storage: hpack.Encoder.Storage(0) = .{};
    var encoder = storage.encoder(.static_only);
    const encoded = encoder.encode(buffer, fields);
    std.debug.assert(encoded.fields == fields.len);
    return encoded.written;
}

test "a plain exchange reads its status" {
    var wire: [4096]u8 = undefined;
    var used: usize = 0;
    // The server's opening SETTINGS, which `open` waits for.
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});

    var block: [512]u8 = undefined;
    const block_len = renderResponseBlock(&block, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    });
    used += renderFrame(wire[used..], .headers, frame.Flag.end_headers.bit(), 1, block[0..block_len]);
    used += renderFrame(wire[used..], .data, frame.Flag.end_stream.bit(), 1, "hello");

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);

    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    });

    const response = try session.exchange(request[0..request_len], "");
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqual(@as(u64, 5), response.bytes - block_len);
    try testing.expect(response.keep_alive);

    // The preface goes first, before anything else. A server reading it
    // otherwise sees a malformed connection.
    try testing.expect(std.mem.startsWith(u8, out[0..writer.end], preface));
}

test "stream identifiers are odd and ascending" {
    // Section 5.1.1, and the reason it matters here: a client that reused an
    // identifier would have its second request answered on a closed stream.
    var wire: [4096]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});

    var block: [256]u8 = undefined;
    const block_len = renderResponseBlock(&block, &.{.{ .name = ":status", .value = "204" }});
    var stream: u31 = 1;
    while (stream <= 5) : (stream += 2) {
        used += renderFrame(
            wire[used..],
            .headers,
            frame.Flag.end_headers.bit() | frame.Flag.end_stream.bit(),
            stream,
            block[0..block_len],
        );
    }

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});

    var sent: u32 = 0;
    while (sent < 3) : (sent += 1) {
        const response = try session.exchange(request[0..request_len], "");
        try testing.expectEqual(@as(u16, 204), response.status);
    }
    try testing.expectEqual(@as(u31, 7), session.next_stream);
}

test "a response without :status is refused" {
    // RFC 9113 section 8.3.2 makes it malformed, and counting it as completed
    // would put a latency sample in the histogram for a request that was never
    // answered.
    var wire: [2048]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});
    var block: [256]u8 = undefined;
    const block_len = renderResponseBlock(&block, &.{.{ .name = "content-type", .value = "text/plain" }});
    used += renderFrame(
        wire[used..],
        .headers,
        frame.Flag.end_headers.bit() | frame.Flag.end_stream.bit(),
        1,
        block[0..block_len],
    );

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectError(error.Protocol, session.exchange(request[0..request_len], ""));
}

test "a stream that ends with data and no headers is refused" {
    // The other way a response can arrive without a `:status`, and the one the
    // check in `finish` exists for: `decodeStatus` catches a header block that
    // omits it, but a peer that sends DATA with END_STREAM and no HEADERS at
    // all never reaches a header block. Reporting that as a completed request
    // would put a latency sample in the histogram with a status of nothing.
    var wire: [2048]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});
    used += renderFrame(wire[used..], .data, frame.Flag.end_stream.bit(), 1, "body");

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectError(error.Protocol, session.exchange(request[0..request_len], ""));
}

test "GOAWAY stops new streams, and refuses the ones past its last" {
    var wire: [2048]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});
    // Last-stream-id 0, error code 0: a graceful shutdown that took nothing.
    used += renderFrame(wire[used..], .goaway, 0, 0, &[_]u8{0} ** 8);

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});
    // The first exchange went out on stream 1 before the GOAWAY was read, and
    // the GOAWAY says the peer processed nothing past 0: section 6.8 makes that
    // a request safe to send again, not one that failed.
    try testing.expectError(error.Refused, session.exchange(request[0..request_len], ""));
    try testing.expect(session.peer_going_away);
    try testing.expectEqual(@as(u31, 0), session.peer_last_stream);
    // The second is refused before touching the wire.
    try testing.expectError(error.Closed, session.exchange(request[0..request_len], ""));
}

test "a stream at or below GOAWAY's last still gets its response" {
    var wire: [2048]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});
    // Last-stream-id 1: the request about to go out on stream 1 is the peer's
    // to finish, so the exchange waits for it rather than giving up.
    used += renderFrame(wire[used..], .goaway, 0, 0, &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0 });
    var block: [64]u8 = undefined;
    const block_len = renderResponseBlock(&block, &.{.{ .name = ":status", .value = "200" }});
    used += renderFrame(wire[used..], .headers, frame.Flag.end_headers.bit() | frame.Flag.end_stream.bit(), 1, block[0..block_len]);

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});
    const response = try session.exchange(request[0..request_len], "");
    try testing.expectEqual(@as(u16, 200), response.status);
}

test "REFUSED_STREAM is a refusal, any other reset is not" {
    var wire: [2048]u8 = undefined;
    var used: usize = 0;
    used += renderFrame(wire[used..], .settings, 0, 0, &.{});
    // Section 8.7: REFUSED_STREAM (0x7) guarantees no processing.
    used += renderFrame(wire[used..], .rst_stream, 0, 1, &[_]u8{ 0, 0, 0, 0x07 });
    // CANCEL (0x8) promises nothing.
    used += renderFrame(wire[used..], .rst_stream, 0, 3, &[_]u8{ 0, 0, 0, 0x08 });

    var reader: Io.Reader = .fixed(wire[0..used]);
    var out: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    var session: Session = .init(&reader, &writer);
    try session.open();

    var request: [256]u8 = undefined;
    const request_len = renderResponseBlock(&request, &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectError(error.Refused, session.exchange(request[0..request_len], ""));
    try testing.expectError(error.Closed, session.exchange(request[0..request_len], ""));
}
