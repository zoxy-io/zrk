//! What a run sends: the interface a request generator implements, the fixed
//! request every run had before it, and the per-connection machinery that
//! turns a generated request into transport bytes.
//!
//! zrk's hot path replays one request built at startup, and that stays the
//! default: a run with no `cli.Config.workload` never reaches this file's
//! `Generator`, and sends exactly the bytes it always did. A workload is the
//! opt-in for requests that change — a different path, header or body per send
//! — which is what a benchmark needs once a server can cache an answer keyed
//! on the request it was given.
//!
//! The interface hands zrk *fields*, never wire bytes. HTTP/2 and HTTP/3 carry
//! a request as an encoded field block, not as text, so a generator that
//! returned HTTP/1.1 bytes would have to be parsed back apart for two of the
//! three transports. Fields encode to all three, through the same functions
//! that build the fixed request — so a generated request is framed, defaulted
//! and validated exactly like a `-H`/`-b` one.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cli = @import("cli.zig");
const httpmod = @import("http.zig");
const h3conn = @import("h3conn.zig");
const hdr = @import("hdr.zig");

pub const Header = cli.Header;

/// One request, as a workload describes it.
///
/// `Host`/`:authority`, `User-Agent`, `Connection` and `Content-Length` are
/// zrk's to add, by the same rules as for the fixed request: each default is
/// skipped when `headers` already names it. The scheme, host and port are the
/// run's (`cli.Config.url`) and cannot change per request, because they decide
/// which connection a request travels on.
pub const Request = struct {
    method: []const u8 = "GET",
    /// Path plus query, starting with '/'.
    target: []const u8 = "/",
    headers: []const Header = &.{},
    body: []const u8 = "",
};

/// A request generator.
///
/// Every call arrives on one connection's coroutine, and different connections
/// call concurrently from different threads: the runtime steals work between
/// executors, so a connection may move threads between two of its own calls.
/// Shared state behind `ptr` is the implementation's to synchronise. State a
/// connection keeps for itself belongs in what `open` returns, which only that
/// connection ever touches — never two calls at once.
pub const Workload = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Once per connection, before its first request, with the
        /// connection's index in `0..cli.Config.connections`. What it returns
        /// is handed back to `next` and `close`. An error fails the run.
        open: *const fn (ptr: *anyopaque, connection: u32) anyerror!*anyopaque,
        /// The request for this connection's send number `seq`.
        ///
        /// `seq` is the connection's position in its send schedule, counting
        /// from 0. It is not dense: a send shed by `--deadline` consumed its
        /// number after the request was generated, and a run's last request
        /// may be generated and never sent. It can repeat: a request the peer
        /// declined unprocessed (an HTTP/2 or HTTP/3 GOAWAY or refusal) is
        /// generated again with its original `seq` before it is resent, so a
        /// workload that derives its request from `seq` resends the same one.
        ///
        /// Called ahead of the send where the schedule allows — before the
        /// pacing wait, and before the clock read that a closed-loop send's
        /// latency is measured from — so the generator's cost is not charged
        /// to the server. Under overload there is no wait to hide it in, and
        /// it lands in the schedule lag instead, which is the honest place.
        ///
        /// Every slice in the result must stay valid until the next `next` or
        /// `close` on the same `state`. An error fails the run: a load test
        /// whose requests could not be built has nothing to report.
        next: *const fn (ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!Request,
        /// Once per connection, when it is done for the run.
        close: *const fn (ptr: *anyopaque, state: *anyopaque) void,
        /// Optional: every completed response, for the request `seq` named.
        ///
        /// Null costs nothing — zrk then keeps no header or body of any
        /// response, as without a workload. Set, every response's header
        /// fields (trailers excluded) and body are collected for it, which
        /// is a copy per response: do not set it for a workload that ignores
        /// what it is given.
        ///
        /// Runs after the response's latency is recorded, so its cost is not
        /// the server's. On a multiplexed HTTP/2 connection it runs on the
        /// receiver while the sender may be in `next` on the same `state`:
        /// what the two share is the implementation's to synchronise. The
        /// `Response` is borrowed for the call. An error fails the run.
        response: ?*const fn (ptr: *anyopaque, state: *anyopaque, seq: u64, response: *const Response) anyerror!void = null,
        /// Optional: what the workload's own calls cost, measured by the
        /// workload, for the report. Covers the calls since the previous
        /// call, and starts counting again. The runner calls it before the
        /// fleet launches, discarding the result — so a run that failed or
        /// was canceled leaves nothing behind — and after it is joined.
        ///
        /// Null, zrk times `next` and `response` from outside, which counts
        /// any wait inside them. A workload whose calls wait on shared state
        /// — a script, for its thread's Lua state — measures inside that wait
        /// and reports here, and zrk then times nothing itself.
        timing: ?*const fn (ptr: *anyopaque, gpa: Allocator) anyerror!TimingSummary = null,
    };

    pub fn open(w: Workload, connection: u32) anyerror!*anyopaque {
        return w.vtable.open(w.ptr, connection);
    }

    pub fn next(w: Workload, state: *anyopaque, seq: u64) anyerror!Request {
        return w.vtable.next(w.ptr, state, seq);
    }

    pub fn close(w: Workload, state: *anyopaque) void {
        w.vtable.close(w.ptr, state);
    }
};

/// A completed response, as `Workload.VTable.response` receives it. Header
/// names are as the server sent them (lowercase over HTTP/2 and HTTP/3).
pub const Response = struct {
    status: u16,
    headers: []const Header,
    body: []const u8,
};

/// One response being collected for `Workload.VTable.response`, reused from
/// one response to the next so the steady state allocates nothing.
///
/// Header text is appended into one buffer and indexed by offsets, and turned
/// into slices only in `view`, once nothing will be appended — a slice taken
/// earlier would dangle the moment the buffer grew.
pub const Capture = struct {
    status: u16 = 0,
    text: std.ArrayList(u8) = .empty,
    spans: std.ArrayList(Span) = .empty,
    body: std.ArrayList(u8) = .empty,
    headers: std.ArrayList(Header) = .empty,
    /// An append ran out of memory somewhere a caller could not be told —
    /// a decoder callback — and `view` reports it.
    failed: bool = false,

    const Span = struct { name: u32, name_len: u32, value_len: u32 };

    pub fn reset(c: *Capture) void {
        c.status = 0;
        c.text.clearRetainingCapacity();
        c.spans.clearRetainingCapacity();
        c.body.clearRetainingCapacity();
        c.failed = false;
    }

    pub fn deinit(c: *Capture, gpa: Allocator) void {
        c.text.deinit(gpa);
        c.spans.deinit(gpa);
        c.body.deinit(gpa);
        c.headers.deinit(gpa);
        c.* = undefined;
    }

    pub fn field(c: *Capture, gpa: Allocator, name: []const u8, value: []const u8) void {
        const at: u32 = @intCast(c.text.items.len);
        c.text.appendSlice(gpa, name) catch return c.fail();
        c.text.appendSlice(gpa, value) catch return c.fail();
        c.spans.append(gpa, .{ .name = at, .name_len = @intCast(name.len), .value_len = @intCast(value.len) }) catch return c.fail();
    }

    pub fn bodyBytes(c: *Capture, gpa: Allocator, bytes: []const u8) void {
        c.body.appendSlice(gpa, bytes) catch c.fail();
    }

    fn fail(c: *Capture) void {
        c.failed = true;
    }

    /// The response collected so far, borrowed from this capture until it is
    /// reset or appended to.
    pub fn view(c: *Capture, gpa: Allocator) !Response {
        if (c.failed) return error.OutOfMemory;
        c.headers.clearRetainingCapacity();
        try c.headers.ensureTotalCapacity(gpa, c.spans.items.len);
        for (c.spans.items) |span| {
            const name = c.text.items[span.name..][0..span.name_len];
            const value = c.text.items[span.name + span.name_len ..][0..span.value_len];
            c.headers.appendAssumeCapacity(.{ .name = name, .value = value });
        }
        return .{ .status = c.status, .headers = c.headers.items, .body = c.body.items };
    }
};

/// The same request on every send: what `-m`, `-H`, `-b` and the URL describe.
///
/// A run with no workload does not go through this as a `Workload` — it
/// replays bytes built once at startup — but those bytes are built from
/// `Fixed.request`, so the two cannot describe different requests. As a
/// `Workload` it is the base case for a generator that varies only some sends,
/// and what the tests use to prove per-request encoding matches the replay
/// path byte for byte.
pub const Fixed = struct {
    request: Request,

    pub fn init(cfg: *const cli.Config) Fixed {
        return .{ .request = .{
            .method = cfg.method,
            .target = cfg.url.target,
            .headers = cfg.headers,
            .body = cfg.body,
        } };
    }

    pub fn workload(fixed: *Fixed) Workload {
        return .{ .ptr = fixed, .vtable = &vtable };
    }

    const vtable: Workload.VTable = .{ .open = open, .next = next, .close = close };

    /// No per-connection state: the request is read-only and shared.
    fn open(ptr: *anyopaque, connection: u32) anyerror!*anyopaque {
        _ = connection;
        return ptr;
    }

    fn next(ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!Request {
        _ = state;
        _ = seq;
        const fixed: *Fixed = @ptrCast(@alignCast(ptr));
        return fixed.request;
    }

    fn close(ptr: *anyopaque, state: *anyopaque) void {
        _ = ptr;
        _ = state;
    }
};

/// A run's dynamic workload, shared by every connection. Owned by the runner;
/// connections reach it through `connection.Params.dynamic`.
pub const Dynamic = struct {
    workload: Workload,
    /// For the run's origin (scheme, host, port) and `--disable-keepalive`,
    /// which every generated request is framed against.
    cfg: *const cli.Config,
    /// Backs each connection's encoding scratch. Must be thread-safe:
    /// connections allocate from it concurrently, on different threads.
    allocator: Allocator,
    failure: Failure = .{},
    /// Where the time spent in the workload's calls is recorded, and the
    /// clock it is read with. Both null: nothing is timed. The runner sets
    /// them, so a run reports what its workload cost.
    timing: ?*Timing = null,
    io: ?std.Io = null,
};

/// The time a workload's calls take, for the report: one histogram of `next`
/// and one of `response`, in nanoseconds.
///
/// Sharded, one shard per `-t` thread, because a histogram per connection is
/// tens of kilobytes and `-c 1000` would spend megabytes on a diagnostic.
/// Connection `i` records into shard `i % shards` under a spin lock: a record
/// is a few nanoseconds against calls of microseconds, so it is rarely
/// contended.
///
/// Used two ways: by `Generator`, timing calls from outside for a workload
/// that does not report its own (`VTable.timing`), where a call's time is
/// wall time and includes any wait inside it; and by a workload that does,
/// recording only what it chooses to count.
pub const Timing = struct {
    shards: []Shard,

    pub const Kind = enum { next, response };

    const Shard = struct {
        lock: std.atomic.Mutex = .unlocked,
        next: hdr.Histogram,
        response: hdr.Histogram,
        /// Exact sums, kept beside the histograms: a histogram clamps what
        /// exceeds its range, and a total built from it would quietly
        /// undercount a call that blocked for longer.
        next_total_ns: u64 = 0,
        response_total_ns: u64 = 0,

        fn of(shard: *Shard, kind: Kind) *hdr.Histogram {
            return switch (kind) {
                .next => &shard.next,
                .response => &shard.response,
            };
        }

        fn total(shard: *Shard, kind: Kind) *u64 {
            return switch (kind) {
                .next => &shard.next_total_ns,
                .response => &shard.response_total_ns,
            };
        }
    };

    /// 1 ns to an hour at two significant figures: calls are microseconds,
    /// a percent of resolution is plenty for a cost, and an hour is past any
    /// call a run could survive. Totals do not depend on it; see `Shard`.
    fn newHistogram(gpa: Allocator) !hdr.Histogram {
        return hdr.Histogram.init(gpa, 1, 3600 * std.time.ns_per_s, 2);
    }

    pub fn init(gpa: Allocator, shards: u32) !Timing {
        const all = try gpa.alloc(Shard, @max(shards, 1));
        var made: usize = 0;
        errdefer {
            for (all[0..made]) |*shard| {
                shard.next.deinit();
                shard.response.deinit();
            }
            gpa.free(all);
        }
        while (made < all.len) : (made += 1) {
            var next = try newHistogram(gpa);
            errdefer next.deinit();
            all[made] = .{ .next = next, .response = try newHistogram(gpa) };
        }
        return .{ .shards = all };
    }

    pub fn deinit(t: *Timing, gpa: Allocator) void {
        for (t.shards) |*shard| {
            shard.next.deinit();
            shard.response.deinit();
        }
        gpa.free(t.shards);
    }

    pub fn record(t: *Timing, connection: u32, kind: Kind, ns: u64) void {
        const shard = &t.shards[connection % t.shards.len];
        while (!shard.lock.tryLock()) std.atomic.spinLoopHint();
        defer shard.lock.unlock();
        shard.of(kind).record(@max(ns, 1));
        shard.total(kind).* +|= ns;
    }

    /// Forget everything recorded, keeping the memory.
    pub fn reset(t: *Timing) void {
        for (t.shards) |*shard| {
            shard.next.reset();
            shard.response.reset();
            shard.next_total_ns = 0;
            shard.response_total_ns = 0;
        }
    }

    /// Every shard merged, once the fleet is joined.
    pub fn summarize(t: *Timing, gpa: Allocator) !TimingSummary {
        var merged = try newHistogram(gpa);
        defer merged.deinit();
        var summary: TimingSummary = .{};
        inline for (.{ Kind.next, Kind.response }) |kind| {
            merged.reset();
            var total: u64 = 0;
            for (t.shards) |*shard| {
                merged.add(shard.of(kind));
                total +|= shard.total(kind).*;
            }
            @field(summary, @tagName(kind)) = .of(&merged, total);
        }
        return summary;
    }
};

/// What `Timing` reports for one kind of call. Nanoseconds throughout.
pub const CallStats = struct {
    calls: u64 = 0,
    total_ns: u64 = 0,
    mean_ns: f64 = 0,
    p50_ns: u64 = 0,
    p99_ns: u64 = 0,
    max_ns: u64 = 0,

    fn of(h: *const hdr.Histogram, total_ns: u64) CallStats {
        const calls = h.count();
        if (calls == 0) return .{};
        return .{
            .calls = calls,
            .total_ns = total_ns,
            .mean_ns = @as(f64, @floatFromInt(total_ns)) / @as(f64, @floatFromInt(calls)),
            .p50_ns = h.valueAtPercentile(50),
            .p99_ns = h.valueAtPercentile(99),
            .max_ns = h.max(),
        };
    }
};

pub const TimingSummary = struct {
    next: CallStats = .{},
    response: CallStats = .{},
};

/// The first error any connection's workload raised, for the runner to return
/// once the fleet is joined. Later errors are dropped: they are almost always
/// the same failure seen from another connection.
pub const Failure = struct {
    code: std.atomic.Value(Code) = .init(0),

    const Code = std.meta.Int(.unsigned, @bitSizeOf(anyerror));

    pub fn record(failure: *Failure, err: anyerror) void {
        _ = failure.code.cmpxchgStrong(0, @intFromError(err), .acq_rel, .monotonic);
    }

    pub fn get(failure: *const Failure) ?anyerror {
        const code = failure.code.load(.acquire);
        return if (code == 0) null else @errorFromInt(code);
    }
};

pub const Transport = enum { http1, http2, http3 };

/// One request, encoded for the transport a connection speaks. Only the fields
/// that transport reads are set.
pub const Wire = struct {
    /// HTTP/1.1: request line, header section and body, ready to write.
    http1: []const u8 = &.{},
    /// HTTP/2: the HPACK header block. The body goes out separately, as DATA.
    block: []const u8 = &.{},
    /// HTTP/3: the HEADERS frame and, with a body, its DATA frame.
    http3: []const u8 = &.{},
    /// HTTP/2's request body.
    body: []const u8 = &.{},
    /// Response framing for HTTP/1.1, where a HEAD response has no body.
    method: httpmod.RequestMethod = .other,
};

/// One connection's view of a dynamic workload: its `open` state, and the
/// scratch the current request is encoded into.
///
/// Holds one request at a time, keyed by `seq`, which is all any transport
/// needs: each has a single sender that finishes writing a request before it
/// generates the next. Asking for the `seq` already held is free, which is
/// what lets a sender generate a request ahead of its send time, then reach
/// the send itself — possibly after a reconnect — without generating it twice.
pub const Generator = struct {
    dynamic: *Dynamic,
    transport: Transport,
    state: *anyopaque,
    /// The request generated furthest along the schedule: the one a sender
    /// prepares ahead of its send time.
    ahead: Entry = .{},
    /// A request generated again behind `ahead` — a resend, after a peer
    /// declined it. Kept apart so a resend never evicts the request already
    /// prepared ahead of it, which would then have to be generated twice.
    behind: Entry = .{},
    /// Field lists and lowered names, per encode.
    arena: std.heap.ArenaAllocator,
    /// The connection's index, which picks its `Timing` shard.
    connection: u32,

    /// One held request: its schedule position and its encoding, which owns
    /// every byte it points at.
    const Entry = struct {
        seq: ?u64 = null,
        wire: Wire = .{},
        /// The encoded request. Grows to the largest request seen and stays.
        buffer: std.ArrayList(u8) = .empty,
        /// HTTP/2's body, copied: the workload's own is valid only until its
        /// next `next`, which the other entry's request may already be.
        body: std.ArrayList(u8) = .empty,

        fn deinit(entry: *Entry, gpa: Allocator) void {
            entry.buffer.deinit(gpa);
            entry.body.deinit(gpa);
        }
    };

    pub fn open(dynamic: *Dynamic, transport: Transport, connection: u32) anyerror!Generator {
        const state = try dynamic.workload.open(connection);
        return .{
            .dynamic = dynamic,
            .transport = transport,
            .state = state,
            .arena = .init(dynamic.allocator),
            .connection = connection,
        };
    }

    /// The clock reading a timed call starts from, when calls are timed.
    fn startTimer(g: *const Generator) ?std.Io.Timestamp {
        if (g.dynamic.timing == null) return null;
        return std.Io.Timestamp.now(g.dynamic.io orelse return null, .awake);
    }

    fn stopTimer(g: *const Generator, started: ?std.Io.Timestamp, kind: Timing.Kind) void {
        const from = started orelse return;
        const elapsed = from.durationTo(std.Io.Timestamp.now(g.dynamic.io.?, .awake));
        g.dynamic.timing.?.record(g.connection, kind, @intCast(@max(elapsed.nanoseconds, 0)));
    }

    /// Whether the workload takes responses, and so whether they are worth
    /// collecting at all.
    pub fn wantsResponses(g: *const Generator) bool {
        return g.dynamic.workload.vtable.response != null;
    }

    /// Hand the response collected in `capture`, to the request `seq` named,
    /// to the workload. Touches only the workload and `capture`, never the
    /// requests this generator holds, so a multiplexed connection's receiver
    /// may call it while its sender is in `at`.
    pub fn respond(g: *const Generator, seq: u64, capture: *Capture) anyerror!void {
        const respond_fn = g.dynamic.workload.vtable.response orelse return;
        const response = try capture.view(g.dynamic.allocator);
        const started = g.startTimer();
        defer g.stopTimer(started, .response);
        try respond_fn(g.dynamic.workload.ptr, g.state, seq, &response);
    }

    pub fn close(g: *Generator) void {
        g.dynamic.workload.close(g.state);
        g.ahead.deinit(g.dynamic.allocator);
        g.behind.deinit(g.dynamic.allocator);
        g.arena.deinit();
        g.* = undefined;
    }

    /// The request for `seq`, generating and encoding it unless it is one
    /// already held. Valid until a call that generates into the same entry:
    /// a request at or past the schedule's furthest point replaces `ahead`,
    /// and a resend behind it replaces `behind`.
    pub fn at(g: *Generator, seq: u64) anyerror!Wire {
        if (g.ahead.seq == seq) return g.ahead.wire;
        if (g.behind.seq == seq) return g.behind.wire;
        const entry = if (g.ahead.seq) |furthest| (if (seq < furthest) &g.behind else &g.ahead) else &g.ahead;
        // Whatever the entry held is about to be overwritten, so it is not
        // held any more — whether or not what replaces it encodes.
        entry.seq = null;
        const request = blk: {
            // The workload's own time only; encoding is zrk's.
            const started = g.startTimer();
            defer g.stopTimer(started, .next);
            break :blk try g.dynamic.workload.next(g.state, seq);
        };
        entry.wire = try g.encode(entry, &request);
        entry.seq = seq;
        return entry.wire;
    }

    fn encode(g: *Generator, entry: *Entry, request: *const Request) !Wire {
        const gpa = g.dynamic.allocator;
        const cfg = g.dynamic.cfg;
        const method: httpmod.RequestMethod = .of(request.method);
        entry.buffer.clearRetainingCapacity();
        switch (g.transport) {
            .http1 => {
                var out: std.Io.Writer.Allocating = .fromArrayList(gpa, &entry.buffer);
                defer entry.buffer = out.toArrayList();
                httpmod.writeRequest(&out.writer, cfg, request) catch return error.OutOfMemory;
                return .{ .http1 = out.written(), .method = method };
            },
            .http2 => {
                _ = g.arena.reset(.retain_capacity);
                const fields = try httpmod.buildRequestFields(g.arena.allocator(), cfg, request);
                const block = try httpmod.encodeRequestBlock(g.arena.allocator(), gpa, &entry.buffer, fields);
                entry.body.clearRetainingCapacity();
                try entry.body.appendSlice(gpa, request.body);
                return .{ .block = block, .body = entry.body.items, .method = method };
            },
            .http3 => {
                _ = g.arena.reset(.retain_capacity);
                const fields = try httpmod.buildRequestFields(g.arena.allocator(), cfg, request);
                try entry.buffer.ensureTotalCapacity(gpa, h3conn.request_octets_max);
                // Exactly the bound, not the capacity: an ArrayList grows past
                // what it was asked for, and a request that fits the buffer
                // but not a stream's send buffer is written short, reset and
                // tried again on every pass — forever, never failing.
                const frames = try h3conn.encodeRequest(
                    g.arena.allocator(),
                    entry.buffer.allocatedSlice()[0..h3conn.request_octets_max],
                    fields,
                    request.body,
                );
                return .{ .http3 = frames, .method = method };
            },
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testConfig(scheme: cli.Scheme) cli.Config {
    var cfg: cli.Config = .{
        .method = "POST",
        .body = "{\"ping\":1}",
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Trace", .value = "abc" },
        },
    };
    cfg.url = .{ .scheme = scheme, .host = "example.test", .port = 8443, .target = "/echo?x=1" };
    return cfg;
}

test "Fixed through the generator encodes the bytes the replay path sends" {
    // The replay path and the generator are two routes to one request. If they
    // ever disagree, `cfg.workload = Fixed` would measure a different request
    // from no workload at all — so this pins them together on every transport.
    inline for (.{ cli.Scheme.http, cli.Scheme.https }) |scheme| {
        inline for (.{ false, true }) |close_each| {
            var cfg = testConfig(scheme);
            cfg.disable_keepalive = close_each;
            var fixed: Fixed = .init(&cfg);
            var dynamic: Dynamic = .{ .workload = fixed.workload(), .cfg = &cfg, .allocator = testing.allocator };

            const h1 = try httpmod.buildRequest(testing.allocator, &cfg);
            defer testing.allocator.free(h1);
            const block = try httpmod.buildRequestBlock(testing.allocator, &cfg);
            defer testing.allocator.free(block);
            const h3 = try h3conn.buildRequest(testing.allocator, &cfg);
            defer testing.allocator.free(h3);

            var g1: Generator = try .open(&dynamic, .http1, 0);
            defer g1.close();
            try testing.expectEqualStrings(h1, (try g1.at(0)).http1);

            var g2: Generator = try .open(&dynamic, .http2, 0);
            defer g2.close();
            const w2 = try g2.at(0);
            try testing.expectEqualSlices(u8, block, w2.block);
            try testing.expectEqualStrings(cfg.body, w2.body);

            var g3: Generator = try .open(&dynamic, .http3, 0);
            defer g3.close();
            try testing.expectEqualSlices(u8, h3, (try g3.at(0)).http3);
        }
    }
}

/// Counts its calls and puts `seq` in the path, so a test can see both which
/// request went out and how many times it was generated.
const Numbered = struct {
    calls: std.atomic.Value(u32) = .init(0),
    fail_at: ?u64 = null,
    opened: std.atomic.Value(u32) = .init(0),
    closed: std.atomic.Value(u32) = .init(0),

    const State = struct { path: [32]u8 = undefined, body: [32]u8 = undefined };

    fn workload(n: *Numbered) Workload {
        return .{ .ptr = n, .vtable = &.{ .open = open, .next = next, .close = close } };
    }

    fn open(ptr: *anyopaque, connection: u32) anyerror!*anyopaque {
        _ = connection;
        const n: *Numbered = @ptrCast(@alignCast(ptr));
        _ = n.opened.fetchAdd(1, .monotonic);
        return try testing.allocator.create(State);
    }

    fn next(ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!Request {
        const n: *Numbered = @ptrCast(@alignCast(ptr));
        const s: *State = @ptrCast(@alignCast(state));
        _ = n.calls.fetchAdd(1, .monotonic);
        if (n.fail_at == seq) return error.ScriptFailed;
        return .{
            .target = try std.fmt.bufPrint(&s.path, "/n/{d}", .{seq}),
            // One buffer per state, rewritten by every call, as a workload's
            // own memory is.
            .body = try std.fmt.bufPrint(&s.body, "body {d}", .{seq}),
        };
    }

    fn close(ptr: *anyopaque, state: *anyopaque) void {
        const n: *Numbered = @ptrCast(@alignCast(ptr));
        _ = n.closed.fetchAdd(1, .monotonic);
        testing.allocator.destroy(@as(*State, @ptrCast(@alignCast(state))));
    }
};

test "the generator holds one request, and asking for it again is free" {
    var cfg = testConfig(.http);
    cfg.method = "GET";
    cfg.body = "";
    var numbered: Numbered = .{};
    var dynamic: Dynamic = .{ .workload = numbered.workload(), .cfg = &cfg, .allocator = testing.allocator };

    var g: Generator = try .open(&dynamic, .http1, 3);
    try testing.expect(std.mem.startsWith(u8, (try g.at(0)).http1, "GET /n/0 HTTP/1.1\r\n"));
    _ = try g.at(0);
    try testing.expectEqual(@as(u32, 1), numbered.calls.load(.monotonic));

    try testing.expect(std.mem.startsWith(u8, (try g.at(1)).http1, "GET /n/1 HTTP/1.1\r\n"));
    try testing.expectEqual(@as(u32, 2), numbered.calls.load(.monotonic));

    // A resent request is generated again with its own number.
    try testing.expect(std.mem.startsWith(u8, (try g.at(0)).http1, "GET /n/0 HTTP/1.1\r\n"));
    try testing.expectEqual(@as(u32, 3), numbered.calls.load(.monotonic));

    g.close();
    try testing.expectEqual(@as(u32, 1), numbered.opened.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), numbered.closed.load(.monotonic));
}

test "a generated request that fails to build is not held" {
    var cfg = testConfig(.http);
    var numbered: Numbered = .{ .fail_at = 1 };
    var dynamic: Dynamic = .{ .workload = numbered.workload(), .cfg = &cfg, .allocator = testing.allocator };

    var g: Generator = try .open(&dynamic, .http2, 0);
    defer g.close();
    _ = try g.at(0);
    try testing.expectError(error.ScriptFailed, g.at(1));
    // Asking again calls the workload again rather than replaying request 0
    // under number 1.
    try testing.expectError(error.ScriptFailed, g.at(1));
    try testing.expectEqual(@as(u32, 3), numbered.calls.load(.monotonic));
}

test "a generated request is validated like a fixed one" {
    const Bad = struct {
        fn open(ptr: *anyopaque, connection: u32) anyerror!*anyopaque {
            _ = connection;
            return ptr;
        }
        fn next(ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!Request {
            _ = .{ ptr, state, seq };
            // RFC 9113 §8.2.2: connection-specific fields are malformed in
            // HTTP/2, so this request cannot go out on that transport.
            return .{ .headers = &.{.{ .name = "Connection", .value = "close" }} };
        }
        fn close(ptr: *anyopaque, state: *anyopaque) void {
            _ = .{ ptr, state };
        }
    };
    var cfg = testConfig(.http);
    var token: u8 = 0;
    var dynamic: Dynamic = .{
        .workload = .{ .ptr = &token, .vtable = &.{ .open = Bad.open, .next = Bad.next, .close = Bad.close } },
        .cfg = &cfg,
        .allocator = testing.allocator,
    };
    var g: Generator = try .open(&dynamic, .http2, 0);
    defer g.close();
    try testing.expectError(error.InvalidRequestHeader, g.at(0));
}

test "Failure keeps the first error" {
    var failure: Failure = .{};
    try testing.expectEqual(@as(?anyerror, null), failure.get());
    failure.record(error.First);
    failure.record(error.Second);
    try testing.expectEqual(@as(?anyerror, error.First), failure.get());
}

test "Capture keeps fields stable across growth and reuses its memory" {
    var c: Capture = .{};
    defer c.deinit(testing.allocator);
    c.status = 200;
    // Enough fields to force the text buffer to grow several times: a slice
    // taken before the last append would point into freed memory.
    var name_buf: [16]u8 = undefined;
    for (0..64) |i| c.field(testing.allocator, try std.fmt.bufPrint(&name_buf, "x-h{d}", .{i}), "value");
    c.bodyBytes(testing.allocator, "hel");
    c.bodyBytes(testing.allocator, "lo");
    const r = try c.view(testing.allocator);
    try testing.expectEqual(@as(usize, 64), r.headers.len);
    try testing.expectEqualStrings("x-h63", r.headers[63].name);
    try testing.expectEqualStrings("value", r.headers[63].value);
    try testing.expectEqualStrings("hello", r.body);

    const capacity = c.text.capacity;
    c.reset();
    c.field(testing.allocator, "a", "b");
    try testing.expectEqual(capacity, c.text.capacity);
    try testing.expectEqual(@as(usize, 1), (try c.view(testing.allocator)).headers.len);
}

test "a resend does not evict the request prepared ahead of it" {
    var cfg = testConfig(.http);
    cfg.method = "GET";
    cfg.body = "";
    var numbered: Numbered = .{};
    var dynamic: Dynamic = .{ .workload = numbered.workload(), .cfg = &cfg, .allocator = testing.allocator };
    var g: Generator = try .open(&dynamic, .http2, 0);
    defer g.close();

    // 5 is prepared ahead; 3 and then 4 are resent before it goes out.
    const five = try g.at(5);
    _ = try g.at(3);
    _ = try g.at(4);
    try testing.expectEqual(@as(u32, 3), numbered.calls.load(.monotonic));
    // 5 is still held, as it was: the workload is not asked for it again.
    const again = try g.at(5);
    try testing.expectEqual(@as(u32, 3), numbered.calls.load(.monotonic));
    try testing.expectEqualSlices(u8, five.block, again.block);
    // And the body is the entry's own copy, not the workload's buffer, which
    // the resends' `next` calls have rewritten since.
    try testing.expectEqualStrings("body 5", again.body);
}

test "an HTTP/3 request too large for a stream fails instead of being retried" {
    const Huge = struct {
        var body: [h3conn.request_octets_max + 100]u8 = @splat('x');
        fn open(ptr: *anyopaque, connection: u32) anyerror!*anyopaque {
            _ = connection;
            return ptr;
        }
        fn next(ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!Request {
            _ = .{ ptr, state, seq };
            return .{ .method = "POST", .body = &body };
        }
        fn close(ptr: *anyopaque, state: *anyopaque) void {
            _ = .{ ptr, state };
        }
    };
    var cfg = testConfig(.https);
    var token: u8 = 0;
    var dynamic: Dynamic = .{
        .workload = .{ .ptr = &token, .vtable = &.{ .open = Huge.open, .next = Huge.next, .close = Huge.close } },
        .cfg = &cfg,
        .allocator = testing.allocator,
    };
    var g: Generator = try .open(&dynamic, .http3, 0);
    defer g.close();
    try testing.expectError(error.RequestTooLarge, g.at(0));
}

test "Timing records each call into its connection's shard, and merges them" {
    var timing = try Timing.init(testing.allocator, 2);
    defer timing.deinit(testing.allocator);
    timing.record(0, .next, 1000);
    timing.record(1, .next, 3000);
    timing.record(2, .next, 2000);
    timing.record(1, .response, 500);
    try testing.expectEqual(@as(u64, 2), timing.shards[0].next.count());
    const summary = try timing.summarize(testing.allocator);
    try testing.expectEqual(@as(u64, 3), summary.next.calls);
    try testing.expectEqual(@as(u64, 1), summary.response.calls);
    // Totals and means are exact, not read back off the histogram.
    try testing.expectEqual(@as(f64, 2000), summary.next.mean_ns);
    try testing.expectEqual(@as(u64, 6000), summary.next.total_ns);
    try testing.expectApproxEqRel(@as(f64, 3000), @as(f64, @floatFromInt(summary.next.max_ns)), 0.02);
}

test "a generator with timing records its workload calls, and only those" {
    var cfg = testConfig(.http);
    var numbered: Numbered = .{};
    var timing = try Timing.init(testing.allocator, 1);
    defer timing.deinit(testing.allocator);
    var dynamic: Dynamic = .{
        .workload = numbered.workload(),
        .cfg = &cfg,
        .allocator = testing.allocator,
        .timing = &timing,
        .io = testing.io,
    };
    var g: Generator = try .open(&dynamic, .http1, 0);
    defer g.close();
    _ = try g.at(0);
    _ = try g.at(0); // held: no call, nothing timed
    _ = try g.at(1);
    try testing.expectEqual(@as(u64, 2), timing.shards[0].next.count());
}

test "a call longer than the histogram's range still counts in full" {
    var timing = try Timing.init(testing.allocator, 1);
    defer timing.deinit(testing.allocator);
    const two_hours: u64 = 2 * 3600 * std.time.ns_per_s;
    timing.record(0, .next, two_hours);
    const summary = try timing.summarize(testing.allocator);
    try testing.expectEqual(two_hours, summary.next.total_ns);
}
