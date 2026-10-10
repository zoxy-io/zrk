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
    /// The encoded request. Grows to the largest request seen and stays there.
    buffer: std.ArrayList(u8) = .empty,
    /// Field lists and lowered names, per request.
    arena: std.heap.ArenaAllocator,
    seq: ?u64 = null,
    wire: Wire = .{},

    pub fn open(dynamic: *Dynamic, transport: Transport, connection: u32) anyerror!Generator {
        const state = try dynamic.workload.open(connection);
        return .{
            .dynamic = dynamic,
            .transport = transport,
            .state = state,
            .arena = .init(dynamic.allocator),
        };
    }

    pub fn close(g: *Generator) void {
        g.dynamic.workload.close(g.state);
        g.buffer.deinit(g.dynamic.allocator);
        g.arena.deinit();
        g.* = undefined;
    }

    /// The request for `seq`, generating and encoding it unless it is the one
    /// already held. Valid until the next call that generates.
    pub fn at(g: *Generator, seq: u64) anyerror!Wire {
        if (g.seq == seq) return g.wire;
        // Whatever was held is about to be overwritten, so it is not held any
        // more — whether or not what replaces it encodes.
        g.seq = null;
        const request = try g.dynamic.workload.next(g.state, seq);
        g.wire = try g.encode(&request);
        g.seq = seq;
        return g.wire;
    }

    fn encode(g: *Generator, request: *const Request) !Wire {
        const gpa = g.dynamic.allocator;
        const cfg = g.dynamic.cfg;
        const method: httpmod.RequestMethod = .of(request.method);
        g.buffer.clearRetainingCapacity();
        switch (g.transport) {
            .http1 => {
                var out: std.Io.Writer.Allocating = .fromArrayList(gpa, &g.buffer);
                defer g.buffer = out.toArrayList();
                httpmod.writeRequest(&out.writer, cfg, request) catch return error.OutOfMemory;
                return .{ .http1 = out.written(), .method = method };
            },
            .http2 => {
                _ = g.arena.reset(.retain_capacity);
                const fields = try httpmod.buildRequestFields(g.arena.allocator(), cfg, request);
                const block = try httpmod.encodeRequestBlock(g.arena.allocator(), gpa, &g.buffer, fields);
                return .{ .block = block, .body = request.body, .method = method };
            },
            .http3 => {
                _ = g.arena.reset(.retain_capacity);
                const fields = try httpmod.buildRequestFields(g.arena.allocator(), cfg, request);
                try g.buffer.ensureTotalCapacity(gpa, h3conn.request_octets_max);
                const frames = try h3conn.encodeRequest(
                    g.arena.allocator(),
                    g.buffer.allocatedSlice(),
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

    const State = struct { path: [32]u8 = undefined };

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
        return .{ .target = try std.fmt.bufPrint(&s.path, "/n/{d}", .{seq}) };
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
