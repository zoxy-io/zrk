//! `--script`: a wrk script as a `wl.Workload`.
//!
//! The target is scripts written for wrk and wrk2 running unchanged, so the
//! language is LuaJIT's — Lua 5.1 with `bit` and `unpack` — and the API is
//! wrk's: a global `wrk` table (`scheme`, `host`, `port`, `method`, `path`,
//! `headers`, `body`, `format`) and the hooks `init(args)` and `request()`.
//!
//! What wrk's model becomes here:
//!
//! - **A script without `request()`** only edits `wrk.method`, `wrk.path`,
//!   `wrk.headers` and `wrk.body`. That request never changes, so it becomes
//!   the run's fixed request — replayed exactly like `-m`/`-H`/`-b`, with no
//!   Lua on the path at all. Its `init(args)`, if any, runs once.
//! - **A script with `request()`** gets one Lua state per `-t` thread, as in
//!   wrk, shared by that thread's share of the connections — so a counter in
//!   a script counts per thread, exactly as it does under wrk. Each state runs
//!   the script, then `init(args)`, at startup; `request()` runs once per send.
//!
//!   A state is not tied to an executor thread, because zio moves connections
//!   between threads: connection `i` uses state `i % threads`, under that
//!   state's lock. A call is microseconds, so the lock is rarely contended,
//!   and a waiting connection yields its coroutine rather than its thread.
//!   One state per connection was the first design, and at `-c 1000` it cost
//!   a thousand JIT warm-ups on the executor threads — a quarter of the
//!   throughput and a 47 ms p99 — plus 136 MB.
//! - **`request()` returns HTTP/1.1 text**, usually from `wrk.format`. zrk
//!   reads it back into fields, so it can go out over HTTP/2 and HTTP/3 too,
//!   framed and validated like any other request. One request per call: wrk's
//!   pipelining trick of returning several back to back is refused, as
//!   `--streams` is zrk's answer to the question pipelining asks.
//! - **`setup`, `delay`, `response` and `done`** are refused at startup rather
//!   than silently skipped: a script that defines them depends on them, and a
//!   run without them would measure something its author did not write.
//!
//! `args` is wrk's too: `args[0]` is the URL as typed, then whatever followed
//! it on the command line (`zrk --script s.lua http://host/ a b`). The CLI
//! hands it over whole as `cli.Config.script_args`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const cli = @import("cli.zig");
const lua = @import("lua.zig");
const wl = @import("workload.zig");

/// Defines `wrk.format` the way wrk does, so a script that builds requests
/// with it — nearly all of them — produces the same text it does under wrk,
/// `Host` default and `Content-Length` included.
const prelude =
    \\local wrk = wrk
    \\function wrk.format(method, path, headers, body)
    \\  method = method or wrk.method
    \\  path = path or wrk.path
    \\  headers = headers or wrk.headers
    \\  body = body or wrk.body
    \\  if not headers["Host"] then headers["Host"] = wrk.host end
    \\  headers["Content-Length"] = body and string.len(body)
    \\  local s = { string.format("%s %s HTTP/1.1", method, path) }
    \\  for name, value in pairs(headers) do
    \\    s[#s + 1] = string.format("%s: %s", name, value)
    \\  end
    \\  s[#s + 1] = ""
    \\  s[#s + 1] = body or ""
    \\  return table.concat(s, "\r\n")
    \\end
    \\local function unsupported(name)
    \\  return function() error("wrk." .. name .. "() is not supported by zrk", 2) end
    \\end
    \\wrk.lookup = unsupported("lookup")
    \\wrk.connect = unsupported("connect")
;

/// wrk hooks zrk does not run. Each is refused when a script defines it.
const unsupported_hooks = [_][:0]const u8{ "setup", "delay", "response", "done" };

/// Why a script failed, in words, for the CLI to print. The first failure
/// wins: once one connection's script has failed, the others are stopping for
/// the same reason. Written by whichever connection failed first and read
/// only after the fleet is joined.
pub const Diagnostic = struct {
    buffer: [1024]u8 = undefined,
    len: usize = 0,
    claimed: std.atomic.Value(bool) = .init(false),

    pub fn set(d: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        if (d.claimed.swap(true, .acq_rel)) return;
        var w: std.Io.Writer = .fixed(&d.buffer);
        // A message longer than the buffer is cut, not dropped.
        w.print(fmt, args) catch {};
        d.len = w.end;
    }

    pub fn message(d: *const Diagnostic) ?[]const u8 {
        if (!d.claimed.load(.acquire)) return null;
        return d.buffer[0..d.len];
    }
};

pub const Script = struct {
    gpa: Allocator,
    io: Io,
    cfg: *const cli.Config,
    source: []const u8,
    /// `@<path>`: Lua's convention for a chunk named after its file, which is
    /// what makes an error read `bench.lua:12: ...`.
    chunk_name: [:0]const u8,
    args: []const []const u8,
    diagnostic: *Diagnostic,
    /// The state the script was checked in at startup. For a static script it
    /// also owns the strings `static` borrows, so it lives as long as the
    /// script does.
    main: *lua.State,
    /// The request a script without `request()` describes. Null when the
    /// script generates requests.
    static: ?wl.Request = null,
    static_headers: std.ArrayList(wl.Header) = .empty,
    /// The states a generating script runs in, one per thread; `main` is the
    /// first. Empty for a static script.
    pool: []Shared = &.{},

    /// One Lua state, and the lock that makes it safe to share.
    const Shared = struct {
        L: *lua.State,
        mutex: Io.Mutex = .init,
    };

    /// Load `source`, run it to check it, and work out which kind of script it
    /// is; a generating script also gets its states, `init(args)` and all, so
    /// every error a script can raise before its first request is raised
    /// here. `gpa` is used from the connections' threads, so it must be
    /// thread-safe. Errors describe themselves in `diagnostic`.
    pub fn load(
        gpa: Allocator,
        io: Io,
        cfg: *const cli.Config,
        path: []const u8,
        source: []const u8,
        args: []const []const u8,
        diagnostic: *Diagnostic,
    ) !*Script {
        const script = try gpa.create(Script);
        errdefer gpa.destroy(script);
        const chunk_name = try std.fmt.allocPrintSentinel(gpa, "@{s}", .{path}, 0);
        errdefer gpa.free(chunk_name);
        script.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .source = source,
            .chunk_name = chunk_name,
            .args = args,
            .diagnostic = diagnostic,
            .main = undefined,
        };
        script.main = try script.newState();
        errdefer lua.lua_close(script.main);
        const L = script.main;

        for (unsupported_hooks) |hook| {
            lua.getGlobal(L, hook);
            const defined = lua.lua_type(L, -1) == .function;
            lua.pop(L, 1);
            if (defined) {
                diagnostic.set("{s}: zrk does not run wrk's {s}() hook yet; remove it to run this script", .{ path, hook });
                return error.ScriptUnsupported;
            }
        }

        lua.getGlobal(L, "request");
        const generates = lua.lua_type(L, -1) == .function;
        lua.pop(L, 1);
        if (!generates) {
            try script.callInit(L);
            // What the script left in `wrk`, as the request every send carries.
            lua.getGlobal(L, "wrk");
            lua.lua_getfield(L, -1, "format");
            try script.call(L, 0, "wrk.format");
            // Left on the stack: `static` borrows this string.
            const raw = lua.toString(L, -1) orelse unreachable;
            script.static = try script.parse(raw, &script.static_headers);
            return script;
        }

        const pool = try gpa.alloc(Shared, @max(cfg.threads, 1));
        var opened: usize = 0;
        errdefer {
            // `main` is pool[0], and closed by the errdefer above.
            for (pool[1..opened]) |shared| lua.lua_close(shared.L);
            gpa.free(pool);
        }
        pool[0] = .{ .L = L };
        opened = 1;
        while (opened < pool.len) : (opened += 1) pool[opened] = .{ .L = try script.newState() };
        for (pool) |shared| try script.callInit(shared.L);
        script.pool = pool;
        return script;
    }

    pub fn deinit(script: *Script) void {
        // `main` is pool[0] when there is a pool.
        for (script.pool[@min(script.pool.len, 1)..]) |shared| lua.lua_close(shared.L);
        script.gpa.free(script.pool);
        lua.lua_close(script.main);
        script.static_headers.deinit(script.gpa);
        script.gpa.free(script.chunk_name);
        script.gpa.destroy(script);
    }

    /// Put the script into effect on `cfg`: as its fixed request when the
    /// script has no `request()`, else as its workload. `cfg` must outlive
    /// the script's use; for a static script its request borrows from it.
    pub fn apply(script: *Script, cfg: *cli.Config) void {
        if (script.static) |request| {
            cfg.method = request.method;
            cfg.url.target = request.target;
            cfg.headers = request.headers;
            cfg.body = request.body;
        } else {
            cfg.workload = script.workload();
        }
    }

    pub fn workload(script: *Script) wl.Workload {
        return .{ .ptr = script, .vtable = &vtable };
    }

    const vtable: wl.Workload.VTable = .{ .open = open, .next = next, .close = close };

    /// A connection's share of a state, and its own copy of the current
    /// request: the state is shared, so the string `request()` returned can
    /// be collected the moment the lock is let go.
    const Connection = struct {
        shared: *Shared,
        raw: std.ArrayList(u8) = .empty,
        headers: std.ArrayList(wl.Header) = .empty,
    };

    fn open(ptr: *anyopaque, index: u32) anyerror!*anyopaque {
        const script: *Script = @ptrCast(@alignCast(ptr));
        const conn = try script.gpa.create(Connection);
        conn.* = .{ .shared = &script.pool[index % script.pool.len] };
        return conn;
    }

    fn next(ptr: *anyopaque, state: *anyopaque, seq: u64) anyerror!wl.Request {
        _ = seq;
        const script: *Script = @ptrCast(@alignCast(ptr));
        const conn: *Connection = @ptrCast(@alignCast(state));
        {
            const shared = conn.shared;
            shared.mutex.lockUncancelable(script.io);
            defer shared.mutex.unlock(script.io);
            const L = shared.L;
            defer lua.lua_settop(L, 0);
            lua.getGlobal(L, "request");
            try script.call(L, 0, "request()");
            const raw = lua.toString(L, -1) orelse {
                script.diagnostic.set("{s}: request() returned {s}, not a string", .{ script.fileName(), typeName(lua.lua_type(L, -1)) });
                return error.ScriptFailed;
            };
            conn.raw.clearRetainingCapacity();
            try conn.raw.appendSlice(script.gpa, raw);
        }
        return script.parse(conn.raw.items, &conn.headers);
    }

    fn close(ptr: *anyopaque, state: *anyopaque) void {
        const script: *Script = @ptrCast(@alignCast(ptr));
        const conn: *Connection = @ptrCast(@alignCast(state));
        conn.raw.deinit(script.gpa);
        conn.headers.deinit(script.gpa);
        script.gpa.destroy(conn);
    }

    fn fileName(script: *const Script) []const u8 {
        return script.chunk_name[1..];
    }

    /// A state with the standard libraries, `wrk` and the script loaded and
    /// run — everything short of `init`.
    fn newState(script: *Script) !*lua.State {
        const L = lua.luaL_newstate() orelse return error.OutOfMemory;
        errdefer lua.lua_close(L);
        lua.luaL_openlibs(L);
        script.pushWrk(L);
        lua.setGlobal(L, "wrk");

        if (lua.luaL_loadbuffer(L, prelude.ptr, prelude.len, "=zrk") != .ok) unreachable;
        try script.call(L, 0, "the wrk prelude");

        switch (lua.luaL_loadbuffer(L, script.source.ptr, script.source.len, script.chunk_name)) {
            .ok => {},
            .memory => return error.OutOfMemory,
            // The message already names the file and line.
            else => {
                script.diagnostic.set("{s}", .{lua.toString(L, -1) orelse "the script does not load"});
                return error.ScriptFailed;
            },
        }
        try script.call(L, 0, "the script");
        lua.lua_settop(L, 0);
        return L;
    }

    /// `wrk`, as wrk builds it: the URL's parts, and the request `-m`, `-H`
    /// and `-b` describe as the defaults a script edits or `wrk.format` reads.
    fn pushWrk(script: *const Script, L: *lua.State) void {
        const cfg = script.cfg;
        lua.lua_createtable(L, 0, 8);
        setString(L, "scheme", if (cfg.url.isTls()) "https" else "http");
        setString(L, "host", cfg.url.host);
        var port_buf: [8]u8 = undefined;
        setString(L, "port", std.fmt.bufPrint(&port_buf, "{d}", .{cfg.url.port}) catch unreachable);
        setString(L, "method", cfg.method);
        setString(L, "path", cfg.url.target);
        if (cfg.body.len > 0) setString(L, "body", cfg.body);
        lua.lua_createtable(L, 0, @intCast(cfg.headers.len));
        for (cfg.headers) |h| {
            lua.pushString(L, h.name);
            lua.pushString(L, h.value);
            lua.lua_settable(L, -3);
        }
        lua.lua_setfield(L, -2, "headers");
    }

    /// `init(args)`, when the script defines it.
    fn callInit(script: *Script, L: *lua.State) !void {
        lua.getGlobal(L, "init");
        if (lua.lua_type(L, -1) != .function) {
            lua.pop(L, 1);
            return;
        }
        lua.lua_createtable(L, @intCast(script.args.len), 0);
        for (script.args, 0..) |arg, i| {
            lua.pushString(L, arg);
            lua.lua_rawseti(L, -2, @intCast(i));
        }
        try script.call(L, 1, "init()");
        lua.pop(L, 1);
    }

    /// Call the function sitting below its `nargs` arguments at the top of
    /// the stack, leaving its first result in their place. A Lua error is
    /// described in the diagnostic.
    fn call(script: *Script, L: *lua.State, nargs: c_int, what: []const u8) !void {
        switch (lua.lua_pcall(L, nargs, 1, 0)) {
            .ok => {},
            .memory => return error.OutOfMemory,
            else => {
                script.diagnostic.set("{s} failed: {s}", .{ what, lua.toString(L, -1) orelse "(an error that is not a string)" });
                return error.ScriptFailed;
            },
        }
    }

    fn parse(script: *Script, raw: []const u8, headers: *std.ArrayList(wl.Header)) !wl.Request {
        return parseRequest(script.gpa, raw, script.cfg.url.host, headers) catch |err| {
            script.diagnostic.set("{s}: request() returned a request zrk cannot send ({s}): \"{f}\"", .{
                script.fileName(),
                @errorName(err),
                std.zig.fmtString(raw[0..@min(raw.len, 120)]),
            });
            return err;
        };
    }
};

fn setString(L: *lua.State, key: [:0]const u8, value: []const u8) void {
    lua.pushString(L, value);
    lua.lua_setfield(L, -2, key);
}

fn typeName(t: lua.Type) []const u8 {
    return switch (t) {
        .none, .nil => "nil",
        .boolean => "a boolean",
        .table => "a table",
        .function => "a function",
        else => "a value of another type",
    };
}

/// Read one HTTP/1.1 request back into fields. Every slice borrows `raw`;
/// `headers` is reused across calls and holds the header list.
///
/// `Host` is dropped when it names `default_host`, which is what `wrk.format`
/// adds by default — zrk then addresses the origin itself, with the port when
/// it is not the scheme's. Any other `Host` is a virtual host the script
/// asked for, and is kept.
pub fn parseRequest(
    gpa: Allocator,
    raw: []const u8,
    default_host: []const u8,
    headers: *std.ArrayList(wl.Header),
) !wl.Request {
    headers.clearRetainingCapacity();
    const head_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.MissingHeaderEnd;
    var lines = std.mem.splitSequence(u8, raw[0..head_end], "\r\n");

    const request_line = lines.first();
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.MalformedRequestLine;
    const target = parts.next() orelse return error.MalformedRequestLine;
    const version = parts.next() orelse return error.MalformedRequestLine;
    if (parts.next() != null or method.len == 0 or target.len == 0 or
        !std.mem.startsWith(u8, version, "HTTP/1."))
        return error.MalformedRequestLine;

    var content_length: ?usize = null;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len == 0 or std.mem.indexOfAny(u8, name, " \t") != null) return error.MalformedHeader;
        if (std.ascii.eqlIgnoreCase(name, "host") and std.mem.eql(u8, value, default_host)) continue;
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.ChunkedBody;
        if (std.ascii.eqlIgnoreCase(name, "content-length"))
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.MalformedHeader;
        try headers.append(gpa, .{ .name = name, .value = value });
    }

    const body = raw[head_end + 4 ..];
    const length = content_length orelse 0;
    if (body.len < length) return error.TruncatedBody;
    // More after the body is a second request: wrk's pipelining.
    if (body.len > length) return error.PipelinedRequests;

    return .{ .method = method, .target = target, .headers = headers.items, .body = body };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_url = "http://example.test:8080/base?q=1";

fn testConfig() cli.Config {
    return .{ .url = cli.parseUrl(test_url) catch unreachable };
}

fn expectHeader(request: wl.Request, name: []const u8, value: []const u8) !void {
    for (request.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return testing.expectEqualStrings(value, h.value);
    }
    std.debug.print("no header {s}\n", .{name});
    return error.TestExpectedHeader;
}

test "parseRequest reads wrk.format's output back into fields" {
    var headers: std.ArrayList(wl.Header) = .empty;
    defer headers.deinit(testing.allocator);
    const r = try parseRequest(
        testing.allocator,
        "POST /x?y=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        "example.test",
        &headers,
    );
    try testing.expectEqualStrings("POST", r.method);
    try testing.expectEqualStrings("/x?y=1", r.target);
    try testing.expectEqualStrings("hello", r.body);
    // The default Host is zrk's to send; a virtual host is the script's.
    try testing.expectEqual(@as(usize, 2), r.headers.len);
    try expectHeader(r, "content-type", "text/plain");

    const vhost = try parseRequest(testing.allocator, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n", "example.test", &headers);
    try expectHeader(vhost, "host", "other.test");
}

test "parseRequest refuses what it cannot send as one request" {
    var headers: std.ArrayList(wl.Header) = .empty;
    defer headers.deinit(testing.allocator);
    const a = testing.allocator;
    try testing.expectError(error.MissingHeaderEnd, parseRequest(a, "GET / HTTP/1.1\r\n", "h", &headers));
    try testing.expectError(error.MalformedRequestLine, parseRequest(a, "GET /\r\n\r\n", "h", &headers));
    try testing.expectError(error.MalformedHeader, parseRequest(a, "GET / HTTP/1.1\r\nNoColon\r\n\r\n", "h", &headers));
    try testing.expectError(error.TruncatedBody, parseRequest(a, "POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nabc", "h", &headers));
    try testing.expectError(error.PipelinedRequests, parseRequest(a, "GET / HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n", "h", &headers));
    try testing.expectError(error.ChunkedBody, parseRequest(a, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "h", &headers));
}

test "a script without request() becomes the fixed request" {
    var cfg = testConfig();
    var diag: Diagnostic = .{};
    const source =
        \\wrk.method = "POST"
        \\wrk.body   = '{"n":' .. bit.lshift(1, 4) .. '}'
        \\wrk.headers["Content-Type"] = "application/json"
        \\function init(args) wrk.path = "/init/" .. args[1] .. "?u=" .. args[0] end
    ;
    const script = try Script.load(testing.allocator, testing.io, &cfg, "post.lua", source, &.{ test_url, "arg1" }, &diag);
    defer script.deinit();
    script.apply(&cfg);

    try testing.expect(cfg.workload == null);
    try testing.expectEqualStrings("POST", cfg.method);
    try testing.expectEqualStrings("/init/arg1?u=http://example.test:8080/base?q=1", cfg.url.target);
    try testing.expectEqualStrings("{\"n\":16}", cfg.body);
    try expectHeader(.{ .headers = cfg.headers }, "content-type", "application/json");
    try expectHeader(.{ .headers = cfg.headers }, "content-length", "8");
}

test "a script with request() generates per thread state, per send" {
    var cfg = testConfig();
    cfg.threads = 2;
    var diag: Diagnostic = .{};
    const source =
        \\local n = 0
        \\function init(args) prefix = "/" .. args[1] end
        \\function request()
        \\  n = n + 1
        \\  return wrk.format(nil, prefix .. "/" .. n)
        \\end
    ;
    const script = try Script.load(testing.allocator, testing.io, &cfg, "gen.lua", source, &.{ test_url, "p" }, &diag);
    defer script.deinit();
    script.apply(&cfg);
    const w = cfg.workload.?;

    // Connections 0 and 2 share thread 0's state, as two connections on one
    // wrk thread share its counter; connection 1 has thread 1's.
    const a = try w.open(0);
    defer w.close(a);
    const b = try w.open(1);
    defer w.close(b);
    const c = try w.open(2);
    defer w.close(c);
    try testing.expectEqualStrings("/p/1", (try w.next(a, 0)).target);
    const first = try w.next(c, 0);
    try testing.expectEqualStrings("/p/2", first.target);
    try testing.expectEqualStrings("/p/1", (try w.next(b, 0)).target);
    // Another connection's call on the same state leaves this one's request
    // intact: it is a copy.
    _ = try w.next(a, 1);
    try testing.expectEqualStrings("/p/2", first.target);
}

test "script failures say what and where" {
    var cfg = testConfig();
    {
        var diag: Diagnostic = .{};
        try testing.expectError(error.ScriptFailed, Script.load(testing.allocator, testing.io, &cfg, "bad.lua", "this is not lua", &.{}, &diag));
        try testing.expect(std.mem.startsWith(u8, diag.message().?, "bad.lua:1:"));
    }
    {
        var diag: Diagnostic = .{};
        try testing.expectError(error.ScriptUnsupported, Script.load(testing.allocator, testing.io, &cfg, "r.lua", "function response() end", &.{}, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "response()") != null);
    }
    {
        var diag: Diagnostic = .{};
        const script = try Script.load(testing.allocator, testing.io, &cfg, "boom.lua", "function request() error('boom') end", &.{}, &diag);
        defer script.deinit();
        const w = script.workload();
        const conn = try w.open(0);
        defer w.close(conn);
        try testing.expectError(error.ScriptFailed, w.next(conn, 0));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "boom.lua:1: boom") != null);
    }
    {
        var diag: Diagnostic = .{};
        const script = try Script.load(testing.allocator, testing.io, &cfg, "pipe.lua", "function request() return wrk.format() .. wrk.format() end", &.{}, &diag);
        defer script.deinit();
        const w = script.workload();
        const conn = try w.open(0);
        defer w.close(conn);
        try testing.expectError(error.PipelinedRequests, w.next(conn, 0));
    }
}
