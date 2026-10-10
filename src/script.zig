//! `--script`: a wrk script as a `wl.Workload`.
//!
//! The target is scripts written for wrk and wrk2 running unchanged, so the
//! language is LuaJIT's — Lua 5.1 with `bit` and `unpack` — and the API is
//! wrk's: a global `wrk` table (`scheme`, `host`, `port`, `method`, `path`,
//! `headers`, `body`, `format`) and the hooks `setup(thread)`, `init(args)`,
//! `request()`, `response(status, headers, body)` and
//! `done(summary, latency, requests)`.
//!
//! What wrk's model becomes here:
//!
//! - **A static script** — no `request()`, `response()` or `setup()` — only
//!   edits `wrk.method`, `wrk.path`, `wrk.headers` and `wrk.body`. That
//!   request never changes, so it becomes the run's fixed request, replayed
//!   exactly like `-m`/`-H`/`-b` with no Lua on the path at all. Its
//!   `init(args)`, if any, runs once, and its `done`, if any, at the end.
//! - **Any other script** gets one Lua state per `-t` thread, as in wrk,
//!   shared by that thread's share of the connections — so a counter in a
//!   script counts per thread, exactly as it does under wrk. At startup each
//!   state runs the script; then `setup(thread)` runs in the main state once
//!   per thread, and `init(args)` in each thread's state. `request()` runs
//!   once per send, `response()` once per response, and `done()` in the main
//!   state after the report. A script with `response()` but no `request()`
//!   sends each thread's `wrk.format()`, built once.
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
//! - **`response()`** gets what zrk otherwise never keeps: the header fields
//!   (names as sent; lowercase over HTTP/2 and HTTP/3) and the body, still in
//!   any content-encoding. Kept only for a script that defines it.
//! - **`done()`** gets wrk's `summary` (with `errors.deadline` added), and
//!   stats objects with `min`, `max`, `mean`, `stdev` and `:percentile(p)`.
//!   `latency` is the coordinated-omission-corrected histogram in µs;
//!   `requests` is requests per second over each `--interval`, where wrk's is
//!   per thread per 100 ms.
//! - **`setup(thread)`** gets wrk's thread object for `thread:get(name)` and
//!   `thread:set(name, value)`; values cross states as copies, tables
//!   included. `thread:stop()` raises an error. `thread.addr` is not
//!   provided: the address it would take comes from `wrk.lookup`, which
//!   raises an error too.
//! - **`delay()`** is refused at startup: requests are paced by `-R`, or sent
//!   back to back with `--closed`, and a script that defines it depends on a
//!   pacing zrk does not do.
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
const hdr = @import("hdr.zig");

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
    /// wrk's main state: where the script is checked, and where `setup` and
    /// `done` run. For a static script its stack also holds the string
    /// `static` borrows, so it lives as long as the script does.
    main: *lua.State,
    /// The request a static script describes. Null for a running script.
    static: ?wl.Request = null,
    static_headers: std.ArrayList(wl.Header) = .empty,
    /// The thread states a running script uses, one per `-t` thread. Empty
    /// for a static script.
    pool: []Shared = &.{},
    hooks: Hooks,
    /// What `request()` and `response()` cost, one shard per thread state,
    /// recorded inside each state's lock around the Lua call alone: not the
    /// wait for the lock, which is not the script's cost, and not zrk's
    /// parsing of what it returned. A state runs one call at a time, so the
    /// time it records cannot exceed the run's.
    timing: ?wl.Timing = null,

    /// Which of wrk's hooks the script defines.
    const Hooks = struct {
        setup: bool,
        request: bool,
        response: bool,
        done: bool,

        fn of(L: *lua.State) Hooks {
            return .{
                .setup = isFunction(L, "setup"),
                .request = isFunction(L, "request"),
                .response = isFunction(L, "response"),
                .done = isFunction(L, "done"),
            };
        }

        /// A script that needs no Lua while the run is going: everything it
        /// says is in the request it leaves in `wrk`. `setup` makes threads
        /// distinguishable, so a script with it runs in thread states too.
        fn static(hooks: Hooks) bool {
            return !hooks.request and !hooks.response and !hooks.setup;
        }
    };

    /// One thread's Lua state, and the lock that makes it safe to share
    /// between the connections that use it.
    const Shared = struct {
        L: *lua.State,
        /// Its position in the pool, and so its `timing` shard.
        index: u32 = 0,
        mutex: Io.Mutex = .init,
        /// What this thread sends when the script has no `request()`: its
        /// `wrk.format()` after `setup` and `init`, which can differ between
        /// threads. Owned text, read without the lock, since it never changes.
        fixed: ?wl.Request = null,
        fixed_raw: std.ArrayList(u8) = .empty,
        fixed_headers: std.ArrayList(wl.Header) = .empty,

        /// Spin briefly before parking. The lock is held for one Lua call —
        /// microseconds, and never across a yield — so a waiter is almost
        /// always better off spinning than parking its coroutine, whose resume
        /// can lag the unlock by far more than the call took. Parking stays
        /// for the long holds: a JIT trace or a GC cycle inside the call.
        fn lock(shared: *Shared, io: Io) void {
            for (0..spins_before_park) |_| {
                if (shared.mutex.tryLock()) return;
                std.atomic.spinLoopHint();
            }
            shared.mutex.lockUncancelable(io);
        }

        const spins_before_park = 1000;

        fn deinit(shared: *Shared, gpa: Allocator) void {
            lua.lua_close(shared.L);
            shared.fixed_raw.deinit(gpa);
            shared.fixed_headers.deinit(gpa);
        }
    };

    /// Load `source`, check it, and set it up the way wrk would before the
    /// first request: a static script is reduced to its request; a running
    /// script gets its thread states, each through `setup(thread)` and then
    /// `init(args)`. So every error a script can raise before it sends is
    /// raised here. `gpa` is used from the connections' threads, so it must be
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
            .hooks = undefined,
        };
        script.main = try script.newState();
        errdefer lua.lua_close(script.main);
        const main = script.main;

        if (isFunction(main, "delay")) {
            diagnostic.set("{s}: zrk does not run wrk's delay() hook: requests are paced by -R, or sent back to back with --closed", .{path});
            return error.ScriptUnsupported;
        }
        script.hooks = .of(main);

        if (script.hooks.static()) {
            errdefer script.static_headers.deinit(gpa);
            try script.callInit(main);
            // What the script left in `wrk`, as the request every send carries.
            const raw = try script.format(main);
            // Left on the stack: `static` borrows this string.
            script.static = try script.parse(raw, &script.static_headers);
            return script;
        }

        const pool = try gpa.alloc(Shared, @max(cfg.threads, 1));
        var opened: usize = 0;
        errdefer {
            for (pool[0..opened]) |*shared| shared.deinit(gpa);
            gpa.free(pool);
        }
        while (opened < pool.len) : (opened += 1) pool[opened] = .{ .L = try script.newState(), .index = @intCast(opened) };

        // wrk's order: every thread's `setup`, in the main state, then every
        // thread's own `init`.
        if (script.hooks.setup) for (pool) |*shared| {
            lua.getGlobal(main, "setup");
            pushThread(main, shared);
            try script.call(main, 1, "setup()");
            lua.lua_settop(main, 0);
        };
        for (pool) |*shared| {
            try script.callInit(shared.L);
            if (script.hooks.request) continue;
            const raw = try script.format(shared.L);
            try shared.fixed_raw.appendSlice(gpa, raw);
            lua.lua_settop(shared.L, 0);
            shared.fixed = try script.parse(shared.fixed_raw.items, &shared.fixed_headers);
        }
        script.timing = try .init(gpa, @intCast(pool.len));
        script.pool = pool;
        return script;
    }

    pub fn deinit(script: *Script) void {
        if (script.timing) |*t| t.deinit(script.gpa);
        for (script.pool) |*shared| shared.deinit(script.gpa);
        script.gpa.free(script.pool);
        lua.lua_close(script.main);
        script.static_headers.deinit(script.gpa);
        script.gpa.free(script.chunk_name);
        script.gpa.destroy(script);
    }

    /// Put the script into effect on `cfg`: as its fixed request when it is
    /// static, else as its workload. For a static script `cfg` then borrows
    /// from the script, which must outlive the run.
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
        return .{
            .ptr = script,
            // Without `response()` the vtable has no hook, and zrk keeps no
            // response for it.
            .vtable = if (script.hooks.response) &vtable_responding else &vtable,
        };
    }

    const vtable: wl.Workload.VTable = .{ .open = open, .next = next, .close = close, .timing = reportTiming };
    const vtable_responding: wl.Workload.VTable = .{ .open = open, .next = next, .close = close, .response = respond, .timing = reportTiming };

    /// This run's calls, and a clean slate for the next: a library caller
    /// may run one script many times, and each report divides by its own
    /// run's length.
    fn reportTiming(ptr: *anyopaque, gpa: Allocator) anyerror!wl.TimingSummary {
        const script: *Script = @ptrCast(@alignCast(ptr));
        const timing = if (script.timing) |*t| t else return .{};
        const summary = try timing.summarize(gpa);
        timing.reset();
        return summary;
    }

    /// The clock around one Lua call, recorded into the state's shard.
    /// Called with the state's lock held.
    fn timeCall(script: *Script, shared: *const Shared, kind: wl.Timing.Kind, started: Io.Timestamp) void {
        const elapsed = started.durationTo(Io.Timestamp.now(script.io, .awake));
        script.timing.?.record(shared.index, kind, @intCast(@max(elapsed.nanoseconds, 0)));
    }

    /// What a finished run hands `done(summary, latency, requests)`.
    pub const Summary = struct {
        duration_us: u64,
        requests: u64,
        bytes: u64,
        errors: struct {
            connect: u64,
            read: u64,
            write: u64,
            /// Non-2xx/3xx responses, which wrk calls `status`.
            status: u64,
            timeout: u64,
            /// `--deadline` misses, which wrk does not have.
            deadline: u64,
        },
        /// The coordinated-omission-corrected latency histogram, in µs.
        latency: *const hdr.Histogram,
        /// Requests per second, one sample per `--interval` window. wrk's
        /// `requests` is per thread per 100 ms; zrk's windows are the run's.
        rates: []const f64,
    };

    /// Run `done(summary, latency, requests)` in the main state, when the
    /// script defines it. After the run, with every connection joined.
    pub fn done(script: *Script, summary: *const Summary) !void {
        if (!script.hooks.done) return;
        const L = script.main;
        const top = lua.lua_gettop(L);
        defer lua.lua_settop(L, top);

        lua.getGlobal(L, "done");

        lua.lua_createtable(L, 0, 5);
        setNumber(L, "duration", summary.duration_us);
        setNumber(L, "requests", summary.requests);
        setNumber(L, "bytes", summary.bytes);
        lua.lua_createtable(L, 0, 6);
        inline for (.{ "connect", "read", "write", "status", "timeout", "deadline" }) |name| {
            setNumber(L, name, @field(summary.errors, name));
        }
        lua.lua_setfield(L, -2, "errors");

        var latency: Stats = .{ .histogram = summary.latency };
        pushStats(L, &latency);

        const sorted = try script.gpa.dupe(f64, summary.rates);
        defer script.gpa.free(sorted);
        std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
        var requests: Stats = .{ .samples = sorted };
        pushStats(L, &requests);

        try script.call(L, 3, "done()");
    }

    /// A connection's thread state, and its own copy of the current request:
    /// the state is shared, so the string `request()` returned can be
    /// collected the moment the lock is let go.
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
        if (conn.shared.fixed) |request| return request;
        {
            const shared = conn.shared;
            shared.lock(script.io);
            defer shared.mutex.unlock(script.io);
            const L = shared.L;
            defer lua.lua_settop(L, 0);
            const started = Io.Timestamp.now(script.io, .awake);
            lua.getGlobal(L, "request");
            try script.call(L, 0, "request()");
            script.timeCall(shared, .next, started);
            const raw = lua.toString(L, -1) orelse {
                script.diagnostic.set("{s}: request() returned {s}, not a string", .{ script.fileName(), typeName(lua.lua_type(L, -1)) });
                return error.ScriptFailed;
            };
            conn.raw.clearRetainingCapacity();
            try conn.raw.appendSlice(script.gpa, raw);
        }
        return script.parse(conn.raw.items, &conn.headers);
    }

    /// `response(status, headers, body)`, in the connection's thread state.
    /// Touches only the shared state, under its lock — never `conn.raw`,
    /// which the sender may be filling at the same moment.
    fn respond(ptr: *anyopaque, state: *anyopaque, seq: u64, response: *const wl.Response) anyerror!void {
        _ = seq;
        const script: *Script = @ptrCast(@alignCast(ptr));
        const conn: *Connection = @ptrCast(@alignCast(state));
        const shared = conn.shared;
        shared.lock(script.io);
        defer shared.mutex.unlock(script.io);
        const L = shared.L;
        defer lua.lua_settop(L, 0);

        lua.getGlobal(L, "response");
        lua.lua_pushinteger(L, response.status);
        lua.lua_createtable(L, 0, @intCast(response.headers.len));
        for (response.headers) |h| {
            lua.pushString(L, h.name);
            lua.pushString(L, h.value);
            lua.lua_settable(L, -3);
        }
        lua.pushString(L, response.body);
        // From here: the headers table above is the script's input, built by
        // zrk, the same as the request text `next` parses after its call.
        const started = Io.Timestamp.now(script.io, .awake);
        try script.call(L, 3, "response()");
        script.timeCall(shared, .response, started);
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
    /// run — everything short of `setup` and `init`.
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
        if (!isFunction(L, "init")) return;
        lua.getGlobal(L, "init");
        lua.lua_createtable(L, @intCast(script.args.len), 0);
        for (script.args, 0..) |arg, i| {
            lua.pushString(L, arg);
            lua.lua_rawseti(L, -2, @intCast(i));
        }
        try script.call(L, 1, "init()");
        lua.pop(L, 1);
    }

    /// `wrk.format()` with no arguments: the request `wrk` describes. The
    /// string is left on the stack, which is what keeps it alive.
    fn format(script: *Script, L: *lua.State) ![]const u8 {
        lua.getGlobal(L, "wrk");
        lua.lua_getfield(L, -1, "format");
        try script.call(L, 0, "wrk.format");
        // A script may replace `wrk.format`, and the replacement may return
        // anything.
        return lua.toString(L, -1) orelse {
            script.diagnostic.set("{s}: wrk.format() returned {s}, not a string", .{ script.fileName(), typeName(lua.lua_type(L, -1)) });
            return error.ScriptFailed;
        };
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

fn isFunction(L: *lua.State, name: [:0]const u8) bool {
    lua.getGlobal(L, name);
    defer lua.pop(L, 1);
    return lua.lua_type(L, -1) == .function;
}

fn setNumber(L: *lua.State, key: [:0]const u8, value: anytype) void {
    lua.lua_pushnumber(L, switch (@typeInfo(@TypeOf(value))) {
        .float => value,
        else => @floatFromInt(value),
    });
    lua.lua_setfield(L, -2, key);
}

/// wrk's thread object, as `setup(thread)` receives it: `thread:get(name)`
/// and `thread:set(name, value)` read and write a global in that thread's
/// state, copying the value across. `thread:stop()` raises an error, since
/// zrk has no per-thread stop. `thread.addr` is absent: a script sets it
/// from `wrk.lookup`, which raises an error first.
fn pushThread(L: *lua.State, shared: *Script.Shared) void {
    lua.lua_createtable(L, 0, 3);
    inline for (.{ .{ "get", threadGet }, .{ "set", threadSet }, .{ "stop", threadStop } }) |method| {
        lua.lua_pushlightuserdata(L, shared);
        lua.lua_pushcclosure(L, method[1], 1);
        lua.lua_setfield(L, -2, method[0]);
    }
}

fn threadShared(L: *lua.State) *Script.Shared {
    return @ptrCast(@alignCast(lua.lua_touserdata(L, lua.upvalueIndex(1)).?));
}

/// The name argument of `thread:get`/`thread:set`, NUL-terminated as every
/// Lua string is.
fn globalName(L: *lua.State) [*:0]const u8 {
    if (lua.lua_type(L, 2) != .string) lua.raise(L, "thread:get/set: the name must be a string");
    var len: usize = 0;
    return @ptrCast(lua.lua_tolstring(L, 2, &len).?);
}

fn threadGet(state: ?*lua.State) callconv(.c) c_int {
    const L = state.?;
    const target = threadShared(L).L;
    // Raw, as the copy below is: the thread's state is idle, with no
    // `lua_pcall` to catch an error, and an ordinary lookup runs the script's
    // own `_G` metamethods — a strict-globals `__index` that raises on an
    // unknown name would end the process.
    lua.pushString(target, std.mem.span(globalName(L)));
    lua.lua_rawget(target, lua.globals_index);
    // Checked before anything is copied, and raised in `L`: the thread's
    // state is idle, with no `lua_pcall` of its own to catch an error, and
    // one raised there takes the process down.
    if (uncopyable(target, -1, 0)) |message| {
        lua.pop(target, 1);
        lua.raise(L, message);
    }
    copyValue(target, -1, L);
    lua.pop(target, 1);
    return 1;
}

fn threadSet(state: ?*lua.State) callconv(.c) c_int {
    const L = state.?;
    const target = threadShared(L).L;
    const name = globalName(L);
    if (uncopyable(L, 3, 0)) |message| lua.raise(L, message);
    // Raw, for the reason `threadGet` gives: a `__newindex` on `_G` would run
    // in a state with nothing to catch its error.
    lua.pushString(target, std.mem.span(name));
    copyValue(L, 3, target);
    lua.lua_rawset(target, lua.globals_index);
    return 0;
}

fn threadStop(state: ?*lua.State) callconv(.c) c_int {
    lua.raise(state.?, "thread:stop() is not supported by zrk");
}

/// Why the value at `index` in `L` cannot cross to another state, or null
/// when it can: nil, booleans, numbers, strings, and tables of those, as wrk
/// copies between states. Raises nothing, so the caller raises in whichever
/// state has a `lua_pcall` to catch it.
fn uncopyable(L: *lua.State, index: c_int, depth: u32) ?[]const u8 {
    const at = lua.absIndex(L, index);
    switch (lua.lua_type(L, at)) {
        .nil, .none, .boolean, .number, .string => return null,
        .table => {
            // Deep enough for any table a script means to pass, shallow
            // enough that a cycle ends in an error rather than a crash.
            if (depth >= 32) return "thread:get/set: table nested too deeply (or a cycle)";
            lua.lua_pushnil(L);
            while (lua.lua_next(L, at) != 0) {
                const why = uncopyable(L, -2, depth + 1) orelse uncopyable(L, -1, depth + 1);
                if (why) |message| {
                    lua.pop(L, 2);
                    return message;
                }
                lua.pop(L, 1);
            }
            return null;
        },
        else => return "thread:get/set: only nil, booleans, numbers, strings and tables cross threads",
    }
}

/// Push onto `to` a copy of the value at `index` in `from`, which
/// `uncopyable` has cleared.
fn copyValue(from: *lua.State, index: c_int, to: *lua.State) void {
    const at = lua.absIndex(from, index);
    switch (lua.lua_type(from, at)) {
        .boolean => lua.lua_pushboolean(to, lua.lua_toboolean(from, at)),
        .number => lua.lua_pushnumber(to, lua.lua_tonumber(from, at)),
        .string => lua.pushString(to, lua.toString(from, at).?),
        .table => {
            lua.lua_createtable(to, 0, 0);
            lua.lua_pushnil(from);
            while (lua.lua_next(from, at) != 0) {
                copyValue(from, -2, to);
                copyValue(from, -1, to);
                lua.lua_settable(to, -3);
                lua.pop(from, 1);
            }
        },
        else => lua.lua_pushnil(to),
    }
}

/// The source behind one of wrk's stats objects in `done`.
const Stats = union(enum) {
    histogram: *const hdr.Histogram,
    /// Sorted ascending.
    samples: []const f64,

    fn min(s: Stats) f64 {
        return switch (s) {
            .histogram => |h| @floatFromInt(h.min()),
            .samples => |x| if (x.len == 0) 0 else x[0],
        };
    }

    fn max(s: Stats) f64 {
        return switch (s) {
            .histogram => |h| @floatFromInt(h.max()),
            .samples => |x| if (x.len == 0) 0 else x[x.len - 1],
        };
    }

    fn mean(s: Stats) f64 {
        return switch (s) {
            .histogram => |h| h.mean(),
            .samples => |x| blk: {
                if (x.len == 0) break :blk 0;
                var sum: f64 = 0;
                for (x) |v| sum += v;
                break :blk sum / @as(f64, @floatFromInt(x.len));
            },
        };
    }

    fn stdev(s: Stats) f64 {
        return switch (s) {
            .histogram => |h| h.stdDev(),
            .samples => |x| blk: {
                if (x.len < 2) break :blk 0;
                const m = s.mean();
                var sum: f64 = 0;
                for (x) |v| sum += (v - m) * (v - m);
                break :blk @sqrt(sum / @as(f64, @floatFromInt(x.len - 1)));
            },
        };
    }

    /// `p` in percent, 0 to 100, as wrk takes it.
    fn percentile(s: Stats, p: f64) f64 {
        const clamped = std.math.clamp(p, 0, 100);
        return switch (s) {
            .histogram => |h| @floatFromInt(h.valueAtPercentile(clamped)),
            .samples => |x| blk: {
                if (x.len == 0) break :blk 0;
                // Nearest rank.
                const rank = @ceil(clamped / 100 * @as(f64, @floatFromInt(x.len)));
                const i: usize = @intFromFloat(@max(rank, 1) - 1);
                break :blk x[@min(i, x.len - 1)];
            },
        };
    }
};

/// One of wrk's stats objects: `min`, `max`, `mean` and `stdev` as fields, and
/// `:percentile(p)`. Valid for the `done` call it is made for.
fn pushStats(L: *lua.State, stats: *Stats) void {
    lua.lua_createtable(L, 0, 5);
    setNumber(L, "min", stats.min());
    setNumber(L, "max", stats.max());
    setNumber(L, "mean", stats.mean());
    setNumber(L, "stdev", stats.stdev());
    lua.lua_pushlightuserdata(L, stats);
    lua.lua_pushcclosure(L, statsPercentile, 1);
    lua.lua_setfield(L, -2, "percentile");
}

fn statsPercentile(state: ?*lua.State) callconv(.c) c_int {
    const L = state.?;
    const stats: *const Stats = @ptrCast(@alignCast(lua.lua_touserdata(L, lua.upvalueIndex(1)).?));
    // `latency:percentile(99)` passes the table first; `latency.percentile(99)`
    // does not.
    const arg: c_int = if (lua.lua_type(L, 1) == .table) 2 else 1;
    if (lua.lua_type(L, arg) != .number) lua.raise(L, "percentile(p): p must be a number from 0 to 100");
    lua.lua_pushnumber(L, stats.percentile(lua.lua_tonumber(L, arg)));
    return 1;
}

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
        try testing.expectError(error.ScriptUnsupported, Script.load(testing.allocator, testing.io, &cfg, "d.lua", "function delay() return 10 end", &.{}, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "delay()") != null);
    }
    {
        // A function cannot cross between states, as under wrk.
        var diag: Diagnostic = .{};
        try testing.expectError(error.ScriptFailed, Script.load(testing.allocator, testing.io, &cfg, "s.lua", "function setup(t) t:set('f', print) end function request() return wrk.format() end", &.{}, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "only nil, booleans") != null);
        // Raised from zrk's C function, and still located in the script.
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "s.lua:1: thread:get/set") != null);
    }
    {
        // Reading a function out of a thread is an error in the reader's
        // script — the thread's own state has no handler, and an error raised
        // there would end the process.
        var diag: Diagnostic = .{};
        const script = try Script.load(testing.allocator, testing.io, &cfg, "get.lua",
            \\local threads = {}
            \\function setup(t) table.insert(threads, t) end
            \\function request() return wrk.format() end
            \\function done() return threads[1]:get("wrk") end
        , &.{test_url}, &diag);
        defer script.deinit();
        var latency = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
        defer latency.deinit();
        try testing.expectError(error.ScriptFailed, script.done(&.{
            .duration_us = 1,
            .requests = 0,
            .bytes = 0,
            .errors = .{ .connect = 0, .read = 0, .write = 0, .status = 0, .timeout = 0, .deadline = 0 },
            .latency = &latency,
            .rates = &.{},
        }));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "only nil, booleans") != null);
    }
    {
        var diag: Diagnostic = .{};
        try testing.expectError(error.ScriptFailed, Script.load(testing.allocator, testing.io, &cfg, "f.lua", "function wrk.format() return nil end", &.{}, &diag));
        try testing.expect(std.mem.indexOf(u8, diag.message().?, "wrk.format() returned nil") != null);
    }
    {
        // Strict globals, a common wrk-script idiom: `_G` raises on an unknown
        // name. thread:get/set must not run that in the thread's own state,
        // which has no handler for it.
        var diag: Diagnostic = .{};
        const script = try Script.load(testing.allocator, testing.io, &cfg, "strict.lua",
            \\local threads = {}
            \\function setup(t) table.insert(threads, t); t:set("seen", 1) end
            \\function init() setmetatable(_G, { __index = function(_, k) error("undeclared " .. k) end, __newindex = function(_, k) error("undeclared " .. k) end }) end
            \\function request() return wrk.format() end
            \\function done() result = { threads[1]:get("missing"), threads[1]:get("seen") } end
        , &.{test_url}, &diag);
        defer script.deinit();
        var latency = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
        defer latency.deinit();
        try script.done(&.{
            .duration_us = 1,
            .requests = 0,
            .bytes = 0,
            .errors = .{ .connect = 0, .read = 0, .write = 0, .status = 0, .timeout = 0, .deadline = 0 },
            .latency = &latency,
            .rates = &.{},
        });
        // Neither the unknown name nor the write in `setup` raised: raw access
        // never meets the metamethods.
        try testing.expectEqual(@as(?[]const u8, null), diag.message());
    }
    {
        // A static request that cannot be sent frees what it had parsed.
        var diag: Diagnostic = .{};
        try testing.expectError(error.ChunkedBody, Script.load(testing.allocator, testing.io, &cfg, "c.lua",
            \\wrk.headers["X-A"] = "1"
            \\wrk.headers["Transfer-Encoding"] = "chunked"
        , &.{}, &diag));
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

/// A global out of a Lua state, as a string, for the tests to read back.
fn globalString(L: *lua.State, name: [:0]const u8) ?[]const u8 {
    lua.getGlobal(L, name);
    defer lua.pop(L, 1);
    return lua.toString(L, -1);
}

test "setup, response and done run as under wrk" {
    var cfg = testConfig();
    cfg.threads = 2;
    var diag: Diagnostic = .{};
    const source =
        \\local threads = {}
        \\function setup(thread)
        \\  table.insert(threads, thread)
        \\  thread:set("id", #threads)
        \\  thread:set("tags", { a = 1, b = { "x" } })
        \\end
        \\function init(args) responses, bytes, typed = 0, 0, 0 end
        \\function request() return wrk.format(nil, "/thread/" .. id .. "/" .. tags.b[1]) end
        \\function response(status, headers, body)
        \\  if status == 200 then responses = responses + 1 end
        \\  bytes = bytes + #body
        \\  if headers["content-type"] == "text/plain" then typed = typed + 1 end
        \\end
        \\function done(summary, latency, requests)
        \\  local r, b, t = 0, 0, 0
        \\  for _, thread in ipairs(threads) do
        \\    r = r + thread:get("responses")
        \\    b = b + thread:get("bytes")
        \\    t = t + thread:get("typed")
        \\  end
        \\  result = string.format("%d %d %d|%d %d %d %d|%d %d %d|%d %d",
        \\    r, b, t,
        \\    summary.requests, summary.duration, summary.errors.status, summary.errors.deadline,
        \\    latency.min, latency.max, latency:percentile(50),
        \\    requests.max, requests:percentile(50))
        \\end
    ;
    const script = try Script.load(testing.allocator, testing.io, &cfg, "hooks.lua", source, &.{test_url}, &diag);
    defer script.deinit();
    script.apply(&cfg);
    const w = cfg.workload.?;
    try testing.expect(w.vtable.response != null);

    // setup ran once per thread, in order, and its values crossed over.
    const a = try w.open(0);
    defer w.close(a);
    const b = try w.open(1);
    defer w.close(b);
    try testing.expectEqualStrings("/thread/1/x", (try w.next(a, 0)).target);
    try testing.expectEqualStrings("/thread/2/x", (try w.next(b, 0)).target);

    const headers = [_]wl.Header{.{ .name = "content-type", .value = "text/plain" }};
    const ok: wl.Response = .{ .status = 200, .headers = &headers, .body = "hello" };
    const missing: wl.Response = .{ .status = 404, .headers = &.{}, .body = "" };
    try w.vtable.response.?(w.ptr, a, 0, &ok);
    try w.vtable.response.?(w.ptr, a, 1, &ok);
    try w.vtable.response.?(w.ptr, b, 0, &missing);

    var latency = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer latency.deinit();
    for ([_]u64{ 100, 200, 300 }) |v| latency.record(v);
    try script.done(&.{
        .duration_us = 2_000_000,
        .requests = 3,
        .bytes = 10,
        .errors = .{ .connect = 0, .read = 0, .write = 0, .status = 1, .timeout = 0, .deadline = 0 },
        .latency = &latency,
        .rates = &.{ 30, 10, 20 },
    });
    try testing.expectEqualStrings("2 10 2|3 2000000 1 0|100 300 200|30 20", globalString(script.main, "result").?);
}

test "a script with response() and no request() sends each thread's fixed request" {
    var cfg = testConfig();
    var diag: Diagnostic = .{};
    const script = try Script.load(testing.allocator, testing.io, &cfg, "count.lua",
        \\wrk.method = "PUT"
        \\function response(status) n = (n or 0) + 1 end
    , &.{test_url}, &diag);
    defer script.deinit();
    script.apply(&cfg);
    const w = cfg.workload.?;
    const conn = try w.open(0);
    defer w.close(conn);
    const first = try w.next(conn, 0);
    try testing.expectEqualStrings("PUT", first.method);
    // The same request, from the same memory: nothing is regenerated.
    try testing.expectEqual(first.target.ptr, (try w.next(conn, 1)).target.ptr);
}

test "a static script still gets done()" {
    var cfg = testConfig();
    var diag: Diagnostic = .{};
    const script = try Script.load(testing.allocator, testing.io, &cfg, "report.lua",
        \\wrk.method = "POST"
        \\function done(summary) seen = summary.requests end
    , &.{test_url}, &diag);
    defer script.deinit();
    script.apply(&cfg);
    try testing.expect(cfg.workload == null);
    try testing.expectEqualStrings("POST", cfg.method);

    var latency = try hdr.Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
    defer latency.deinit();
    try script.done(&.{
        .duration_us = 1,
        .requests = 7,
        .bytes = 0,
        .errors = .{ .connect = 0, .read = 0, .write = 0, .status = 0, .timeout = 0, .deadline = 0 },
        .latency = &latency,
        .rates = &.{},
    });
    try testing.expectEqualStrings("7", globalString(script.main, "seen").?);
    // The fixed request still borrows from the main state's stack, which
    // `done` left as it found it.
    try testing.expectEqualStrings("POST", cfg.method);
}

test "a script reports its own Lua time, and only calls that ran Lua" {
    var cfg = testConfig();
    cfg.threads = 2;
    var diag: Diagnostic = .{};
    // No `request()`: each thread sends its fixed request, which is no call.
    const fixed = try Script.load(testing.allocator, testing.io, &cfg, "r.lua", "function response() end", &.{test_url}, &diag);
    defer fixed.deinit();
    const w = fixed.workload();
    // zrk does not time around a script; the script times itself.
    try testing.expect(w.vtable.timing != null);
    const conn = try w.open(0);
    defer w.close(conn);
    for (0..3) |seq| _ = try w.next(conn, seq);
    const ok: wl.Response = .{ .status = 200, .headers = &.{}, .body = "" };
    try w.vtable.response.?(w.ptr, conn, 0, &ok);
    const fixed_timing = try w.vtable.timing.?(w.ptr, testing.allocator);
    try testing.expectEqual(@as(u64, 0), fixed_timing.next.calls);
    try testing.expectEqual(@as(u64, 1), fixed_timing.response.calls);

    const generating = try Script.load(testing.allocator, testing.io, &cfg, "g.lua", "function request() return wrk.format() end", &.{test_url}, &diag);
    defer generating.deinit();
    const g = generating.workload();
    const a = try g.open(0);
    defer g.close(a);
    const b = try g.open(1);
    defer g.close(b);
    _ = try g.next(a, 0);
    _ = try g.next(a, 1);
    _ = try g.next(b, 0);
    const timing = try g.vtable.timing.?(g.ptr, testing.allocator);
    try testing.expectEqual(@as(u64, 3), timing.next.calls);
    try testing.expectEqual(@as(u64, 0), timing.response.calls);
    try testing.expect(timing.next.max_ns > 0);

    // A second run of the same script reports its own calls, not both runs'.
    _ = try g.next(a, 2);
    const second = try g.vtable.timing.?(g.ptr, testing.allocator);
    try testing.expectEqual(@as(u64, 1), second.next.calls);
}
