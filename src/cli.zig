//! Command-line parsing and configuration for zrk.
//!
//! Flags are wrk2-compatible where they overlap, plus a few additions for the
//! live dashboard (`--interval`, `--plain`). All parsing is pure (no I/O) so it
//! can be unit tested; the caller passes in an already-collected argv slice.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Scheme = enum { http, https };

pub const Url = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    /// Path plus query, always starting with '/'.
    target: []const u8,

    pub fn isTls(self: Url) bool {
        return self.scheme == .https;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Config = struct {
    threads: u32 = 2,
    connections: u32 = 10,
    /// Total test duration.
    duration_ns: u64 = 10 * std.time.ns_per_s,
    /// Target throughput in requests/second (total, across all connections).
    rate: u64 = 1000,
    /// Per-request timeout.
    timeout_ns: u64 = 2 * std.time.ns_per_s,
    /// Dashboard refresh / snapshot period.
    interval_ns: u64 = 1 * std.time.ns_per_s,

    method: []const u8 = "GET",
    body: []const u8 = "",
    headers: []const Header = &.{},

    /// Print the full latency percentile spectrum in the final report.
    latency: bool = false,
    /// Skip TLS certificate verification.
    insecure: bool = false,
    /// Emit append-only text lines instead of a redrawing TUI (for CI/pipes).
    plain: bool = false,

    url: Url = undefined,
};

pub const ParseError = error{
    MissingUrl,
    UnknownFlag,
    MissingValue,
    InvalidNumber,
    InvalidDuration,
    InvalidUrl,
    InvalidHeader,
    ZeroConnections,
    ZeroThreads,
    ZeroRate,
    OutOfMemory,
};

/// Result of parsing: either a usable config, or a request to print help/usage.
pub const Parsed = union(enum) {
    config: Config,
    help,
};

pub const usage =
    \\zrk — constant-throughput HTTP load generator
    \\
    \\Usage: zrk [options] <url>
    \\
    \\Options:
    \\  -t, --threads     <N>     Number of worker threads       (default 2)
    \\  -c, --connections <N>     Total connections to keep open (default 10)
    \\  -d, --duration    <T>     Test duration, e.g. 30s, 2m    (default 10s)
    \\  -R, --rate        <N>     Target requests/second (total) (default 1000)
    \\  -H, --header  <K: V>      Add a request header (repeatable)
    \\  -m, --method      <M>     HTTP method                    (default GET)
    \\  -b, --body        <S>     Request body
    \\      --timeout     <T>     Per-request timeout            (default 2s)
    \\      --interval    <T>     Dashboard refresh interval     (default 1s)
    \\      --latency             Print full latency spectrum in the final report
    \\  -k, --insecure            Skip TLS certificate verification
    \\      --plain               Append-only output instead of a live dashboard
    \\  -h, --help                Show this help
    \\
;

/// Short options that take a value, so `-t2` can be split into `-t 2`.
const value_short_opts = "tcdRHmb";

/// Parse argv (excluding the program name). Header slices and the header array
/// are allocated from `arena`; string values point into `args` (borrowed).
pub fn parse(arena: Allocator, args: []const []const u8) ParseError!Parsed {
    var cfg: Config = .{};
    var url_arg: ?[]const u8 = null;
    var headers: std.ArrayList(Header) = .empty;

    // Expand wrk-style attached short options (`-t2`) into separate tokens so
    // the main loop only has to deal with `-t 2`.
    var expanded: std.ArrayList([]const u8) = .empty;
    for (args) |arg| {
        if (arg.len > 2 and arg[0] == '-' and arg[1] != '-' and
            std.mem.indexOfScalar(u8, value_short_opts, arg[1]) != null)
        {
            try expanded.append(arena, arg[0..2]);
            try expanded.append(arena, arg[2..]);
        } else {
            try expanded.append(arena, arg);
        }
    }
    const tokens = expanded.items;

    var i: usize = 0;
    while (i < tokens.len) : (i += 1) {
        const arg = tokens[i];
        if (arg.len == 0) continue;

        if (eq(arg, "-h") or eq(arg, "--help")) return .help;

        if (eq(arg, "--latency")) {
            cfg.latency = true;
        } else if (eq(arg, "-k") or eq(arg, "--insecure")) {
            cfg.insecure = true;
        } else if (eq(arg, "--plain") or eq(arg, "--no-tui")) {
            cfg.plain = true;
        } else if (eq(arg, "-t") or eq(arg, "--threads")) {
            cfg.threads = try parseU32(try nextValue(tokens, &i));
        } else if (eq(arg, "-c") or eq(arg, "--connections")) {
            cfg.connections = try parseU32(try nextValue(tokens, &i));
        } else if (eq(arg, "-d") or eq(arg, "--duration")) {
            cfg.duration_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "-R") or eq(arg, "--rate")) {
            cfg.rate = try parseU64(try nextValue(tokens, &i));
        } else if (eq(arg, "--timeout")) {
            cfg.timeout_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "--interval")) {
            cfg.interval_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "-m") or eq(arg, "--method")) {
            cfg.method = try nextValue(tokens, &i);
        } else if (eq(arg, "-b") or eq(arg, "--body")) {
            cfg.body = try nextValue(tokens, &i);
        } else if (eq(arg, "-H") or eq(arg, "--header")) {
            try headers.append(arena, try parseHeader(try nextValue(tokens, &i)));
        } else if (arg[0] == '-' and arg.len > 1) {
            return error.UnknownFlag;
        } else {
            // Positional: the target URL (last one wins).
            url_arg = arg;
        }
    }

    if (cfg.threads == 0) return error.ZeroThreads;
    if (cfg.connections == 0) return error.ZeroConnections;
    if (cfg.rate == 0) return error.ZeroRate;
    // Never run more worker threads than connections.
    if (cfg.threads > cfg.connections) cfg.threads = cfg.connections;

    const raw_url = url_arg orelse return error.MissingUrl;
    cfg.url = try parseUrl(raw_url);
    cfg.headers = try headers.toOwnedSlice(arena);
    return .{ .config = cfg };
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn nextValue(args: []const []const u8, i: *usize) ParseError![]const u8 {
    if (i.* + 1 >= args.len) return error.MissingValue;
    i.* += 1;
    return args[i.*];
}

fn parseU32(s: []const u8) ParseError!u32 {
    return std.fmt.parseInt(u32, s, 10) catch error.InvalidNumber;
}

fn parseU64(s: []const u8) ParseError!u64 {
    return std.fmt.parseInt(u64, s, 10) catch error.InvalidNumber;
}

/// Parse a "Name: Value" header. Whitespace around the value is trimmed.
fn parseHeader(s: []const u8) ParseError!Header {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return error.InvalidHeader;
    const name = s[0..colon];
    if (name.len == 0) return error.InvalidHeader;
    const value = std.mem.trim(u8, s[colon + 1 ..], " \t");
    return .{ .name = name, .value = value };
}

/// Parse a duration like `500ms`, `30s`, `2m`, `1h`, or a bare number (seconds).
pub fn parseDuration(s: []const u8) ParseError!u64 {
    if (s.len == 0) return error.InvalidDuration;

    // Split trailing unit letters from the leading number.
    var split: usize = 0;
    while (split < s.len and (std.ascii.isDigit(s[split]) or s[split] == '.')) split += 1;
    if (split == 0) return error.InvalidDuration;

    const num_str = s[0..split];
    const unit = s[split..];

    const value = std.fmt.parseFloat(f64, num_str) catch return error.InvalidDuration;
    if (value < 0) return error.InvalidDuration;

    const multiplier: f64 = if (unit.len == 0 or eq(unit, "s"))
        @floatFromInt(std.time.ns_per_s)
    else if (eq(unit, "ms"))
        @floatFromInt(std.time.ns_per_ms)
    else if (eq(unit, "us"))
        @floatFromInt(std.time.ns_per_us)
    else if (eq(unit, "m"))
        @floatFromInt(std.time.ns_per_min)
    else if (eq(unit, "h"))
        @floatFromInt(std.time.ns_per_hour)
    else
        return error.InvalidDuration;

    return @intFromFloat(value * multiplier);
}

/// Parse an absolute http(s) URL into scheme/host/port/target.
pub fn parseUrl(raw: []const u8) ParseError!Url {
    var scheme: Scheme = undefined;
    var rest: []const u8 = undefined;
    if (std.mem.startsWith(u8, raw, "http://")) {
        scheme = .http;
        rest = raw["http://".len..];
    } else if (std.mem.startsWith(u8, raw, "https://")) {
        scheme = .https;
        rest = raw["https://".len..];
    } else {
        return error.InvalidUrl;
    }

    // Authority ends at the first '/', '?' or '#'.
    var authority_end: usize = rest.len;
    for (rest, 0..) |ch, idx| {
        if (ch == '/' or ch == '?' or ch == '#') {
            authority_end = idx;
            break;
        }
    }
    const authority = rest[0..authority_end];
    const target = rest[authority_end..];
    if (authority.len == 0) return error.InvalidUrl;

    var host: []const u8 = authority;
    var port: u16 = if (scheme == .https) 443 else 80;

    // Handle IPv6 literal in brackets: [::1]:8080
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidUrl;
        host = authority[1..close];
        const after = authority[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return error.InvalidUrl;
            port = std.fmt.parseInt(u16, after[1..], 10) catch return error.InvalidUrl;
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.InvalidUrl;
    }
    if (host.len == 0) return error.InvalidUrl;

    return .{
        .scheme = scheme,
        .host = host,
        .port = port,
        .target = if (target.len == 0) "/" else target,
    };
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "parseDuration units" {
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), try parseDuration("30s"));
    try testing.expectEqual(@as(u64, 2 * std.time.ns_per_min), try parseDuration("2m"));
    try testing.expectEqual(@as(u64, 500 * std.time.ns_per_ms), try parseDuration("500ms"));
    try testing.expectEqual(@as(u64, std.time.ns_per_hour), try parseDuration("1h"));
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), try parseDuration("5")); // bare = seconds
    try testing.expectError(error.InvalidDuration, parseDuration(""));
    try testing.expectError(error.InvalidDuration, parseDuration("abc"));
    try testing.expectError(error.InvalidDuration, parseDuration("10x"));
}

test "parseUrl http default port and path" {
    const u = try parseUrl("http://example.com/index.html");
    try testing.expectEqual(Scheme.http, u.scheme);
    try testing.expectEqualStrings("example.com", u.host);
    try testing.expectEqual(@as(u16, 80), u.port);
    try testing.expectEqualStrings("/index.html", u.target);
}

test "parseUrl https default port and empty path" {
    const u = try parseUrl("https://example.com");
    try testing.expectEqual(Scheme.https, u.scheme);
    try testing.expectEqual(@as(u16, 443), u.port);
    try testing.expectEqualStrings("/", u.target);
    try testing.expect(u.isTls());
}

test "parseUrl explicit port and query" {
    const u = try parseUrl("http://127.0.0.1:8080/a/b?x=1&y=2");
    try testing.expectEqualStrings("127.0.0.1", u.host);
    try testing.expectEqual(@as(u16, 8080), u.port);
    try testing.expectEqualStrings("/a/b?x=1&y=2", u.target);
}

test "parseUrl ipv6 literal with port" {
    const u = try parseUrl("http://[::1]:9000/path");
    try testing.expectEqualStrings("::1", u.host);
    try testing.expectEqual(@as(u16, 9000), u.port);
    try testing.expectEqualStrings("/path", u.target);
}

test "parseUrl rejects non-http scheme" {
    try testing.expectError(error.InvalidUrl, parseUrl("ftp://example.com"));
    try testing.expectError(error.InvalidUrl, parseUrl("example.com"));
}

test "parseHeader trims value" {
    const h = try parseHeader("Content-Type:  application/json ");
    try testing.expectEqualStrings("Content-Type", h.name);
    try testing.expectEqualStrings("application/json", h.value);
    try testing.expectError(error.InvalidHeader, parseHeader("no-colon"));
    try testing.expectError(error.InvalidHeader, parseHeader(": novalue"));
}

test "parse full command line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = [_][]const u8{
        "-t",         "4",
        "-c",         "100",
        "-d",         "30s",
        "-R",         "2000",
        "-H",         "Accept: application/json",
        "-H",         "X-Test: 1",
        "--latency",  "http://127.0.0.1:8080/index.html",
    };
    const parsed = try parse(arena, &args);
    const cfg = parsed.config;
    try testing.expectEqual(@as(u32, 4), cfg.threads);
    try testing.expectEqual(@as(u32, 100), cfg.connections);
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), cfg.duration_ns);
    try testing.expectEqual(@as(u64, 2000), cfg.rate);
    try testing.expect(cfg.latency);
    try testing.expectEqual(@as(usize, 2), cfg.headers.len);
    try testing.expectEqualStrings("Accept", cfg.headers[0].name);
    try testing.expectEqualStrings("application/json", cfg.headers[0].value);
    try testing.expectEqualStrings("127.0.0.1", cfg.url.host);
    try testing.expectEqual(@as(u16, 8080), cfg.url.port);
}

test "parse help flag" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(), &[_][]const u8{"--help"});
    try testing.expect(parsed == .help);
}

test "parse missing url errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.MissingUrl, parse(arena_state.allocator(), &[_][]const u8{ "-t", "2" }));
}

test "threads clamped to connections" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const args = [_][]const u8{ "-t", "8", "-c", "4", "http://x.com/" };
    const parsed = try parse(arena_state.allocator(), &args);
    try testing.expectEqual(@as(u32, 4), parsed.config.threads);
}
