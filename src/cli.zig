//! Command-line parsing and configuration for zrk.
//!
//! Flags are wrk2-compatible where they overlap, plus a few additions for the
//! live dashboard (`--interval`, `--plain`). All parsing is pure (no I/O) so it
//! can be unit tested; the caller passes in an already-collected argv slice.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// zrk version string, surfaced by `--version` and embedded in JSON reports.
/// Single-sourced from build.zig.zon via the build's options module.
pub const version: []const u8 = @import("build_info").version;

pub const Scheme = enum { http, https };

/// Final-report output format. `text` is the human wrk2-style report (and live
/// dashboard); `json` is a single machine-readable summary object.
pub const Format = enum { text, json };

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
    connections: u32 = 10,
    /// Total test duration.
    duration_ns: u64 = 10 * std.time.ns_per_s,
    /// Target throughput in requests/second (total, across all connections).
    /// With `rate_end` set this is the ramp's *start* rate.
    rate: u64 = 1000,
    /// End rate for a linear ramp (null = constant `rate`). When set, the total
    /// target rate ramps linearly from `rate` to `rate_end` over the duration.
    rate_end: ?u64 = null,
    /// Per-request wire timeout: bounds the attempt on the wire, measured from
    /// the actual send (catches a hung socket / dead server). Does *not* bound
    /// coordinated-omission latency under overload — see `deadline_ns`.
    timeout_ns: u64 = 2 * std.time.ns_per_s,
    /// Coordinated-omission deadline (0 = off): a request whose CO-corrected
    /// latency (measured from its *scheduled* send time) would exceed this is
    /// failed as a `deadline` error rather than recorded, bounding the latency
    /// tail and surfacing sustained overload through the error path.
    deadline_ns: u64 = 0,
    /// Stats window: per-connection publish period, `--timeseries` row cadence,
    /// and the line rate of `--plain` output.
    interval_ns: u64 = 1 * std.time.ns_per_s,
    /// Live dashboard redraw period (TTY only). Independent of the stats
    /// window so the TUI can feel realtime without changing measurement or
    /// timeseries semantics.
    refresh_ns: u64 = 80 * std.time.ns_per_ms,

    method: []const u8 = "GET",
    body: []const u8 = "",
    /// When set (from `-b @FILE`), the caller reads the request body from this
    /// path and fills in `body`. `"-"` means stdin. Parsing stays pure — the
    /// file is not read here.
    body_path: ?[]const u8 = null,
    headers: []const Header = &.{},

    /// Print the full latency percentile spectrum in the final report.
    latency: bool = false,
    /// Skip TLS certificate verification.
    insecure: bool = false,
    /// Emit append-only text lines instead of a redrawing TUI (for CI/pipes).
    plain: bool = false,

    /// Final-report format written at end of run.
    format: Format = .text,
    /// Where the final report goes (null = stdout).
    output_path: ?[]const u8 = null,
    /// If set, also write the HdrHistogram percentile distribution (.hgrm,
    /// wrk2/HdrHistogram-plotter compatible) to this path.
    hdr_path: ?[]const u8 = null,
    /// If set, stream one NDJSON object per `--interval` with that window's
    /// throughput and latency percentiles (a time series, ideal for ramps).
    timeseries_path: ?[]const u8 = null,
    /// Augment each `--timeseries` row with that interval's full latency
    /// distribution as an HdrHistogram V2 base64 blob (lossless, mergeable).
    timeseries_histogram: bool = false,

    /// Record a (coordinated-omission-corrected) latency sample for requests
    /// that hit `--timeout`, so the tail isn't silently truncated. On by
    /// default; `--no-record-timeouts` restores wrk2's drop-on-timeout behavior.
    record_timeouts: bool = true,

    /// CI gate: fail (exit 3) if the final p99 exceeds this many nanoseconds.
    slo_p99_ns: ?u64 = null,
    /// CI gate: fail (exit 3) if the error rate exceeds this fraction (0..1).
    max_error_rate: ?f64 = null,

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
    InvalidFormat,
    ZeroConnections,
    ZeroRate,
    ZeroInterval,
    ZeroRefresh,
    OutOfMemory,
};

/// Result of parsing: a usable config, or a request to print help / version.
pub const Parsed = union(enum) {
    config: Config,
    help,
    version,
};

pub const usage =
    \\zrk — constant-throughput HTTP load generator
    \\
    \\Usage: zrk [options] <url>
    \\
    \\Options:
    \\  -c, --connections <N>     Total connections to keep open (default 10)
    \\  -d, --duration    <T>     Test duration, e.g. 30s, 2m    (default 10s)
    \\  -R, --rate      <N|A:B>   Target requests/second (total); A:B ramps
    \\                            linearly from A to B over the run (default 1000)
    \\  -H, --header  <K: V>      Add a request header (repeatable)
    \\  -m, --method      <M>     HTTP method                    (default GET)
    \\  -b, --body     <S|@FILE>  Request body; @FILE reads it from a file
    \\                            (@- = stdin, @@x = a literal "@x")
    \\      --timeout     <T>     Wire timeout per attempt, from the actual
    \\                            send (default 2s); does not bound CO latency
    \\      --deadline    <T>     Max coordinated-omission latency, from the
    \\                            scheduled send: a request past T is failed as
    \\                            a `deadline` error, not recorded (0 = off)
    \\      --interval    <T>     Stats window: --timeseries rows and --plain
    \\                            lines                          (default 1s)
    \\      --refresh     <T>     Live dashboard redraw rate     (default 80ms)
    \\      --latency             Print full latency spectrum in the final report
    \\  -k, --insecure            Skip TLS certificate verification
    \\      --plain               Append-only output instead of a live dashboard
    \\
    \\Reporting:
    \\      --format  <text|json> Final report format            (default text)
    \\  -o, --output      <FILE>  Write the final report to FILE (default stdout)
    \\      --hdr         <FILE>  Also write the HdrHistogram percentile
    \\                            distribution (.hgrm) to FILE
    \\      --timeseries  <FILE>  Stream per-interval NDJSON (throughput +
    \\                            latency percentiles) to FILE
    \\      --timeseries-histogram  Add each interval's full latency histogram
    \\                            (HdrHistogram base64) to every --timeseries row
    \\      --no-record-timeouts  Drop wire-timed-out requests from the latency
    \\                            histogram (default: record them). Independent
    \\                            of --deadline misses, which are never recorded.
    \\
    \\CI gates (exit code 3 on breach):
    \\      --slo-p99     <T>     Fail if final p99 latency exceeds T
    \\      --max-error-rate <F>  Fail if error rate exceeds F (0..1)
    \\
    \\  -h, --help                Show this help
    \\      --version             Show version
    \\
;

/// Short options that take a value, so `-c100` can be split into `-c 100`.
const value_short_opts = "cdRHmbo";

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
        if (eq(arg, "--version")) return .version;

        if (eq(arg, "--latency")) {
            cfg.latency = true;
        } else if (eq(arg, "-k") or eq(arg, "--insecure")) {
            cfg.insecure = true;
        } else if (eq(arg, "--plain") or eq(arg, "--no-tui")) {
            cfg.plain = true;
        } else if (eq(arg, "--no-record-timeouts")) {
            cfg.record_timeouts = false;
        } else if (eq(arg, "--record-timeouts")) {
            cfg.record_timeouts = true;
        } else if (eq(arg, "--format")) {
            cfg.format = try parseFormat(try nextValue(tokens, &i));
        } else if (eq(arg, "-o") or eq(arg, "--output")) {
            cfg.output_path = try nextValue(tokens, &i);
        } else if (eq(arg, "--hdr")) {
            cfg.hdr_path = try nextValue(tokens, &i);
        } else if (eq(arg, "--timeseries")) {
            cfg.timeseries_path = try nextValue(tokens, &i);
        } else if (eq(arg, "--timeseries-histogram")) {
            cfg.timeseries_histogram = true;
        } else if (eq(arg, "--slo-p99")) {
            cfg.slo_p99_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "--max-error-rate")) {
            cfg.max_error_rate = try parseErrorRate(try nextValue(tokens, &i));
        } else if (eq(arg, "-c") or eq(arg, "--connections")) {
            cfg.connections = try parseU32(try nextValue(tokens, &i));
        } else if (eq(arg, "-d") or eq(arg, "--duration")) {
            cfg.duration_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "-R") or eq(arg, "--rate")) {
            const spec = try parseRateSpec(try nextValue(tokens, &i));
            cfg.rate = spec.start;
            cfg.rate_end = spec.end;
        } else if (eq(arg, "--timeout")) {
            cfg.timeout_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "--deadline")) {
            cfg.deadline_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "--interval")) {
            cfg.interval_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "--refresh")) {
            cfg.refresh_ns = try parseDuration(try nextValue(tokens, &i));
        } else if (eq(arg, "-m") or eq(arg, "--method")) {
            cfg.method = try nextValue(tokens, &i);
        } else if (eq(arg, "-b") or eq(arg, "--body")) {
            const v = try nextValue(tokens, &i);
            // curl/vegeta convention: a leading '@' reads the body from a file
            // (`@-` = stdin), and `@@` escapes a body that literally starts '@'.
            if (v.len >= 2 and v[0] == '@' and v[1] == '@') {
                cfg.body = v[1..];
                cfg.body_path = null;
            } else if (v.len >= 1 and v[0] == '@') {
                cfg.body_path = v[1..];
                cfg.body = "";
            } else {
                cfg.body = v;
                cfg.body_path = null;
            }
        } else if (eq(arg, "-H") or eq(arg, "--header")) {
            try headers.append(arena, try parseHeader(try nextValue(tokens, &i)));
        } else if (arg[0] == '-' and arg.len > 1) {
            return error.UnknownFlag;
        } else {
            // Positional: the target URL (last one wins).
            url_arg = arg;
        }
    }

    if (cfg.connections == 0) return error.ZeroConnections;
    if (cfg.rate == 0) return error.ZeroRate;
    // A ramp toward 0 req/s has no well-defined schedule; require a positive end.
    if (cfg.rate_end) |e| if (e == 0) return error.ZeroRate;
    // A zero interval would busy-loop the snapshot thread and take the publish
    // lock on every request.
    if (cfg.interval_ns == 0) return error.ZeroInterval;
    // Same busy-loop hazard for the dashboard redraw cadence.
    if (cfg.refresh_ns == 0) return error.ZeroRefresh;

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

const RateSpec = struct { start: u64, end: ?u64 };

/// Parse a rate argument: either a scalar (`2000`, constant) or a linear ramp
/// (`START:END`, e.g. `100:5000`).
fn parseRateSpec(s: []const u8) ParseError!RateSpec {
    if (std.mem.indexOfScalar(u8, s, ':')) |colon| {
        return .{
            .start = try parseU64(s[0..colon]),
            .end = try parseU64(s[colon + 1 ..]),
        };
    }
    return .{ .start = try parseU64(s), .end = null };
}

fn parseFormat(s: []const u8) ParseError!Format {
    if (eq(s, "text")) return .text;
    if (eq(s, "json")) return .json;
    return error.InvalidFormat;
}

/// Parse an error-rate threshold. Accepts a bare fraction (`0.01`) or a
/// percentage with a trailing `%` (`1%`); both mean "1%". Must be in [0, 1].
fn parseErrorRate(s: []const u8) ParseError!f64 {
    if (s.len == 0) return error.InvalidNumber;
    if (s[s.len - 1] == '%') {
        const pct = std.fmt.parseFloat(f64, s[0 .. s.len - 1]) catch return error.InvalidNumber;
        return clampErrorRate(pct / 100.0);
    }
    const frac = std.fmt.parseFloat(f64, s) catch return error.InvalidNumber;
    return clampErrorRate(frac);
}

fn clampErrorRate(v: f64) ParseError!f64 {
    if (v < 0 or v > 1) return error.InvalidNumber;
    return v;
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

    // Reject durations the i64-nanosecond timestamp math downstream cannot
    // represent (~292 years) instead of tripping checked-@intFromFloat UB.
    const scaled = value * multiplier;
    if (scaled >= @as(f64, @floatFromInt(std.math.maxInt(i64)))) return error.InvalidDuration;
    return @intFromFloat(scaled);
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

test "durations beyond the timestamp range are rejected, not UB" {
    try testing.expectError(error.InvalidDuration, parseDuration("99999999999999999999"));
    try testing.expectError(error.InvalidDuration, parseDuration("9999999999999h"));
    // Large-but-representable spans still parse.
    try testing.expect(try parseDuration("100000h") > 0);
}

test "zero interval is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectError(error.ZeroInterval, parse(a, &[_][]const u8{ "--interval", "0", "http://x/" }));
    // Zero timeout stays valid: it means "no response timeout".
    const cfg = (try parse(a, &[_][]const u8{ "--timeout", "0", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 0), cfg.timeout_ns);
}

test "deadline flag parses; defaults off" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Off by default (0 = no deadline), independent of --timeout's own default.
    const default = (try parse(a, &[_][]const u8{"http://x/"})).config;
    try testing.expectEqual(@as(u64, 0), default.deadline_ns);
    const cfg = (try parse(a, &[_][]const u8{ "--deadline", "250ms", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 250 * std.time.ns_per_ms), cfg.deadline_ns);
}

test "refresh flag parses and zero is rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = (try parse(a, &[_][]const u8{ "--refresh", "100ms", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), cfg.refresh_ns);
    try testing.expectError(error.ZeroRefresh, parse(a, &[_][]const u8{ "--refresh", "0", "http://x/" }));
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
        "-c",        "100",
        "-d",        "30s",
        "-R",        "2000",
        "-H",        "Accept: application/json",
        "-H",        "X-Test: 1",
        "--latency", "http://127.0.0.1:8080/index.html",
    };
    const parsed = try parse(arena, &args);
    const cfg = parsed.config;
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

test "body: inline, @file, @- stdin, and @@ escape" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Inline literal is unchanged, with no file reference.
    const inline_body = (try parse(a, &[_][]const u8{ "-b", "hello", "http://x/" })).config;
    try testing.expectEqualStrings("hello", inline_body.body);
    try testing.expectEqual(@as(?[]const u8, null), inline_body.body_path);

    // @FILE records a path and leaves body empty (read happens in the caller).
    const from_file = (try parse(a, &[_][]const u8{ "-b", "@payload.json", "http://x/" })).config;
    try testing.expectEqualStrings("payload.json", from_file.body_path.?);
    try testing.expectEqualStrings("", from_file.body);

    // @- means stdin.
    const from_stdin = (try parse(a, &[_][]const u8{ "--body", "@-", "http://x/" })).config;
    try testing.expectEqualStrings("-", from_stdin.body_path.?);

    // @@ escapes to a literal body that starts with '@'.
    const escaped = (try parse(a, &[_][]const u8{ "-b", "@@handle", "http://x/" })).config;
    try testing.expectEqualStrings("@handle", escaped.body);
    try testing.expectEqual(@as(?[]const u8, null), escaped.body_path);
}

test "parse help flag" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(), &[_][]const u8{"--help"});
    try testing.expect(parsed == .help);
}

test "parse version flag" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const parsed = try parse(arena_state.allocator(), &[_][]const u8{"--version"});
    try testing.expect(parsed == .version);
}

test "parse reporting and CI-gate flags" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const args = [_][]const u8{
        "--format",             "json",
        "-o",                   "out.json",
        "--hdr",                "lat.hgrm",
        "--slo-p99",            "250ms",
        "--max-error-rate",     "1%",
        "--no-record-timeouts", "http://127.0.0.1:8080/",
    };
    const cfg = (try parse(arena_state.allocator(), &args)).config;
    try testing.expectEqual(Format.json, cfg.format);
    try testing.expectEqualStrings("out.json", cfg.output_path.?);
    try testing.expectEqualStrings("lat.hgrm", cfg.hdr_path.?);
    try testing.expectEqual(@as(u64, 250 * std.time.ns_per_ms), cfg.slo_p99_ns.?);
    try testing.expectApproxEqAbs(@as(f64, 0.01), cfg.max_error_rate.?, 1e-9);
    try testing.expect(!cfg.record_timeouts);
}

test "record_timeouts defaults on; error rate accepts fraction" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const args = [_][]const u8{ "--max-error-rate", "0.05", "http://x/" };
    const cfg = (try parse(arena_state.allocator(), &args)).config;
    try testing.expect(cfg.record_timeouts);
    try testing.expectApproxEqAbs(@as(f64, 0.05), cfg.max_error_rate.?, 1e-9);
}

test "invalid format and out-of-range error rate are rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectError(error.InvalidFormat, parse(a, &[_][]const u8{ "--format", "yaml", "http://x/" }));
    try testing.expectError(error.InvalidNumber, parse(a, &[_][]const u8{ "--max-error-rate", "2", "http://x/" }));
}

test "parse missing url errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.MissingUrl, parse(arena_state.allocator(), &[_][]const u8{ "-c", "2" }));
}

test "rate parses scalar and ramp forms" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const constant = (try parse(a, &[_][]const u8{ "-R", "2000", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 2000), constant.rate);
    try testing.expectEqual(@as(?u64, null), constant.rate_end);

    const ramp = (try parse(a, &[_][]const u8{ "-R", "100:5000", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 100), ramp.rate);
    try testing.expectEqual(@as(?u64, 5000), ramp.rate_end);

    // Attached short form and ramp-to-zero rejection.
    const attached = (try parse(a, &[_][]const u8{ "-R100:5000", "http://x/" })).config;
    try testing.expectEqual(@as(u64, 100), attached.rate);
    try testing.expectEqual(@as(?u64, 5000), attached.rate_end);
    try testing.expectError(error.ZeroRate, parse(a, &[_][]const u8{ "-R", "100:0", "http://x/" }));
}

test "removed threads flag is rejected as unknown" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectError(error.UnknownFlag, parse(a, &[_][]const u8{ "-t", "8", "http://x.com/" }));
    try testing.expectError(error.UnknownFlag, parse(a, &[_][]const u8{ "--threads", "8", "http://x.com/" }));
}
