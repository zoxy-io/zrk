//! Minimal HTTP/1.1 request building and response parsing for load generation.
//!
//! zrk sends one fixed request repeatedly over a keep-alive connection and only
//! needs enough of the response to (a) learn the status class, (b) consume the
//! body so the connection stays framed for the next request, and (c) count
//! bytes for throughput. It deliberately does not retain header or body content.
//!
//! Response framing is zurl's, not ours. Building the request stays here: zrk
//! builds it once and replays the bytes on every send, which zurl's
//! `writeRequest` cannot do — it re-serializes per call, 93-103 ns against 2.6
//! ns for writing the prebuilt blob, on a hot path that runs millions of times.
//! So this file owns what is fixed for the whole run, and zurl owns what
//! arrives from a server we do not control.

const std = @import("std");
const h2 = @import("h2");
const zurl = @import("zurl");
const Io = std.Io;
const cli = @import("cli.zig");

/// Build the raw request bytes for a config. The result is built once per run
/// and reused for every request on every connection (the request is fixed).
pub fn buildRequest(allocator: std.mem.Allocator, cfg: *const cli.Config) ![]u8 {
    var alloc_writer = Io.Writer.Allocating.init(allocator);
    errdefer alloc_writer.deinit();
    const w = &alloc_writer.writer;

    try w.print("{s} {s} HTTP/1.1\r\n", .{ cfg.method, cfg.url.target });

    // Host header: include the port only when it is non-default.
    const default_port: u16 = if (cfg.url.isTls()) 443 else 80;
    if (cfg.url.port == default_port) {
        try w.print("Host: {s}\r\n", .{cfg.url.host});
    } else {
        try w.print("Host: {s}:{d}\r\n", .{ cfg.url.host, cfg.url.port });
    }

    // Sensible defaults, each skipped when the user supplies the same header
    // via -H (other duplicate -H headers pass through, mirroring wrk).
    var has_ua = false;
    var has_conn = false;
    var has_cl = false;
    for (cfg.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) has_ua = true;
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) has_conn = true;
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) has_cl = true;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    if (!has_ua) try w.writeAll("User-Agent: zrk\r\n");
    // Under `--disable-keepalive` the socket goes away after this response
    // whatever the server answers (see `connection.run`), so say so: a
    // compliant server can then release its end with the response instead of
    // parking an idle connection until its own keep-alive timeout. An explicit
    // `-H Connection: ...` still wins — the flag governs our socket, `-H`
    // governs the bytes, and a run that wants to see how a server reacts to
    // being told `keep-alive` while we close anyway is a legitimate probe.
    if (!has_conn) try w.writeAll(if (cfg.disable_keepalive)
        "Connection: close\r\n"
    else
        "Connection: keep-alive\r\n");

    if (!has_cl) {
        if (cfg.body.len > 0) {
            try w.print("Content-Length: {d}\r\n", .{cfg.body.len});
        } else if (methodAnticipatesBody(cfg.method)) {
            // An empty body on a body-bearing method still needs an explicit
            // length: many servers answer 411 otherwise.
            try w.writeAll("Content-Length: 0\r\n");
        }
    }
    try w.writeAll("\r\n");
    try w.writeAll(cfg.body);

    return alloc_writer.toOwnedSlice();
}

/// One request field, in the form both HPACK and QPACK take it.
///
/// A local type rather than either encoder's. h2 vendors its own HPACK and h3
/// depends on zoxy-io/hpack, so `h2.hpack.Field` and `h3.qpack.Field` are
/// distinct nominal types of identical shape — and the rules that decide
/// *which* fields zrk's request carries are not rules to write twice. They are
/// written once, here, and each transport maps this list into its own encoder's
/// type at the last moment.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// The field list zrk's request is, for either of the two transports that take
/// one. Every string it points at is allocated in `scratch`, which the caller
/// owns; the encoders copy the octets in, so the list dies with the encode.
///
/// Validated here rather than by each caller: a malformed request would be
/// answered with a stream error on every single stream, and the run would
/// report the target failing when it was us.
pub fn buildRequestFields(scratch: std.mem.Allocator, cfg: *const cli.Config) ![]const Field {
    var fields: std.ArrayList(Field) = .empty;

    // RFC 9113 §8.3 and RFC 9114 §4.3.1 name the same four, and they come first.
    try fields.append(scratch, .{ .name = ":method", .value = cfg.method });
    try fields.append(scratch, .{ .name = ":scheme", .value = if (cfg.url.isTls()) "https" else "http" });
    try fields.append(scratch, .{ .name = ":path", .value = cfg.url.target });

    // §8.3.1: `:authority` replaces `Host`, and carries the port only when it
    // is not the scheme's default — the same rule `buildRequest` applies to
    // `Host`, so every transport addresses the same origin.
    const default_port: u16 = if (cfg.url.isTls()) 443 else 80;
    const authority = if (cfg.url.port == default_port)
        try scratch.dupe(u8, cfg.url.host)
    else
        try std.fmt.allocPrint(scratch, "{s}:{d}", .{ cfg.url.host, cfg.url.port });
    try fields.append(scratch, .{ .name = ":authority", .value = authority });

    var has_ua = false;
    var has_cl = false;
    for (cfg.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) has_ua = true;
        if (std.ascii.eqlIgnoreCase(h.name, "content-length")) has_cl = true;
        // §8.2.1 requires field names to be lowercase on the wire. `-H` takes
        // them in whatever case the user typed, exactly as HTTP/1.1 does, so
        // the case is folded here rather than refused — the user asked for a
        // header, not for a lesson.
        try fields.append(scratch, .{
            .name = try lowerName(scratch, h.name),
            .value = h.value,
        });
    }
    if (!has_ua) try fields.append(scratch, .{ .name = "user-agent", .value = "zrk" });

    // No `Connection: keep-alive`: §8.2.2 makes connection-specific header
    // fields malformed above HTTP/1.1, and `buildRequest` adds one.
    if (!has_cl) {
        if (cfg.body.len > 0) {
            try fields.append(scratch, .{
                .name = "content-length",
                .value = try std.fmt.allocPrint(scratch, "{d}", .{cfg.body.len}),
            });
        } else if (methodAnticipatesBody(cfg.method)) {
            try fields.append(scratch, .{ .name = "content-length", .value = "0" });
        }
    }

    try validateRequestFields(fields.items);
    return fields.items;
}

/// The HTTP/2 request as one HPACK-encoded header block, built once.
///
/// Encoded with `Encoder.Mode.static_only`, which is an API guarantee in
/// zoxy-io/h2 rather than an optimisation: the block depends on no encoder
/// state, so it can be replayed byte-identically on every stream for the whole
/// run. A block that touched the dynamic table would be legal only in the
/// order it was produced, and zrk's request never changes.
///
/// The result is the caller's to free, like `buildRequest`'s.
pub fn buildRequestBlock(allocator: std.mem.Allocator, cfg: *const cli.Config) ![]u8 {
    // The field list and every string it points at live only until the block is
    // encoded — HPACK copies the octets in. An arena rather than a `defer free`
    // per allocation because there are a variable number of them (one lowered
    // name per `-H`), which is exactly the bookkeeping that leaks.
    var scratch: std.heap.ArenaAllocator = .init(allocator);
    defer scratch.deinit();
    const tmp = scratch.allocator();

    const fields = try buildRequestFields(tmp, cfg);

    // Into h2's own field type at the last moment; see `Field`.
    const hpack_fields = try tmp.alloc(h2.hpack.Field, fields.len);
    for (hpack_fields, fields) |*out, in| out.* = .{ .name = in.name, .value = in.value };

    return encodeBlock(allocator, hpack_fields);
}

/// Encode into a buffer sized from the fields themselves.
fn encodeBlock(allocator: std.mem.Allocator, fields: []const h2.hpack.Field) ![]u8 {
    // An upper bound rather than a guess: a literal costs its two lengths, the
    // octets themselves, and a few of framing, and Huffman only ever shortens.
    var bound: usize = 0;
    for (fields) |field| bound += field.name.len + field.value.len + block_field_overhead;

    const buffer = try allocator.alloc(u8, bound);
    errdefer allocator.free(buffer);

    var storage: h2.hpack.Encoder.Storage(0) = .{};
    var encoder = storage.encoder(.static_only);
    const encoded = encoder.encode(buffer, fields);
    // `encode` reports how many fields fit rather than failing, so a short
    // buffer is a partial block. The bound above makes that unreachable, and
    // this is what says so.
    if (encoded.fields != fields.len) return error.RequestTooLarge;

    return allocator.realloc(buffer, encoded.written);
}

/// Framing octets one literal field can cost on top of its text: the two length
/// prefixes and the representation byte, each of which is at most five octets
/// for a length this side of 4 GiB.
const block_field_overhead: usize = 16;

fn lowerName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const lowered = try allocator.alloc(u8, name.len);
    for (lowered, name) |*out, in| out.* = std.ascii.toLower(in);
    return lowered;
}

/// The request has to be a well-formed HTTP/2 request before it is sent a
/// million times.
fn validateRequestFields(fields: []const Field) !void {
    var validator: h2.fields.MessageValidator = .init(.{
        .kind = .request,
        // The stricter reading for what *we* send. zrk is lenient about what a
        // target returns — a measurement should not become an argument — but a
        // request it generates itself has no excuse for being questionable.
        .rules = .strict,
    });
    // h2's validator for the HTTP/3 request too. RFC 9114 §4.3 restates RFC
    // 9113 §8.3's rules for the same four pseudo-headers, so one validator
    // answers for both — and it is the request *this program builds*, not
    // anything a peer sent, so the two readings cannot diverge on real input.
    for (fields) |field| {
        const one: h2.hpack.Field = .{ .name = field.name, .value = field.value };
        validator.field(&one) catch return error.InvalidRequestHeader;
    }
    validator.finish() catch return error.InvalidRequestHeader;
}

/// Methods whose semantics anticipate request content (RFC 9110 §9.3), for
/// which an empty body still gets an explicit `Content-Length: 0`.
fn methodAnticipatesBody(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "POST") or
        std.ascii.eqlIgnoreCase(method, "PUT") or
        std.ascii.eqlIgnoreCase(method, "PATCH");
}

pub const StatusClass = enum {
    informational, // 1xx
    success, // 2xx
    redirect, // 3xx
    client_error, // 4xx
    server_error, // 5xx

    pub fn of(status: u16) StatusClass {
        return switch (status / 100) {
            1 => .informational,
            2 => .success,
            3 => .redirect,
            4 => .client_error,
            else => .server_error,
        };
    }
};

pub const Response = struct {
    status: u16,
    /// Total bytes consumed from the wire for this response (headers + body).
    bytes: u64,
    /// Whether the server indicated the connection may be reused.
    keep_alive: bool,
};

pub const ParseError = error{
    MalformedStatusLine,
    MalformedHeader,
    MalformedChunk,
    UnexpectedEof,
    HeaderTooLong,
    ReadFailed,
};

/// The one method distinction response parsing needs: responses to HEAD carry
/// framing headers describing the body a GET would have returned, but never
/// the body itself (RFC 9112 §6.3). Every other method — including arbitrary
/// `-m` strings zrk passes through verbatim — frames normally.
pub const RequestMethod = enum {
    other,
    head,

    /// Classify a raw method string (methods are case-sensitive per RFC 9110,
    /// but we accept any casing of HEAD rather than misframe the response).
    pub fn of(method: []const u8) RequestMethod {
        return if (std.ascii.eqlIgnoreCase(method, "HEAD")) .head else .other;
    }

    /// What zurl's `streamBody` takes. Only the HEAD/not-HEAD distinction
    /// survives the trip, because that is the only thing a method decides
    /// about a RESPONSE — and it is what lets `-m` keep taking any string at
    /// all: `std.http.Method` is a closed enum of nine and cannot name
    /// `PROPPATCH`, while nothing downstream of here needs it to.
    pub fn toStd(m: RequestMethod) std.http.Method {
        return switch (m) {
            .head => .HEAD,
            .other => .GET,
        };
    }
};

/// Parse one HTTP/1.1 response from `r`, consuming its full body so the reader
/// is positioned at the start of the next response. `method` is the request's
/// framing classification (see `RequestMethod`).
///
/// `r`'s buffer must be able to hold the response's ENTIRE head, not merely
/// its longest header line as the hand-rolled parser this replaces needed:
/// zurl scans a contiguous slice, so the buffer is the bound. Connections size
/// theirs at `read_buffer_size`, which is 16 KiB against a 64 KiB
/// `max_head_bytes` default, so the buffer is what a real server would hit
/// first — and `error.HeaderTooLong` is what it hits.
pub fn parseResponse(r: *Io.Reader, method: RequestMethod) ParseError!Response {
    // The body goes nowhere: zrk measures responses, it does not read them.
    // The sink is how zurl hands bytes over, and `Discarding` is the one that
    // counts them and drops them — its drain cannot fail, which is why the
    // `WriteFailed` arm of `mapError` is unreachable in this caller.
    var discard_buf: [512]u8 = undefined;
    var discarding: Io.Writer.Discarding = .init(&discard_buf);

    const head = zurl.parser.parseHead(r, parse_options) catch |err| return mapError(err);
    const body = zurl.parser.streamBody(
        r,
        head,
        method.toStd(),
        &discarding.writer,
        parse_options,
    ) catch |err| return mapError(err);

    return .{
        .status = head.status,
        // What the response cost on the wire, which is what `Transfer/sec`
        // reports and what wrk means by it: the head, and the body including
        // chunk-size lines, their CRLFs and any trailer section. `body.len`
        // would be the DECODED size and would under-report every chunked
        // response by exactly its framing.
        .bytes = head.head_len + body.wire_len,
        // The exchange's verdict rather than the head's: a close-delimited
        // body forces the connection shut whatever the headers claimed.
        .keep_alive = body.keep_alive,
    };
}

/// How zrk reads a response, fixed for the whole run.
const parse_options: zurl.HeadOptions = .{
    // zrk sends no `accept-encoding`, but an origin may compress anyway, and a
    // compressed response is still a response that arrived: it has a status,
    // it has a length, and zrk never looks inside it. Left at the default,
    // every request against such a target would fail with
    // `UnsupportedContentEncoding` and the run would report the target broken
    // when it was us being fussy about bytes we discard.
    .allow_encoded_body = true,
    // No `on_header`: zrk retains nothing, and the callback would run on every
    // header of every response for the whole run.
};

/// zurl's parser errors in zrk's vocabulary.
///
/// Two arms cannot fire under `parse_options` and are still mapped rather than
/// left `unreachable`: `unreachable` is undefined behaviour in ReleaseFast,
/// which is the mode every release binary is built in, and the caller buckets
/// all of these as one read error anyway.
fn mapError(err: zurl.parser.Error) ParseError {
    return switch (err) {
        error.MalformedStatusLine => error.MalformedStatusLine,
        error.MalformedHeader => error.MalformedHeader,
        error.MalformedChunk => error.MalformedChunk,
        error.UnexpectedEof => error.UnexpectedEof,
        error.HeadTooLong => error.HeaderTooLong,
        error.ReadFailed => error.ReadFailed,
        // The sink is a `Discarding` writer and cannot fail.
        error.WriteFailed => error.ReadFailed,
        // Refused only when `allow_encoded_body` is false, and it is not.
        error.UnsupportedContentEncoding => error.ReadFailed,
    };
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "buildRequest basic GET" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const cfg = cli.Config{ .url = try cli.parseUrl("http://example.com/index.html") };
    const req = try buildRequest(arena.allocator(), &cfg);
    try testing.expect(std.mem.startsWith(u8, req, "GET /index.html HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Connection: keep-alive\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, req, "\r\n\r\n"));
}

test "buildRequest advertises close under --disable-keepalive" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = cli.Config{ .url = try cli.parseUrl("http://example.com/") };
    cfg.disable_keepalive = true;
    const req = try buildRequest(arena.allocator(), &cfg);
    try testing.expect(std.mem.indexOf(u8, req, "Connection: close\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Connection: keep-alive\r\n") == null);
}

test "an explicit -H Connection wins over --disable-keepalive's default" {
    // The flag governs our socket; `-H` governs the bytes. Telling a server
    // `keep-alive` while closing anyway is a legitimate probe of how it copes,
    // and the header must not be silently doubled either way.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var cfg = cli.Config{
        .url = try cli.parseUrl("http://example.com/"),
        .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
    };
    cfg.disable_keepalive = true;
    const req = try buildRequest(arena.allocator(), &cfg);
    try testing.expect(std.mem.indexOf(u8, req, "Connection: close\r\n") == null);
    try testing.expectEqual(
        std.mem.indexOf(u8, req, "Connection: keep-alive\r\n"),
        std.mem.lastIndexOf(u8, req, "Connection: keep-alive\r\n"),
    );
}

test "buildRequest with non-default port, method, body, headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const headers = [_]cli.Header{.{ .name = "Accept", .value = "application/json" }};
    const cfg = cli.Config{
        .method = "POST",
        .body = "hello",
        .headers = &headers,
        .url = try cli.parseUrl("http://example.com:8080/api"),
    };
    const req = try buildRequest(arena.allocator(), &cfg);
    try testing.expect(std.mem.startsWith(u8, req, "POST /api HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.com:8080\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Accept: application/json\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Content-Length: 5\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, req, "\r\n\r\nhello"));
}

test "parseResponse content-length" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
    try testing.expectEqual(StatusClass.success, StatusClass.of(resp.status));
}

test "parseResponse two pipelined responses stay framed" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi" ++
        "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno!";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 200), first.status);
    const second = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 404), second.status);
    try testing.expectEqual(StatusClass.client_error, StatusClass.of(second.status));
}

test "parseResponse chunked" {
    const raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
}

test "parseResponse connection close disables keep-alive" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expect(!resp.keep_alive);
}

test "parseResponse http/1.0 defaults to no keep-alive" {
    const raw = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expect(!resp.keep_alive);
}

test "buildRequest Content-Length: bodyless methods, empty POST, user override" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // GET with no body: no Content-Length at all.
    const get = try buildRequest(a, &.{ .url = try cli.parseUrl("http://x/") });
    try testing.expect(std.mem.indexOf(u8, get, "Content-Length") == null);

    // POST with an empty body still declares an explicit zero length.
    const post = try buildRequest(a, &.{ .method = "POST", .url = try cli.parseUrl("http://x/") });
    try testing.expect(std.mem.indexOf(u8, post, "Content-Length: 0\r\n") != null);

    // A user-supplied Content-Length suppresses the automatic one.
    const headers = [_]cli.Header{.{ .name = "Content-Length", .value = "5" }};
    const custom = try buildRequest(a, &.{
        .method = "POST",
        .body = "hello",
        .headers = &headers,
        .url = try cli.parseUrl("http://x/"),
    });
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, custom, "Content-Length"));
}

test "parseResponse rejects non-3-digit status codes" {
    var short = Io.Reader.fixed("HTTP/1.1 42 Weird\r\n\r\n");
    try testing.expectError(error.MalformedStatusLine, parseResponse(&short, .other));
    var long = Io.Reader.fixed("HTTP/1.1 12345 Weird\r\n\r\n");
    try testing.expectError(error.MalformedStatusLine, parseResponse(&long, .other));
}

test "RequestMethod.of classifies HEAD case-insensitively" {
    try testing.expectEqual(RequestMethod.head, RequestMethod.of("HEAD"));
    try testing.expectEqual(RequestMethod.head, RequestMethod.of("head"));
    try testing.expectEqual(RequestMethod.other, RequestMethod.of("GET"));
    try testing.expectEqual(RequestMethod.other, RequestMethod.of("PROPPATCH"));
    // A method `std.http.Method` cannot name still reaches the parser as the
    // only thing the parser uses a method for: not-HEAD.
    try testing.expectEqual(std.http.Method.GET, RequestMethod.of("PROPPATCH").toStd());
    try testing.expectEqual(std.http.Method.HEAD, RequestMethod.of("head").toStd());
}

test "a compressed body is measured, not refused" {
    // zurl refuses a `content-encoding` it cannot decode, on the grounds that
    // its callers read bodies. zrk opts out because it discards them: a gzip
    // response has a status, a length and a latency like any other, and left
    // at zurl's default every request against a compressing origin would fail
    // and the run would report that target down.
    const raw = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\n\x1f\x8b\x08\x00";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
    try testing.expect(resp.keep_alive);
}

test "conflicting Content-Length is refused rather than guessed" {
    // A request-smuggling primitive: two lengths let an intermediary and an
    // origin disagree about where the body ends. The hand-rolled parser took
    // the last one silently and stayed framed on whichever it picked; zurl
    // refuses, and a load generator has no business preferring one.
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhello";
    var r = Io.Reader.fixed(raw);
    try testing.expectError(error.MalformedHeader, parseResponse(&r, .other));

    // Duplicates that AGREE are tolerated: some proxies stack them, and there
    // is nothing to disagree about.
    const agreeing = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
    var ok = Io.Reader.fixed(agreeing);
    const resp = try parseResponse(&ok, .other);
    try testing.expectEqual(@as(u64, agreeing.len), resp.bytes);
}

test "chunk framing counts toward Transfer/sec, decoded length does not" {
    // The distinction `Response.bytes` exists for. Nine bytes of payload
    // arrive inside 24 bytes of body wire, and a meter that reported the
    // former would under-report every chunked target it ever measured.
    const body = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    const raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++ body;
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
    try testing.expect(resp.bytes > raw.len - body.len + 9);
}

test "parseResponse HEAD ignores Content-Length and stays framed" {
    // HEAD responses advertise the entity's Content-Length but carry no body;
    // two back-to-back responses must parse cleanly without consuming "body"
    // bytes that don't exist.
    const one = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
    const raw = one ++ "HTTP/1.1 404 Not Found\r\nContent-Length: 99\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, .head);
    try testing.expectEqual(@as(u16, 200), first.status);
    try testing.expect(first.keep_alive);
    try testing.expectEqual(@as(u64, one.len), first.bytes);
    const second = try parseResponse(&r, .head);
    try testing.expectEqual(@as(u16, 404), second.status);
}

test "parseResponse HEAD ignores chunked transfer-encoding" {
    const raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .head);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
}

test "parseResponse 304 with Content-Length has no body" {
    const one = "HTTP/1.1 304 Not Modified\r\nContent-Length: 5678\r\n\r\n";
    const raw = one ++ "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 304), first.status);
    try testing.expect(first.keep_alive);
    try testing.expectEqual(@as(u64, one.len), first.bytes);
    const second = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 200), second.status);
}

test "parseResponse 204 no body" {
    const raw = "HTTP/1.1 204 No Content\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, .other);
    try testing.expectEqual(@as(u16, 204), resp.status);
    try testing.expect(resp.keep_alive);
}

test "StatusClass.of boundaries" {
    try testing.expectEqual(StatusClass.informational, StatusClass.of(100));
    try testing.expectEqual(StatusClass.success, StatusClass.of(299));
    try testing.expectEqual(StatusClass.redirect, StatusClass.of(301));
    try testing.expectEqual(StatusClass.client_error, StatusClass.of(499));
    try testing.expectEqual(StatusClass.server_error, StatusClass.of(503));
}

test "the h2 request block round-trips through a decoder" {
    // The block is sent on every stream for a whole run, so what matters is
    // that it decodes to the request the user asked for. Decoded with an empty
    // dynamic table because `static_only` is what produced it — if the encoder
    // ever touched the table, this would fail rather than silently produce a
    // block only valid in the order it was made.
    const allocator = std.testing.allocator;
    var cfg: cli.Config = .{
        .method = "POST",
        .body = "hi",
        .headers = &.{
            .{ .name = "X-Trace-Id", .value = "abc123" },
            .{ .name = "Accept", .value = "*/*" },
        },
    };
    cfg.url = .{ .scheme = .http, .host = "example.com", .port = 8080, .target = "/submit?q=1" };

    const block = try buildRequestBlock(allocator, &cfg);
    defer allocator.free(block);

    var storage: h2.hpack.DynamicTable.Storage(0) = .{};
    var decoder: h2.hpack.Decoder = .init(storage.table(), 64 * 1024);
    var buffer: [4096]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block);

    var seen: [8][2][]const u8 = undefined;
    var count: usize = 0;
    while (try iterator.next()) |field| : (count += 1) {
        seen[count] = .{ field.name, field.value };
    }

    try std.testing.expectEqualStrings(":method", seen[0][0]);
    try std.testing.expectEqualStrings("POST", seen[0][1]);
    try std.testing.expectEqualStrings(":scheme", seen[1][0]);
    try std.testing.expectEqualStrings("http", seen[1][1]);
    try std.testing.expectEqualStrings(":path", seen[2][0]);
    try std.testing.expectEqualStrings("/submit?q=1", seen[2][1]);
    // The port is not the scheme's default, so it belongs in the authority —
    // the same rule `buildRequest` applies to `Host`.
    try std.testing.expectEqualStrings(":authority", seen[3][0]);
    try std.testing.expectEqualStrings("example.com:8080", seen[3][1]);
    // `-H` names are folded to lowercase, which section 8.2.1 requires and
    // HTTP/1.1 did not.
    try std.testing.expectEqualStrings("x-trace-id", seen[4][0]);
    try std.testing.expectEqualStrings("abc123", seen[4][1]);
    try std.testing.expectEqualStrings("accept", seen[5][0]);
    try std.testing.expectEqualStrings("user-agent", seen[6][0]);
    try std.testing.expectEqualStrings("content-length", seen[7][0]);
    try std.testing.expectEqualStrings("2", seen[7][1]);
    try std.testing.expectEqual(@as(usize, 8), count);
}

test "the block never carries a connection-specific header" {
    // `buildRequest` adds `Connection: keep-alive`, which RFC 9113 section
    // 8.2.2 makes malformed in HTTP/2 — a server is required to reject the
    // whole message for it. The h2 builder must not inherit that, and a user
    // who passes one via -H must be refused rather than sent a request every
    // stream of which will be reset.
    const allocator = std.testing.allocator;
    var cfg: cli.Config = .{ .headers = &.{.{ .name = "Connection", .value = "keep-alive" }} };
    cfg.url = .{ .scheme = .http, .host = "example.com", .port = 80, .target = "/" };
    try std.testing.expectError(error.InvalidRequestHeader, buildRequestBlock(allocator, &cfg));

    // And nothing adds one on its own.
    var plain: cli.Config = .{};
    plain.url = .{ .scheme = .http, .host = "example.com", .port = 80, .target = "/" };
    const block = try buildRequestBlock(allocator, &plain);
    defer allocator.free(block);

    var storage: h2.hpack.DynamicTable.Storage(0) = .{};
    var decoder: h2.hpack.Decoder = .init(storage.table(), 64 * 1024);
    var buffer: [4096]u8 = undefined;
    var iterator = decoder.iterate(&buffer, block);
    while (try iterator.next()) |field| {
        try std.testing.expect(!std.mem.eql(u8, field.name, "connection"));
    }
}

test "a header value that would split a request is refused" {
    // The h2-to-h1 downgrade guard, applied to our own output. A CR in a value
    // is the request-splitting primitive RFC 9113 section 8.2.1 exists for, and
    // a load generator that emitted one would be attacking the target it was
    // pointed at rather than measuring it.
    const allocator = std.testing.allocator;
    var cfg: cli.Config = .{ .headers = &.{.{ .name = "X-Evil", .value = "a\r\nx-injected: 1" }} };
    cfg.url = .{ .scheme = .http, .host = "example.com", .port = 80, .target = "/" };
    try std.testing.expectError(error.InvalidRequestHeader, buildRequestBlock(allocator, &cfg));
}
