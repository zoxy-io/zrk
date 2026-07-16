//! Minimal HTTP/1.1 request building and response parsing for load generation.
//!
//! zrk sends one fixed request repeatedly over a keep-alive connection and only
//! needs enough of the response to (a) learn the status class, (b) consume the
//! body so the connection stays framed for the next request, and (c) count
//! bytes for throughput. It deliberately does not retain header or body content.

const std = @import("std");
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

    // Sensible defaults; a user -H of the same name is additionally sent, which
    // mirrors wrk's behavior of not de-duplicating headers.
    var has_ua = false;
    var has_conn = false;
    for (cfg.headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "user-agent")) has_ua = true;
        if (std.ascii.eqlIgnoreCase(h.name, "connection")) has_conn = true;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    if (!has_ua) try w.writeAll("User-Agent: zrk\r\n");
    if (!has_conn) try w.writeAll("Connection: keep-alive\r\n");

    if (cfg.body.len > 0) {
        try w.print("Content-Length: {d}\r\n", .{cfg.body.len});
    }
    try w.writeAll("\r\n");
    try w.writeAll(cfg.body);

    return alloc_writer.toOwnedSlice();
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

/// Parse one HTTP/1.1 response from `r`, consuming its full body so the reader
/// is positioned at the start of the next response. `head` must be true when
/// the request was HEAD: those responses carry framing headers describing the
/// body they *would* have, but never the body itself (RFC 9112 §6.3). `r`'s
/// buffer capacity must be large enough to hold the longest single header line.
pub fn parseResponse(r: *Io.Reader, head: bool) ParseError!Response {
    var bytes: u64 = 0;

    // Status line: "HTTP/1.1 200 OK\r\n"
    const status_line = takeLine(r, &bytes) catch return error.MalformedStatusLine;
    const status = parseStatus(status_line) catch return error.MalformedStatusLine;

    var content_length: ?u64 = null;
    var chunked = false;
    // Default keep-alive is true for HTTP/1.1 unless the server says otherwise.
    var keep_alive = std.mem.startsWith(u8, status_line, "HTTP/1.1");

    // Headers, one per line, terminated by a blank line.
    while (true) {
        const line = takeLine(r, &bytes) catch return error.MalformedHeader;
        if (line.len == 0) break; // blank line: end of headers

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(u64, value, 10) catch return error.MalformedHeader;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (asciiContainsIgnoreCase(value, "chunked")) chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (asciiContainsIgnoreCase(value, "close")) {
                keep_alive = false;
            } else if (asciiContainsIgnoreCase(value, "keep-alive")) {
                keep_alive = true;
            }
        }
    }

    // Body. HEAD responses and 1xx/204/304 statuses never carry one, whatever
    // Content-Length or Transfer-Encoding claim (RFC 9112 §6.3) — consuming a
    // body there would eat into the next response and break framing.
    const bodyless = head or status == 204 or status == 304 or status / 100 == 1;
    if (bodyless) {
        // Nothing to consume.
    } else if (chunked) {
        try consumeChunkedBody(r, &bytes);
    } else if (content_length) |len| {
        discard(r, len, &bytes) catch return error.UnexpectedEof;
    } else {
        // No framing info: the body runs to connection close, which precludes
        // keep-alive.
        keep_alive = false;
    }

    return .{ .status = status, .bytes = bytes, .keep_alive = keep_alive };
}

/// Read a CRLF-terminated line, return it without the trailing CRLF, and add
/// the raw byte count (including CRLF) to `bytes`.
fn takeLine(r: *Io.Reader, bytes: *u64) !([]const u8) {
    const raw = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.HeaderTooLong,
        error.EndOfStream => return error.UnexpectedEof,
        error.ReadFailed => return error.ReadFailed,
    };
    bytes.* += raw.len;
    var line = raw;
    if (line.len > 0 and line[line.len - 1] == '\n') line = line[0 .. line.len - 1];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
    return line;
}

fn parseStatus(status_line: []const u8) !u16 {
    // "HTTP/1.1 200 OK" -> take the token after the first space.
    const first_space = std.mem.indexOfScalar(u8, status_line, ' ') orelse return error.MalformedStatusLine;
    const after = status_line[first_space + 1 ..];
    const code_end = std.mem.indexOfScalar(u8, after, ' ') orelse after.len;
    return std.fmt.parseInt(u16, after[0..code_end], 10) catch error.MalformedStatusLine;
}

fn consumeChunkedBody(r: *Io.Reader, bytes: *u64) ParseError!void {
    while (true) {
        const size_line = takeLine(r, bytes) catch return error.MalformedChunk;
        // Chunk size is hex, optionally followed by ";extensions".
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size = std.fmt.parseInt(u64, size_line[0..semi], 16) catch return error.MalformedChunk;
        if (size == 0) {
            // Trailing headers (if any) until a blank line, then done.
            while (true) {
                const line = takeLine(r, bytes) catch return error.MalformedChunk;
                if (line.len == 0) break;
            }
            return;
        }
        discard(r, size, bytes) catch return error.MalformedChunk;
        // Each chunk's data is followed by a CRLF.
        _ = takeLine(r, bytes) catch return error.MalformedChunk;
    }
}

fn discard(r: *Io.Reader, n: u64, bytes: *u64) !void {
    r.discardAll64(n) catch return error.UnexpectedEof;
    bytes.* += n;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
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
    const resp = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
    try testing.expectEqual(StatusClass.success, StatusClass.of(resp.status));
}

test "parseResponse two pipelined responses stay framed" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi" ++
        "HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno!";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 200), first.status);
    const second = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 404), second.status);
    try testing.expectEqual(StatusClass.client_error, StatusClass.of(second.status));
}

test "parseResponse chunked" {
    const raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
}

test "parseResponse connection close disables keep-alive" {
    const raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, false);
    try testing.expect(!resp.keep_alive);
}

test "parseResponse http/1.0 defaults to no keep-alive" {
    const raw = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, false);
    try testing.expect(!resp.keep_alive);
}

test "parseResponse HEAD ignores Content-Length and stays framed" {
    // HEAD responses advertise the entity's Content-Length but carry no body;
    // two back-to-back responses must parse cleanly without consuming "body"
    // bytes that don't exist.
    const one = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
    const raw = one ++ "HTTP/1.1 404 Not Found\r\nContent-Length: 99\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, true);
    try testing.expectEqual(@as(u16, 200), first.status);
    try testing.expect(first.keep_alive);
    try testing.expectEqual(@as(u64, one.len), first.bytes);
    const second = try parseResponse(&r, true);
    try testing.expectEqual(@as(u16, 404), second.status);
}

test "parseResponse HEAD ignores chunked transfer-encoding" {
    const raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, true);
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expect(resp.keep_alive);
    try testing.expectEqual(@as(u64, raw.len), resp.bytes);
}

test "parseResponse 304 with Content-Length has no body" {
    const one = "HTTP/1.1 304 Not Modified\r\nContent-Length: 5678\r\n\r\n";
    const raw = one ++ "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    var r = Io.Reader.fixed(raw);
    const first = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 304), first.status);
    try testing.expect(first.keep_alive);
    try testing.expectEqual(@as(u64, one.len), first.bytes);
    const second = try parseResponse(&r, false);
    try testing.expectEqual(@as(u16, 200), second.status);
}

test "parseResponse 204 no body" {
    const raw = "HTTP/1.1 204 No Content\r\n\r\n";
    var r = Io.Reader.fixed(raw);
    const resp = try parseResponse(&r, false);
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
