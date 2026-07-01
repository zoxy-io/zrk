//! TLS transport helpers layered over a plain `net.Stream`.
//!
//! `CaStore` holds the system CA bundle, loaded once and shared (read-mostly)
//! across all connections. `State` is a per-connection, pinned block of buffers
//! plus the `std.crypto.tls.Client`; it wraps a connected stream and exposes the
//! decrypted reader/writer that the HTTP layer talks to.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;

/// Encrypted-record buffer size required by the TLS client.
const record_len = tls.max_ciphertext_record_len;
/// Room for a full HTTP response head on top of one TLS record.
const app_read_len = record_len + 16 * 1024;
const app_write_len = 8 * 1024;

/// The system trust store, loaded once and shared by all connections.
pub const CaStore = struct {
    bundle: Certificate.Bundle,
    lock: Io.RwLock = .init,

    pub fn load(gpa: std.mem.Allocator, io: Io) !CaStore {
        var bundle: Certificate.Bundle = .empty;
        try bundle.rescan(gpa, io, Io.Timestamp.now(io, .real));
        return .{ .bundle = bundle };
    }

    pub fn deinit(self: *CaStore, gpa: std.mem.Allocator) void {
        self.bundle.deinit(gpa);
    }
};

/// Per-connection TLS state. Must not be moved once `handshake` has run, since
/// the `tls.Client` stores pointers into its own buffers and stream adapters.
/// Reused across reconnects by simply re-running `handshake`.
pub const State = struct {
    app_read: [app_read_len]u8 = undefined,
    sock_read: [record_len]u8 = undefined,
    sock_write: [record_len]u8 = undefined,
    app_write: [app_write_len]u8 = undefined,
    sreader: net.Stream.Reader = undefined,
    swriter: net.Stream.Writer = undefined,
    client: tls.Client = undefined,

    pub const HandshakeError = tls.Client.InitError;

    /// Perform the TLS handshake over `stream`. When `insecure` is true, neither
    /// the hostname nor the certificate chain is verified (`-k`).
    pub fn handshake(
        self: *State,
        io: Io,
        gpa: std.mem.Allocator,
        stream: net.Stream,
        host: []const u8,
        insecure: bool,
        ca: ?*CaStore,
    ) HandshakeError!void {
        self.sreader = stream.reader(io, &self.sock_read);
        self.swriter = stream.writer(io, &self.sock_write);

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);

        const host_opt: @FieldType(tls.Client.Options, "host") =
            if (insecure) .no_verification else .{ .explicit = host };
        const ca_opt: @FieldType(tls.Client.Options, "ca") = if (insecure or ca == null)
            .no_verification
        else
            .{ .bundle = .{
                .gpa = gpa,
                .io = io,
                .lock = &ca.?.lock,
                .bundle = &ca.?.bundle,
            } };

        self.client = try tls.Client.init(&self.sreader.interface, &self.swriter.interface, .{
            .host = host_opt,
            .ca = ca_opt,
            .read_buffer = &self.app_read,
            .write_buffer = &self.app_write,
            .entropy = &entropy,
            .realtime_now = Io.Timestamp.now(io, .real),
            // Safe for HTTP: responses are framed by Content-Length / chunked.
            .allow_truncation_attacks = true,
        });
    }

    pub fn reader(self: *State) *Io.Reader {
        return &self.client.reader;
    }

    pub fn writer(self: *State) *Io.Writer {
        return &self.client.writer;
    }
};
