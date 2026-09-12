//! TLS transport helpers layered over a plain `net.Stream`.
//!
//! `CaStore` holds the system CA bundle, loaded once and shared (read-mostly)
//! across all connections. `State` is a per-connection, pinned block of buffers
//! plus the TLS engine; it wraps a connected stream and exposes the decrypted
//! reader/writer that the HTTP layer talks to.
//!
//! ## Why zssl, and what this file therefore owns
//!
//! zssl is sans-I/O: it takes whole TLS records in and hands bytes out, and
//! owns no socket, no allocator and no entropy. That is the reason it can be
//! audited, and the reason this file is not a thin wrapper — everything zssl
//! deliberately declines to do lands here:
//!
//!   * **The `std.Io` adapter.** `Reader`/`Writer` below implement the two
//!     vtables zrk's HTTP layers consume, over a record buffer this file
//!     pumps from the socket.
//!   * **Trust.** zssl proves *possession* — that the peer holds the key its
//!     leaf certificate names. Proving *identity* — that the chain builds to
//!     a system anchor and the name matches — is the embedder's, and
//!     `verifyChain` below is zrk's answer, over `std.crypto.Certificate`.
//!     That is the same split `std.crypto.tls.Client` makes internally; here
//!     it is visible, which is the point.
//!   * **Entropy.** zssl draws none, so each handshake takes 64 bytes from
//!     `io.random`.
//!
//! ALPN is why any of this exists rather than `std.crypto.tls`: HTTP/2 over
//! TLS is selected by it (RFC 9113 §3.2), and `std.crypto.tls` has none, so
//! `--http2` could only ever have been cleartext. See zoxy-io/zrk#21.
//!
//! Nothing here imposes a timeout; the right mechanism is `std.Io`
//! cancellation, and when `connection.zig` arms it — around the HTTP/2
//! preface, and through `Watchdog` once the transport is up — shutting the
//! socket down surfaces here as a transport error.
//!
//! The handshake itself is *not* covered by either: a peer that completes the
//! TCP connect and then never sends a ServerHello pins the connection's
//! coroutine past the run's end. That gap predates this file's rewrite and is
//! noted here rather than papered over.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const Certificate = std.crypto.Certificate;
const zssl = @import("zssl");

/// The system trust store, loaded once and shared by all connections.
///
/// Rescanning the OS trust store on every handshake would be fine for a
/// program that opens one connection and wrong for one that opens thousands,
/// so it is loaded once and then only read. Never mutated after `load`, which
/// is why nothing below takes the lock to read it.
pub const CaStore = struct {
    bundle: Certificate.Bundle,

    pub fn load(gpa: std.mem.Allocator, io: Io) !CaStore {
        var bundle: Certificate.Bundle = .empty;
        try bundle.rescan(gpa, io, Io.Timestamp.now(io, .real));
        return .{ .bundle = bundle };
    }

    pub fn deinit(self: *CaStore, gpa: std.mem.Allocator) void {
        self.bundle.deinit(gpa);
    }
};

/// Matching the cleartext path's buffers in `connection.zig`, so the two
/// transports frame identically and a response that fits one fits the other.
const read_buffer_bytes = 16 * 1024;
const write_buffer_bytes = 8 * 1024;

/// Must hold the server's whole certificate flight. zssl asserts a floor of
/// 8 KiB; real chains with a 4096-bit RSA leaf and two intermediates clear
/// that but not by much, so this is doubled from the floor rather than set at
/// it.
const reassembly_bytes = 16 * 1024;

/// One whole record, which is what `handleRecord` and `sendApplicationData`
/// both need to write into.
const out_bytes = zssl.ClientHandshake.out_bytes_min;

pub const HandshakeError = error{
    /// The chain did not build to a trusted anchor, the name did not match,
    /// or the leaf's own signature did not check out.
    CertificateVerificationFailed,
    /// The peer's bytes were not a TLS 1.3 handshake we could complete.
    TlsHandshakeFailed,
    /// The socket failed, or the peer went away mid-handshake.
    TransportFailed,
    /// A record or flight larger than the buffers sized for it.
    HandshakeTooLarge,
};

/// Per-connection TLS state. Must not be moved once `handshake` has run: the
/// reader and writer interfaces hold pointers into this struct's own buffers.
///
/// Allocated as one undefined block per connection (`stats.Fleet`), so `init`
/// must run before anything reads a field, and `handshake` may be re-run to
/// reconnect — it tears the previous session down first.
pub const State = struct {
    /// Whether `client` holds a session that owes a `deinit`. The first thing
    /// written, because everything else starts as undefined memory.
    live: bool,

    client: zssl.ClientHandshake,
    records: zssl.record_buffer.RecordBuffer,
    trust: Trust,

    io: Io,
    stream: net.Stream,

    /// Decrypted application bytes handed out by `handleRecord` and not yet
    /// copied to the caller. Views `out_read`, so it dies at the next read.
    pending: []const u8,
    /// Set once the peer's close_notify or a transport EOF landed.
    read_closed: bool,

    reader_impl: Reader,
    writer_impl: Writer,

    record_storage: [zssl.record.wire_record_bytes_max]u8,
    reassembly: [reassembly_bytes]u8,
    /// Two out buffers, not one. `handleRecord` decrypts *into* this buffer
    /// and returns a slice of it, so a write that sealed a record through the
    /// same buffer would overwrite plaintext a concurrent read still owed the
    /// caller. HTTP/1.1 alternates and would never notice; h2 interleaves and
    /// would, silently and rarely, which is the worst way to find it.
    out_read: [out_bytes]u8,
    out_write: [out_bytes]u8,
    read_storage: [read_buffer_bytes]u8,
    write_storage: [write_buffer_bytes]u8,

    /// Bring a freshly allocated block to a state where every other method is
    /// safe to call. Nothing else may read a field first.
    pub fn init(self: *State) void {
        self.live = false;
    }

    pub fn deinit(self: *State) void {
        if (!self.live) return;
        self.client.deinit();
        self.live = false;
    }

    /// Perform the TLS handshake over `stream`, offering `alpn`.
    ///
    /// When `insecure` is true (`-k`) the certificate is not looked at *at
    /// all*: not the hostname, not the chain, and not the CertificateVerify
    /// that would prove the peer holds the key its leaf names. The session is
    /// encrypted and wholly unauthenticated.
    ///
    /// That is more permissive than curl's `-k`, which still checks
    /// possession, and it is the deliberate choice for a benchmarking tool:
    /// `-k` means "measure this endpoint whatever it presents", including
    /// leaf key types zssl would otherwise refuse. It is not a weaker version
    /// of verification, it is the absence of it.
    pub fn handshake(
        self: *State,
        io: Io,
        gpa: std.mem.Allocator,
        stream: net.Stream,
        host: []const u8,
        insecure: bool,
        ca: ?*CaStore,
        alpn: []const []const u8,
    ) HandshakeError!void {
        _ = gpa;
        // Reconnects land here on a state that still owns the last session.
        self.deinit();

        self.io = io;
        self.stream = stream;
        self.pending = &.{};
        self.read_closed = false;
        self.records = .init(&self.record_storage);
        self.reader_impl = .init(self);
        self.writer_impl = .init(self);

        // `-k`, or a run with no trust store to check against, verifies
        // neither name nor chain. Everything else gets both.
        const verifying = !insecure and ca != null;
        self.trust = .{
            .io = io,
            .bundle = if (verifying) &ca.?.bundle else null,
            .host = host,
        };

        var entropy: [64]u8 = undefined;
        io.random(&entropy);
        self.client = .init(&.{
            .client_random = entropy[0..32].*,
            .x25519_private = entropy[32..64].*,
            // SNI is sent either way: a server that needs it to pick a
            // certificate needs it under `-k` too, and withholding it would
            // change which endpoint is being measured.
            .server_name = host,
            .alpn_protocols = alpn,
            .certificate_policy = if (verifying) .leaf_signature else .insecure_no_verification,
            .chain_verifier = if (verifying) self.trust.verifier() else null,
            .reassembly = &self.reassembly,
        });
        self.live = true;

        try self.transportWrite(self.client.start(&self.out_read));
        while (self.client.state != .connected) {
            const wire_record = self.nextRecord() catch |err| return switch (err) {
                error.RecordFailed => error.HandshakeTooLarge,
                error.PeerClosed, error.TransportFailed => error.TransportFailed,
            };
            // One record can carry more than one message, so the first event
            // comes from the record and the rest from `drain` until it
            // answers null. Null is "nothing further", never "the last
            // message resolved to nothing" â zssl skips those itself.
            var event = self.client.handleRecord(wire_record, &self.out_read) catch |err|
                return self.trust.classify(err);
            while (event) |ready| : (event = self.client.drain(&self.out_read) catch |err|
                return self.trust.classify(err))
            {
                switch (ready) {
                    .ticket => {},
                    .send => |bytes| try self.transportWrite(bytes),
                    .connected => |flight| try self.transportWrite(flight),
                    // Neither can arrive before `connected`; zssl answers
                    // `UnexpectedMessage` for the first and we offer no early
                    // data, so this is a zssl bug rather than a peer's.
                    .application_data => unreachable,
                    .closed => return error.TransportFailed,
                }
            }
        }
    }

    /// The protocol ALPN settled on, or null if the peer selected none.
    ///
    /// Checked by the caller rather than asserted here: a server that ignores
    /// the offer and answers HTTP/1.1 to an `h2` request is a real thing to
    /// meet, and a load generator should report it rather than crash on it.
    pub fn negotiatedAlpn(self: *State) ?[]const u8 {
        return self.client.alpnSelected();
    }

    pub fn reader(self: *State) *Io.Reader {
        return &self.reader_impl.interface;
    }

    pub fn writer(self: *State) *Io.Writer {
        return &self.writer_impl.interface;
    }

    // ── transport ────────────────────────────────────────────────────────

    /// Why a record could not be produced. The three are kept apart because
    /// the read path has to tell a *close* from a *failure*: collapsing them
    /// reports a connection reset mid-body as a clean end of stream, and a
    /// close-delimited HTTP response truncated by a reset then parses as a
    /// complete one and is counted as a success.
    const RecordError = error{
        /// The peer stopped sending. A transport EOF, not a `close_notify`;
        /// TLS calls that truncation, but enough servers close this way that
        /// the caller is left to judge whether it landed at a legal point.
        PeerClosed,
        /// The socket failed, or the run's watchdog shut it down.
        TransportFailed,
        /// The bytes were not a record we could frame.
        RecordFailed,
    };

    /// Read straight into the record buffer's own writable region, so a
    /// record is staged once rather than copied through a second buffer.
    fn fillRecords(self: *State) RecordError!void {
        const room = self.records.writable();
        var data: [1][]u8 = .{room};
        const n = self.io.vtable.netRead(self.io.userdata, self.stream.socket.handle, &data) catch
            return error.TransportFailed;
        if (n == 0) return error.PeerClosed;
        self.records.advance(n);
    }

    /// The next whole record off the wire.
    fn nextRecord(self: *State) RecordError![]const u8 {
        while (true) {
            if (self.records.next() catch return error.RecordFailed) |wire_record| {
                return wire_record;
            }
            try self.fillRecords();
        }
    }

    fn transportWrite(self: *State, bytes: []const u8) HandshakeError!void {
        var rest = bytes;
        while (rest.len != 0) {
            const data: [1][]const u8 = .{rest};
            const n = self.io.vtable.netWrite(
                self.io.userdata,
                self.stream.socket.handle,
                "",
                &data,
                1,
            ) catch return error.TransportFailed;
            rest = rest[n..];
        }
    }

    // ── application data ─────────────────────────────────────────────────

    const StreamError = error{ EndOfStream, Failed };

    /// Drive the record loop until it yields application bytes, or the
    /// session ends. The result views `out_read` and dies at the next call.
    fn nextApplicationData(self: *State) StreamError![]const u8 {
        if (self.read_closed) return error.EndOfStream;
        while (true) {
            const wire_record = self.nextRecord() catch |err| {
                self.read_closed = true;
                return switch (err) {
                    // How most servers end a close-delimited response.
                    error.PeerClosed => error.EndOfStream,
                    // A reset, or the wire timeout shutting the socket down.
                    // Reported as a failure so a body cut short is counted as
                    // one instead of parsing as a complete response.
                    error.TransportFailed, error.RecordFailed => error.Failed,
                };
            };
            var event = self.client.handleRecord(wire_record, &self.out_read) catch {
                self.read_closed = true;
                return error.Failed;
            };
            // A record's inner content type is singular, so the drain only
            // ever has more to say about a handshake record: a ticket packed
            // with a KeyUpdate is what Go and OpenSSL emit, and reading just
            // the first would strand the second until the next record.
            // Returning below therefore leaves nothing behind â the record
            // that carried application data carried only that.
            while (event) |ready| : (event = self.client.drain(&self.out_read) catch {
                self.read_closed = true;
                return error.Failed;
            }) {
                switch (ready) {
                    // A zero-length record is legal and carries nothing; keep
                    // reading rather than reporting a false end of stream.
                    .application_data => |plaintext| if (plaintext.len != 0) return plaintext,
                    // Post-handshake traffic: a KeyUpdate we must answer, or a
                    // ticket we have no use for.
                    .send => |bytes| self.transportWrite(bytes) catch {
                        self.read_closed = true;
                        return error.Failed;
                    },
                    .ticket => {},
                    .closed => {
                        self.read_closed = true;
                        return error.EndOfStream;
                    },
                    .connected => unreachable, // Already connected.
                }
            }
        }
    }

    /// Seal `bytes` into records and put them on the wire. TLS caps a record's
    /// plaintext at 16 KiB (§5.1), so anything longer becomes several.
    fn sendApplicationData(self: *State, bytes: []const u8) Io.Writer.Error!void {
        // zssl asserts the session is connected, so writing after the peer
        // closed would panic the process rather than fail the connection.
        // `connection.zig` does not do that today — it drops the connection
        // on any read failure — but that is a property of a caller in another
        // file, and one missed reconnect should not take the fleet down.
        if (self.read_closed or self.client.state != .connected) return error.WriteFailed;
        var rest = bytes;
        while (rest.len != 0) {
            const take = @min(rest.len, zssl.record.plaintext_bytes_max);
            const sealed = self.client.sendApplicationData(rest[0..take], &self.out_write) catch
                return error.WriteFailed;
            self.transportWrite(sealed) catch return error.WriteFailed;
            rest = rest[take..];
        }
    }

    pub const Reader = struct {
        interface: Io.Reader,

        fn init(self: *State) Reader {
            return .{ .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = &self.read_storage,
                .seek = 0,
                .end = 0,
            } };
        }

        /// Copy decrypted application data into `io_w`.
        ///
        /// This honours the `Io.Reader.stream` contract rather than repointing
        /// `io_r.buffer` at the plaintext in place. Repointing removes a copy
        /// but makes the reader's capacity equal to the current record's
        /// length, which breaks every stdlib path that buffers across records
        /// — `peek`, `takeDelimiterInclusive` and friends, which is precisely
        /// what zurl's response parser is built from.
        fn streamImpl(
            io_r: *Io.Reader,
            io_w: *Io.Writer,
            limit: Io.Limit,
        ) Io.Reader.StreamError!usize {
            const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r));
            const self: *State = @alignCast(@fieldParentPtr("reader_impl", r));

            if (self.pending.len == 0) {
                self.pending = self.nextApplicationData() catch |err| switch (err) {
                    error.EndOfStream => return error.EndOfStream,
                    error.Failed => return error.ReadFailed,
                };
            }
            // A short write leaves the remainder pending for the next call,
            // and an error leaves it whole: `pending` only advances by what
            // the destination accepted.
            const n = try io_w.write(limit.sliceConst(self.pending));
            self.pending = self.pending[n..];
            return n;
        }
    };

    pub const Writer = struct {
        interface: Io.Writer,

        fn init(self: *State) Writer {
            return .{ .interface = .{
                .vtable = &.{ .drain = drainImpl },
                .buffer = &self.write_storage,
            } };
        }

        fn drainImpl(
            io_w: *Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) Io.Writer.Error!usize {
            const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            const self: *State = @alignCast(@fieldParentPtr("writer_impl", w));

            // Buffered plaintext first, then each slice, with the last
            // repeated `splat` times; `consume` subtracts the buffered part.
            var total: usize = 0;
            const buffered = io_w.buffered();
            if (buffered.len != 0) {
                try self.sendApplicationData(buffered);
                total += buffered.len;
            }
            if (data.len != 0) {
                for (data[0 .. data.len - 1]) |slice| {
                    try self.sendApplicationData(slice);
                    total += slice.len;
                }
                const last = data[data.len - 1];
                for (0..splat) |_| {
                    try self.sendApplicationData(last);
                    total += last.len;
                }
            }
            return io_w.consume(total);
        }
    };
};

/// zrk's half of the trust decision: the chain building and RFC 9525 name
/// matching zssl leaves to its embedder.
///
/// Reached through `ClientHandshake.Config.chain_verifier`, which shows the
/// peer's chain while its bytes are still live and takes a yes or no. The
/// reason for the failure is kept here because the callback can only answer
/// with a bool, and "which certificate error" is worth reporting.
///
/// Public because it serves **both** of zrk's TLS engines. QUIC needs a
/// handshake zssl declines to do, so `quic_tls.zig` is a second engine — but
/// "does zrk trust this chain" is the same question with the same answer, and
/// a second copy of it is the last thing a trust decision should have.
/// `verifyList` is the entry point that engine reaches, and it differs from
/// the one below only in taking the `certificate_list` octets rather than
/// zssl's view of them.
pub const Trust = struct {
    io: Io,
    /// null when this connection verifies nothing (`-k`, or no trust store).
    bundle: ?*const Certificate.Bundle,
    host: []const u8,
    failed: bool = false,

    pub fn verifier(self: *Trust) zssl.ClientHandshake.ChainVerifier {
        return .{ .context = self, .verify = Trust.verify };
    }

    /// The same decision, for a caller holding the `certificate_list` field's
    /// octets rather than a zssl wrapper over them — which is what
    /// `CertificateList` is, so this is the wrapper and nothing else.
    pub fn verifyList(context: *anyopaque, list: []const u8) bool {
        return Trust.verify(context, .init(list));
    }

    pub fn verify(context: *anyopaque, chain: zssl.certificate_list.CertificateList) bool {
        const self: *Trust = @ptrCast(@alignCast(context));
        const bundle = self.bundle orelse return true;
        verifyChain(bundle, chain, self.host, self.io) catch {
            self.failed = true;
            return false;
        };
        return true;
    }

    /// Turn a zssl handshake error into this file's vocabulary, using what
    /// the verifier recorded to tell "we refused the chain" apart from "the
    /// leaf's own signature did not check out" — zssl reports both as
    /// `BadCertificate`, and only the first is a trust decision zrk made.
    fn classify(self: *const Trust, err: anyerror) HandshakeError {
        if (self.failed) return error.CertificateVerificationFailed;
        return switch (err) {
            error.BadCertificate, error.BadSignature => error.CertificateVerificationFailed,
            error.BufferOverflow => error.HandshakeTooLarge,
            else => error.TlsHandshakeFailed,
        };
    }
};

/// What a certificate is permitted to do as an issuer (RFC 5280 §4.2.1.9,
/// §4.2.1.3), read back out of its DER.
///
/// `std.crypto.Certificate` parses these extensions' OIDs but keeps only the
/// subject alternative name, and `Parsed.verify` checks issuer name, validity
/// and signature and nothing else — so a chain walk built on it alone will
/// happily let an end-entity certificate sign another certificate. That is
/// the hole this closes.
const IssuerCapability = struct {
    is_ca: bool,
    /// `pathLenConstraint`: how many non-self-issued intermediates may sit
    /// between this certificate and the leaf. Null means unconstrained.
    path_len: ?u8,
    /// keyUsage is optional; absent means unconstrained (§4.2.1.3), present
    /// means `keyCertSign` has to be among the bits.
    permits_cert_sign: bool,
};

/// Re-walk `tbsCertificate` to the extensions block and read basicConstraints
/// and keyUsage.
///
/// The walk is duplicated from `std.crypto.Certificate.parse` because `Parsed`
/// does not retain the offset the extensions start at — it keeps slices, not
/// the `subjectPublicKeyInfo` element that locates what follows it.
fn issuerCapability(parsed: Certificate.Parsed) !IssuerCapability {
    // A v1 or v2 certificate carries no extensions at all, so it asserts no
    // cA bit and cannot be an issuer under this policy.
    if (parsed.version == .v1) return .{ .is_ca = false, .path_len = null, .permits_cert_sign = false };

    const der = Certificate.der;
    const bytes = parsed.certificate.buffer;
    const certificate = try der.Element.parse(bytes, parsed.certificate.index);
    const tbs = try der.Element.parse(bytes, certificate.slice.start);
    const version_elem = try der.Element.parse(bytes, tbs.slice.start);
    // `[0] EXPLICIT version` is optional; when absent the first element is
    // already the serial number.
    const serial = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try der.Element.parse(bytes, version_elem.slice.end)
    else
        version_elem;
    const tbs_signature = try der.Element.parse(bytes, serial.slice.end);
    const issuer = try der.Element.parse(bytes, tbs_signature.slice.end);
    const validity = try der.Element.parse(bytes, issuer.slice.end);
    const subject = try der.Element.parse(bytes, validity.slice.end);
    const pub_key_info = try der.Element.parse(bytes, subject.slice.end);

    var capability: IssuerCapability = .{
        .is_ca = false,
        .path_len = null,
        // Absent keyUsage is unconstrained, so this starts true and is
        // narrowed only if the extension actually appears.
        .permits_cert_sign = true,
    };
    if (pub_key_info.slice.end >= tbs.slice.end) return capability;

    // `[3] EXPLICIT extensions`. std matches the context tag number against
    // `.bitstring` because both are 3; the same trick is used here so the two
    // walks cannot disagree about where extensions begin.
    const outer = try der.Element.parse(bytes, pub_key_info.slice.end);
    if (outer.identifier.tag != .bitstring) return capability;
    const extensions = try der.Element.parse(bytes, outer.slice.start);

    var index = extensions.slice.start;
    while (index < extensions.slice.end) {
        const extension = try der.Element.parse(bytes, index);
        index = extension.slice.end;
        const oid = try der.Element.parse(bytes, extension.slice.start);
        // The optional `critical` BOOLEAN sits between the OID and the value.
        const after_oid = try der.Element.parse(bytes, oid.slice.end);
        const value = if (after_oid.identifier.tag != .boolean)
            after_oid
        else
            try der.Element.parse(bytes, after_oid.slice.end);
        const oid_bytes = bytes[oid.slice.start..oid.slice.end];
        if (std.mem.eql(u8, oid_bytes, &.{ 0x55, 0x1d, 0x13 })) {
            try readBasicConstraints(bytes, value, &capability);
        } else if (std.mem.eql(u8, oid_bytes, &.{ 0x55, 0x1d, 0x0f })) {
            capability.permits_cert_sign = try readKeyCertSign(bytes, value);
        }
    }
    return capability;
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
/// pathLenConstraint INTEGER (0..MAX) OPTIONAL }`, inside the extension's
/// OCTET STRING.
fn readBasicConstraints(
    bytes: []const u8,
    value: Certificate.der.Element,
    capability: *IssuerCapability,
) !void {
    const der = Certificate.der;
    const sequence = try der.Element.parse(bytes, value.slice.start);
    if (sequence.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;
    var index = sequence.slice.start;
    if (index >= sequence.slice.end) return; // Both members defaulted/absent.
    const first = try der.Element.parse(bytes, index);
    var rest = first;
    if (first.identifier.tag == .boolean) {
        if (first.slice.end - first.slice.start != 1) return error.CertificateFieldHasInvalidLength;
        // DER says TRUE is 0xff, but be liberal in what a nonzero byte means
        // here: anything other than zero asserts the bit.
        capability.is_ca = bytes[first.slice.start] != 0;
        index = first.slice.end;
        if (index >= sequence.slice.end) return;
        rest = try der.Element.parse(bytes, index);
    }
    if (rest.identifier.tag == .integer) {
        const length = rest.slice.end - rest.slice.start;
        // A path length that does not fit in a byte is longer than any chain
        // we would walk, so it constrains nothing.
        if (length == 1) capability.path_len = bytes[rest.slice.start];
    }
}

/// `KeyUsage ::= BIT STRING`, where `keyCertSign` is bit 5 counting from the
/// most significant bit of the first data byte.
fn readKeyCertSign(bytes: []const u8, value: Certificate.der.Element) !bool {
    const der = Certificate.der;
    const bit_string = try der.Element.parse(bytes, value.slice.start);
    if (bit_string.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    // The first content byte counts unused trailing bits; the flags follow.
    if (bit_string.slice.end - bit_string.slice.start < 2) return false;
    const flags = bytes[bit_string.slice.start + 1];
    return flags & 0x04 != 0;
}

const VerifyError = error{
    CertificateHostMismatch,
    CertificateIssuerNotFound,
    CertificateMalformed,
    CertificateNotTrusted,
    /// A certificate in the chain signed the one before it without being
    /// allowed to sign anything: no `cA` bit, no `keyCertSign`, or a
    /// `pathLenConstraint` shorter than the chain that followed it.
    CertificateIssuerNotCa,
};

/// Walk the peer's chain from leaf to anchor, the way `std.crypto.tls.Client`
/// does internally: the leaf's name must match the host, each certificate must
/// be signed by the next, and some certificate along the way must be signed by
/// something in the system bundle.
fn verifyChain(
    bundle: *const Certificate.Bundle,
    chain: zssl.certificate_list.CertificateList,
    host: []const u8,
    io: Io,
) VerifyError!void {
    const now_sec = Io.Timestamp.now(io, .real).toSeconds();
    var it = chain.iterator();
    var index: usize = 0;
    var previous: Certificate.Parsed = undefined;
    while (it.next() catch return error.CertificateMalformed) |der| : (index += 1) {
        const certificate: Certificate = .{ .buffer = der, .index = 0 };
        const subject = certificate.parse() catch return error.CertificateMalformed;
        if (index == 0) {
            // RFC 9525: the name is checked on the leaf and nowhere else.
            subject.verifyHostName(host) catch return error.CertificateHostMismatch;
        } else {
            // Each certificate must actually have issued the one before it,
            // so a peer cannot smuggle an unrelated trusted certificate into
            // the list to satisfy the anchor check below.
            previous.verify(subject, now_sec) catch return error.CertificateNotTrusted;
            // And it must have been *allowed* to issue it. Without this, any
            // holder of a publicly-trusted end-entity certificate can sign a
            // certificate for any name and present
            // [forged, their_leaf, real_intermediate]: every signature checks
            // out and the walk reaches a real anchor. `Parsed.verify` does not
            // look at basicConstraints, so the check has to be here.
            const capability = issuerCapability(subject) catch return error.CertificateMalformed;
            if (!capability.is_ca) return error.CertificateIssuerNotCa;
            if (!capability.permits_cert_sign) return error.CertificateIssuerNotCa;
            // `pathLenConstraint` counts the intermediates allowed between
            // this certificate and the leaf, which is how many the peer put
            // there: everything at a lower index except the leaf itself.
            if (capability.path_len) |limit| {
                if (index - 1 > limit) return error.CertificateIssuerNotCa;
            }
        }
        if (bundle.verify(subject, now_sec)) {
            return;
        } else |err| switch (err) {
            // Not an anchor: keep walking outward.
            error.CertificateIssuerNotFound => {},
            else => return error.CertificateNotTrusted,
        }
        previous = subject;
    }
    // Every certificate the peer sent, and none of them reached an anchor.
    return error.CertificateIssuerNotFound;
}

/// A self-signed P-256 leaf for `zrk.test`, valid until 2126, generated by
/// openssl and committed as DER so the tests need neither a network nor an
/// openssl on PATH. Throwaway material, never a credential.
const test_leaf_der = @embedFile("testdata/leaf.der");

/// A second self-signed leaf, unrelated to the first — a different key and a
/// different name — for the case where a chain's links do not actually sign
/// each other.
const test_unrelated_der = @embedFile("testdata/unrelated.der");

/// Frame one DER certificate as a §4.4.2 `certificate_list` — a u24 length
/// and an empty extensions block per entry — so a test can hand `verifyChain`
/// what the handshake would.
fn testChain(storage: []u8, certificates: []const []const u8) zssl.certificate_list.CertificateList {
    var index: usize = 0;
    for (certificates) |der| {
        std.mem.writeInt(u24, storage[index..][0..3], @intCast(der.len), .big);
        index += 3;
        @memcpy(storage[index..][0..der.len], der);
        index += der.len;
        std.mem.writeInt(u16, storage[index..][0..2], 0, .big);
        index += 2;
    }
    return .init(storage[0..index]);
}

/// A CA (`CA:TRUE`, `keyCertSign`) and a leaf it actually issued.
const test_ca_der = @embedFile("testdata/ca.der");
const test_ca_issued_leaf_der = @embedFile("testdata/ca-issued-leaf.der");

/// The impersonation chain: an ordinary end-entity certificate
/// (`CA:FALSE`) and a leaf for someone else's name that it signed.
const test_attacker_leaf_der = @embedFile("testdata/attacker-leaf.der");
const test_forged_leaf_der = @embedFile("testdata/forged-leaf.der");

test "verifyChain refuses an end-entity certificate acting as a CA" {
    // The attack this exists to stop: an adversary holding any leaf a real
    // CA issued signs a certificate for someone else's name and presents
    // [forged, their_leaf, real_intermediate, ...]. Every signature checks
    // out and the walk reaches a genuine anchor, so name matching and
    // link-signing alone accept it. `basicConstraints` is what does not.
    var storage: [4096]u8 = undefined;
    const chain = testChain(&storage, &.{ test_forged_leaf_der, test_attacker_leaf_der });
    const empty: Certificate.Bundle = .empty;
    try std.testing.expectError(
        error.CertificateIssuerNotCa,
        verifyChain(&empty, chain, "victim.zrk.test", std.testing.io),
    );
}

test "verifyChain accepts a real CA as an issuer" {
    // The other half of the pair: an issuer that does assert cA and
    // keyCertSign passes the capability check and the walk continues,
    // failing only because this bundle trusts nothing. Without this the
    // test above would pass just as well against a check that refused
    // every issuer.
    var storage: [4096]u8 = undefined;
    const chain = testChain(&storage, &.{ test_ca_issued_leaf_der, test_ca_der });
    const empty: Certificate.Bundle = .empty;
    try std.testing.expectError(
        error.CertificateIssuerNotFound,
        verifyChain(&empty, chain, "good.zrk.test", std.testing.io),
    );
}

test "verifyChain checks the name on the leaf, before the anchor" {
    var storage: [1024]u8 = undefined;
    const chain = testChain(&storage, &.{test_leaf_der});
    // An empty bundle trusts nothing, so a name that *matches* can only fail
    // by running out of chain — which is what separates the two branches.
    const empty: Certificate.Bundle = .empty;
    const io = std.testing.io;

    try std.testing.expectError(
        error.CertificateHostMismatch,
        verifyChain(&empty, chain, "not-zrk.test", io),
    );
    try std.testing.expectError(
        error.CertificateIssuerNotFound,
        verifyChain(&empty, chain, "zrk.test", io),
    );
    // The SAN carries two names and both must be honoured; a check that only
    // read the subject CN would pass the first and fail this.
    try std.testing.expectError(
        error.CertificateIssuerNotFound,
        verifyChain(&empty, chain, "www.zrk.test", io),
    );
}

test "verifyChain refuses a chain whose links do not sign each other" {
    // An unrelated certificate appended after the leaf. It did not issue the
    // leaf, so the link check must reject it rather than walking on to look
    // for an anchor — without that check a peer could append any certificate
    // it liked in order to reach one the bundle happens to trust.
    //
    // Not the leaf twice: a self-signed certificate *is* validly signed by
    // itself, so that pair is a legitimate link and proves nothing.
    var storage: [1024]u8 = undefined;
    const chain = testChain(&storage, &.{ test_leaf_der, test_unrelated_der });
    const empty: Certificate.Bundle = .empty;
    try std.testing.expectError(
        error.CertificateNotTrusted,
        verifyChain(&empty, chain, "zrk.test", std.testing.io),
    );
}

test "verifyChain rejects a malformed chain rather than trusting it" {
    // A length that overruns the buffer: the iterator errors, and the
    // failure must be a refusal, not a fall-through to "no issuer found".
    var storage: [16]u8 = .{ 0, 0xff, 0xff, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const chain = zssl.certificate_list.CertificateList.init(storage[0..6]);
    const empty: Certificate.Bundle = .empty;
    try std.testing.expectError(
        error.CertificateMalformed,
        verifyChain(&empty, chain, "zrk.test", std.testing.io),
    );
}

/// What to offer for each protocol, in preference order.
///
/// `http/1.1` is offered alongside `h2` so that a server without HTTP/2 answers
/// on the protocol it does have instead of failing the handshake — the caller
/// then sees the mismatch through `negotiatedAlpn` and can report it.
pub const alpn_http1: []const []const u8 = &.{"http/1.1"};
pub const alpn_http2: []const []const u8 = &.{ "h2", "http/1.1" };
