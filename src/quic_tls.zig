//! A TLS 1.3 client handshake in QUIC mode, for `h3conn.zig` and nothing else.
//!
//! ## Why this file exists at all
//!
//! zrk terminates TLS through zssl everywhere else, and zssl is the right
//! engine: it is audited Zig over a constant-time libcrypto, and `src/tls.zig`
//! adds the two things it declines — the `std.Io` adapter and X.509 chain and
//! hostname verification. **zssl does not do QUIC** (its README: "Out, for
//! now: ... and QUIC"), and QUIC does not want a TLS *record* layer at all.
//! RFC 9001 §4 replaces it: handshake messages cross as CRYPTO frames, and
//! what the engine hands back is a traffic secret per encryption level rather
//! than a sealed record. There is no way to drive that through an API whose
//! unit is a record.
//!
//! So this is a second, much smaller TLS client, vendored from h3's
//! `interop/tls.zig` — the file that completed real handshakes against
//! quic-go, ngtcp2 and aioquic in the QUIC Interop Runner. It is here rather
//! than in h3 because h3's `paths` ships `src/` only: `interop/` is that
//! package's test harness, deliberately not part of its library.
//!
//! ## What it does and does not check
//!
//! **It verifies certificates**, through the same decision the other two
//! transports make: `tls.Trust` builds the chain to a system anchor and
//! matches the name, and it is reached from here by the same callback zssl
//! reaches it by. One implementation of "does zrk trust this chain", two TLS
//! engines — because a second copy of a trust decision is the last thing a
//! trust decision should have.
//!
//! What is written here rather than borrowed is RFC 8446 §4.4.3's
//! `CertificateVerify`: the peer signing the transcript through `Certificate`
//! under a context string, checked against the leaf's own key. That is the
//! half a chain cannot give you — without it the chain says only that
//! *somebody* was issued a certificate for the name, and anyone able to reach
//! the client could replay one they do not hold the key for. The five schemes
//! `clientHello` offers are the five it verifies, and a scheme that disagrees
//! with the key the leaf actually carries is refused before any verifier sees
//! the bytes.
//!
//! `--insecure` is the only thing that turns any of this off, and it does so
//! by handing this file no verifier at all.
//!
//! **It offers only SHA-256 suites** — `TLS_AES_128_GCM_SHA256` and
//! `TLS_CHACHA20_POLY1305_SHA256` — because the key schedule below is written
//! against one hash rather than parameterised over two. `h3`'s packet
//! protection supports AES-256-GCM regardless of whether this file can
//! negotiate it.
//!
//! **It offers one group**, X25519, and refuses a HelloRetryRequest rather
//! than answering one. **No 0-RTT, no session tickets, no post-handshake
//! authentication**; a `NewSessionTicket` is read off the 1-RTT crypto stream
//! and discarded, which is what keeps a server that sends two of them from
//! stalling the connection.
//!
//! ## The transcript, which is where this goes wrong
//!
//! Three derivations read the transcript hash at three different points, and
//! the boundaries are not interchangeable:
//!
//! - the handshake traffic secrets, at `ClientHello .. ServerHello`;
//! - the server's `Finished`, verified at `ClientHello .. CertificateVerify`,
//!   which is to say *before* that `Finished` is added;
//! - the application traffic secrets and the client's own `Finished`, at
//!   `ClientHello .. server Finished`, which is to say after.
//!
//! `message` is arranged so each of the three happens at its own boundary and
//! the reader can see which. A transcript off by one message produces secrets
//! that are wrong in a way nothing local can detect: the failure surfaces as
//! the peer discarding packets it cannot authenticate.

const std = @import("std");

const h3 = @import("h3");

const Certificate = std.crypto.Certificate;
const Hash = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

const Level = h3.quic.crypto.Level;
const Suite = h3.quic.crypto.Suite;

/// SHA-256's output, which is a traffic secret's length for every suite this
/// file offers.
pub const secret_octets: usize = Hash.digest_length;
/// X25519's public key and its shared secret are both this.
const share_octets: usize = 32;

/// TLS 1.3's cipher suite code points, restricted to the two whose hash is
/// SHA-256. `aes_256_gcm_sha384` is deliberately absent; see the module
/// comment.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    chacha20_poly1305_sha256 = 0x1303,

    fn quic(self: CipherSuite) Suite {
        return switch (self) {
            .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
            .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
        };
    }
};

/// RFC 8446 section 4: the handshake message types this file acts on. Anything
/// else is a protocol error rather than something to skip, because a message
/// this client did not expect is a handshake it did not understand.
const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    _,
};

const Extension = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    alpn = 16,
    supported_versions = 43,
    key_share = 51,
    /// RFC 9001 section 8.2.
    quic_transport_parameters = 57,
    _,
};

/// X25519's code point in TLS's named group registry.
const group_x25519: u16 = 0x001d;

/// RFC 8446 section 4.1.3: the `Random` a server sends to mean
/// HelloRetryRequest. Recognised so that the failure names itself.
const hello_retry_request_random: [32]u8 = .{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02,
    0x1e, 0x65, 0xb8, 0x91,
} ++ .{0} ** 16;

pub const Error = error{
    /// A message, extension or length field that does not parse, or a length
    /// that runs past the octets it was given.
    Malformed,
    /// A handshake this client cannot complete: a HelloRetryRequest, a suite
    /// or group it did not offer, a TLS version below 1.3, a message arriving
    /// at the wrong encryption level or in the wrong order.
    Unsupported,
    /// The server's `Finished` did not match the transcript. Either the
    /// handshake was tampered with, or — far likelier while this file is being
    /// written — a secret or a transcript boundary here is wrong.
    BadFinished,
    /// Something exceeded a fixed bound: the peer's transport parameters, or
    /// the ClientHello's own buffer.
    TooLarge,
    /// RFC 9001 section 8.1: the client offered no protocol this endpoint
    /// speaks. Its own error because the alert has its own number, and h3spec
    /// asserts on it — a handshake that failed for this reason and said
    /// `unexpected_message` is a handshake whose peer learns nothing.
    NoApplicationProtocol,
    /// RFC 9001 section 8.2: no `quic_transport_parameters` extension. Likewise
    /// its own alert.
    MissingExtension,
    /// The peer's certificate chain did not parse, or the embedder's verifier
    /// refused it: it did not build to a trusted anchor, or the leaf did not
    /// match the name that was asked for.
    BadCertificate,
    /// RFC 8446 section 4.4.3's `CertificateVerify` did not check out against
    /// the leaf's public key — so whoever is on the other end does not hold the
    /// key the certificate names, whatever the chain said.
    BadSignature,
};

/// The embedder's half of the trust decision, shown the peer's chain while its
/// octets are still live and asked for a yes or a no.
///
/// The same shape `zssl.ClientHandshake.ChainVerifier` has, deliberately, so
/// that one implementation of "does zrk trust this chain" serves both of zrk's
/// TLS engines — see `tls.Trust`. It crosses as the `certificate_list` field's
/// raw octets rather than as a zssl type, because a file that exists because
/// zssl does not do QUIC should not import zssl to describe its arguments.
pub const ChainVerifier = struct {
    context: *anyopaque,
    /// Every `CertificateEntry`, with the enclosing u24 length already
    /// stripped. Leaf first, in the order RFC 8446 section 4.4.2 fixes.
    verify: *const fn (context: *anyopaque, list: []const u8) bool,
};

/// The largest leaf public key this client will hold, matching the bound
/// `std.crypto.tls.Client` uses for the same job: the key has to outlive the
/// chain, because `CertificateVerify` arrives a message after the octets it
/// came in have gone.
const leaf_key_octets: usize = 600;

/// RFC 8446 section 4.4.3: what a server's `CertificateVerify` signs, ahead of
/// the transcript hash.
const certificate_verify_context = [_]u8{0x20} ** 64 ++ "TLS 1.3, server CertificateVerify" ++ [_]u8{0};

/// A traffic secret to hand to `Connection.installSecret`, held until the
/// caller drains it. An array rather than an event queue with slices in it:
/// the caller drives both sides of the seam in one loop, and a secret that
/// borrows from a parse buffer is a use-after-free waiting for the next
/// datagram.
pub const Install = struct {
    level: Level,
    direction: enum { send, receive },
    secret: [secret_octets]u8,
    suite: Suite,
    /// The NSS key log label for this secret, so `SSLKEYLOGFILE` can be
    /// written without the caller re-deriving which secret it just received.
    label: []const u8,
};

pub const Options = struct {
    /// The name to put in SNI, and the one this client does not check the
    /// certificate against.
    server_name: []const u8,
    /// The single protocol to offer. `hq-interop` for the HTTP/0.9 test cases,
    /// `h3` for the HTTP/3 ones.
    alpn: []const u8,
    /// The QUIC transport parameters extension's *body*: the encoding
    /// `transport_parameters.encode` produces. RFC 9001 section 8.2 carries it
    /// in the ClientHello, which is on this side of the seam.
    transport_parameters: []const u8,
    /// The suites to offer, in preference order.
    offer: []const CipherSuite,
    /// 32 octets of entropy for the ClientHello's `Random`, and 32 for the
    /// X25519 private key. Parameters rather than draws, for the same reason
    /// `now_ns` is a parameter in `src/`: a handshake this file cannot replay
    /// is a handshake nothing can debug.
    random: [32]u8,
    key_seed: [32]u8,
    /// Who decides whether the peer's chain is trusted, or null to check
    /// neither the chain nor the leaf's signature.
    ///
    /// Null is what `--insecure` means, and it is the *only* thing that means
    /// it: with a verifier present this client refuses a chain the verifier
    /// declines and a `CertificateVerify` that does not check out, so a run
    /// cannot end up unauthenticated by accident.
    chain_verifier: ?ChainVerifier = null,
};

pub const Client = struct {
    /// Where the handshake is. The order is RFC 8446 section 4.4.2's, and a
    /// message arriving out of it is `error.Unsupported` rather than something
    /// to buffer: a client that tolerates reordering here is a client that
    /// hashes the transcript in an order the server did not.
    state: enum {
        wait_server_hello,
        wait_encrypted_extensions,
        wait_certificate,
        wait_certificate_verify,
        wait_finished,
        established,
    } = .wait_server_hello,

    random: [32]u8,
    key_pair: X25519.KeyPair,
    server_name: []const u8,
    alpn: []const u8,
    transport_parameters: []const u8,
    offer: []const CipherSuite,

    transcript: Hash = Hash.init(.{}),
    /// The ECDHE output, held between parsing the ServerHello and deriving
    /// from it. A field rather than a local because the transcript update sits
    /// between the two and has to happen first.
    shared: [share_octets]u8 = @splat(0),
    suite: CipherSuite = .aes_128_gcm_sha256,

    /// RFC 8446 section 7.1's schedule, kept because each stage is the salt of
    /// the next and the next arrives a round trip later.
    handshake_secret: [secret_octets]u8 = @splat(0),
    client_handshake_traffic: [secret_octets]u8 = @splat(0),
    server_handshake_traffic: [secret_octets]u8 = @splat(0),

    /// Secrets produced and not yet installed. Four is the whole handshake:
    /// two at Handshake and two at 1-RTT, and the two halves of a level are
    /// always produced together.
    installs: [4]Install = undefined,
    installs_len: u8 = 0,

    /// The client's `Finished`, waiting to be handed to `cryptoIn`. Sized for
    /// a handshake header and SHA-256's output and asserted against both.
    finished: [4 + secret_octets]u8 = @splat(0),
    finished_len: u8 = 0,

    /// The server's QUIC transport parameters, as the extension's octets.
    /// 1024 matches `Connection.Config.transport_parameters_octets`; a server
    /// sending more is refused here rather than at `transportParametersIn`, so
    /// the error names the side that was too large.
    peer_parameters: [1024]u8 = @splat(0),
    peer_parameters_len: u16 = 0,
    peer_parameters_seen: bool = false,

    /// Who answers for the chain, and the leaf's key kept back from it.
    ///
    /// The key is copied rather than borrowed because `CertificateVerify`
    /// arrives a message after `Certificate`, and by then the octets the chain
    /// came in have been consumed: `read` is handed a view of the connection's
    /// crypto buffer, which the caller reclaims as soon as it returns.
    chain_verifier: ?ChainVerifier = null,
    leaf_algo: Certificate.AlgorithmCategory = .rsaEncryption,
    leaf_key: [leaf_key_octets]u8 = @splat(0),
    leaf_key_len: u16 = 0,

    pub fn init(options: Options) Client {
        return .{
            .random = options.random,
            // X25519 accepts any 32 octets as a private key: it clamps, and
            // the only failure `generateDeterministic` reports is an identity
            // element, which a seed cannot produce.
            .key_pair = X25519.KeyPair.generateDeterministic(options.key_seed) catch unreachable,
            .server_name = options.server_name,
            .alpn = options.alpn,
            .chain_verifier = options.chain_verifier,
            .transport_parameters = options.transport_parameters,
            .offer = options.offer,
        };
    }

    // -------------------------------------------------------------- outbound

    /// Write the ClientHello into `buffer` and fold it into the transcript.
    /// The caller hands the result to `cryptoIn(.initial, ...)`.
    pub fn clientHello(self: *Client, buffer: []u8) Error![]const u8 {
        var out: Writer = .{ .buffer = buffer };

        try out.byte(@intFromEnum(MessageType.client_hello));
        const body = try out.beginLength(3);
        {
            // `legacy_version` is 1.2 on the wire for every TLS 1.3 hello; the
            // real version is in `supported_versions`.
            try out.int(u16, 0x0303);
            try out.bytes(&self.random);
            // RFC 9001 section 8.4: over QUIC the session ID is empty, because
            // there is no middlebox to fool and no compatibility mode to enter.
            try out.byte(0);

            const suites = try out.beginLength(2);
            for (self.offer) |one| try out.int(u16, @intFromEnum(one));
            try out.endLength(suites);

            // One compression method, `null`. TLS 1.3 permits nothing else.
            try out.byte(1);
            try out.byte(0);

            const extensions = try out.beginLength(2);
            try self.writeExtensions(&out);
            try out.endLength(extensions);
        }
        try out.endLength(body);

        const written = out.written();
        self.transcript.update(written);
        return written;
    }

    fn writeExtensions(self: *Client, out: *Writer) Error!void {
        // server_name: a list of one, of type `host_name`.
        try out.int(u16, @intFromEnum(Extension.server_name));
        var extension = try out.beginLength(2);
        {
            const list = try out.beginLength(2);
            try out.byte(0);
            const name = try out.beginLength(2);
            try out.bytes(self.server_name);
            try out.endLength(name);
            try out.endLength(list);
        }
        try out.endLength(extension);

        // supported_groups: X25519 alone. See the module comment on HRR.
        try out.int(u16, @intFromEnum(Extension.supported_groups));
        extension = try out.beginLength(2);
        {
            const list = try out.beginLength(2);
            try out.int(u16, group_x25519);
            try out.endLength(list);
        }
        try out.endLength(extension);

        // signature_algorithms. Required to be present and, since nothing here
        // verifies a signature, its contents only have to be wide enough that
        // no server refuses for lack of an algorithm it holds a certificate
        // for. These are the five the runner's servers use between them.
        try out.int(u16, @intFromEnum(Extension.signature_algorithms));
        extension = try out.beginLength(2);
        {
            const list = try out.beginLength(2);
            try out.int(u16, 0x0403); // ecdsa_secp256r1_sha256
            try out.int(u16, 0x0503); // ecdsa_secp384r1_sha384
            try out.int(u16, 0x0804); // rsa_pss_rsae_sha256
            try out.int(u16, 0x0805); // rsa_pss_rsae_sha384
            try out.int(u16, 0x0806); // rsa_pss_rsae_sha512
            try out.endLength(list);
        }
        try out.endLength(extension);

        // ALPN. RFC 9001 section 8.1 requires one over QUIC, and the runner
        // decides which by test case.
        try out.int(u16, @intFromEnum(Extension.alpn));
        extension = try out.beginLength(2);
        {
            const list = try out.beginLength(2);
            const protocol = try out.beginLength(1);
            try out.bytes(self.alpn);
            try out.endLength(protocol);
            try out.endLength(list);
        }
        try out.endLength(extension);

        // supported_versions: 1.3 alone.
        try out.int(u16, @intFromEnum(Extension.supported_versions));
        extension = try out.beginLength(2);
        {
            const list = try out.beginLength(1);
            try out.int(u16, 0x0304);
            try out.endLength(list);
        }
        try out.endLength(extension);

        // key_share, so the handshake finishes in one round trip.
        try out.int(u16, @intFromEnum(Extension.key_share));
        extension = try out.beginLength(2);
        {
            const list = try out.beginLength(2);
            try out.int(u16, group_x25519);
            const key = try out.beginLength(2);
            try out.bytes(&self.key_pair.public_key);
            try out.endLength(key);
            try out.endLength(list);
        }
        try out.endLength(extension);

        // quic_transport_parameters, whose body the caller built with
        // `transport_parameters.encode`. This is the extension docs/DESIGN.md
        // section 4 says is assembled on this side of the seam.
        try out.int(u16, @intFromEnum(Extension.quic_transport_parameters));
        extension = try out.beginLength(2);
        try out.bytes(self.transport_parameters);
        try out.endLength(extension);
    }

    // --------------------------------------------------------------- inbound

    /// Consume whole handshake messages from the front of `source`, returning
    /// how many octets were taken. A partial message at the end is left for
    /// the next call, which is why the caller passes `cryptoOut`'s slice and
    /// then `cryptoConsumed`s exactly the return value.
    pub fn read(self: *Client, level: Level, source: []const u8) Error!usize {
        var offset: usize = 0;
        // Bounded by `source`: every iteration consumes at least the four
        // octets of a header, and the loop stops when fewer remain.
        while (source.len - offset >= 4) {
            const length = readInt(u24, source[offset + 1 ..][0..3]);
            const total = 4 + @as(usize, length);
            if (source.len - offset < total) break;
            try self.message(level, source[offset..][0..total]);
            offset += total;
        }
        return offset;
    }

    /// One message, header included. `body` below is the message without it.
    fn message(self: *Client, level: Level, whole: []const u8) Error!void {
        std.debug.assert(whole.len >= 4);
        const kind: MessageType = @enumFromInt(whole[0]);
        const body = whole[4..];

        switch (kind) {
            .server_hello => {
                if (level != .initial) return error.Unsupported;
                if (self.state != .wait_server_hello) return error.Unsupported;
                try self.serverHello(body);
                // The handshake traffic secrets read the transcript at
                // `ClientHello .. ServerHello`, so the ServerHello goes in
                // before they are derived and after it is parsed — the shared
                // secret it carries is an input to the same derivation.
                self.transcript.update(whole);
                self.deriveHandshake();
                self.state = .wait_encrypted_extensions;
            },
            .encrypted_extensions => {
                if (level != .handshake) return error.Unsupported;
                if (self.state != .wait_encrypted_extensions) return error.Unsupported;
                self.transcript.update(whole);
                try self.encryptedExtensions(body);
                self.state = .wait_certificate;
            },
            .certificate_request => {
                // RFC 9001 section 4.4 forbids post-handshake client
                // authentication, and this client holds no certificate to
                // answer one during the handshake either.
                return error.Unsupported;
            },
            .certificate => {
                if (level != .handshake) return error.Unsupported;
                if (self.state != .wait_certificate) return error.Unsupported;
                try self.certificate(whole[4..]);
                self.transcript.update(whole);
                self.state = .wait_certificate_verify;
            },
            .certificate_verify => {
                if (level != .handshake) return error.Unsupported;
                if (self.state != .wait_certificate_verify) return error.Unsupported;
                // Before the transcript takes this message, and that ordering
                // is the whole of it: section 4.4.3 signs the transcript
                // through `Certificate` and not through this. Updating first
                // would verify against a hash the server never computed.
                if (self.chain_verifier != null) try self.certificateVerify(whole[4..]);
                self.transcript.update(whole);
                self.state = .wait_finished;
            },
            .finished => {
                if (level != .handshake) return error.Unsupported;
                if (self.state != .wait_finished) return error.Unsupported;
                // Verified against `ClientHello .. CertificateVerify`, which is
                // the transcript as it stands *before* this message joins it.
                try self.verifyFinished(body);
                self.transcript.update(whole);
                // And everything after reads `ClientHello .. server Finished`.
                self.deriveApplication();
                self.writeFinished();
                self.state = .established;
            },
            .new_session_ticket => {
                // Post-handshake, at 1-RTT, and of no use to a client that
                // does not resume. Discarded rather than refused: a server
                // that sends two would otherwise fail a connection that is
                // working.
                if (level != .one_rtt) return error.Unsupported;
                if (self.state != .established) return error.Unsupported;
            },
            else => return error.Unsupported,
        }
    }

    fn serverHello(self: *Client, body: []const u8) Error!void {
        var in: Reader = .{ .buffer = body };

        if (try in.int(u16) != 0x0303) return error.Unsupported;
        const random = try in.take(32);
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.Unsupported;
        // RFC 9001 section 8.4: an empty session ID went out, so an empty one
        // comes back.
        if (try in.byte() != 0) return error.Unsupported;

        const suite = try in.int(u16);
        self.suite = for (self.offer) |one| {
            if (@intFromEnum(one) == suite) break one;
        } else return error.Unsupported;

        if (try in.byte() != 0) return error.Unsupported; // compression

        var version_seen = false;
        var share: ?[]const u8 = null;
        var extensions: Reader = .{ .buffer = try in.lengthPrefixed(2) };
        // Bounded by the extensions block: `extension` consumes its own length
        // every iteration.
        while (!extensions.done()) {
            const id: Extension = @enumFromInt(try extensions.int(u16));
            const value = try extensions.lengthPrefixed(2);
            switch (id) {
                .supported_versions => {
                    if (value.len != 2 or readInt(u16, value[0..2]) != 0x0304) return error.Unsupported;
                    version_seen = true;
                },
                .key_share => {
                    var one: Reader = .{ .buffer = value };
                    if (try one.int(u16) != group_x25519) return error.Unsupported;
                    share = try one.lengthPrefixed(2);
                },
                else => {},
            }
        }
        // A ServerHello without `supported_versions` is a TLS 1.2 server, and
        // RFC 9001 section 4.2 makes that fatal rather than a downgrade.
        if (!version_seen) return error.Unsupported;

        const public = share orelse return error.Unsupported;
        if (public.len != share_octets) return error.Malformed;
        const shared = X25519.scalarmult(self.key_pair.secret_key, public[0..share_octets].*) catch
            return error.Unsupported; // An identity element: no shared secret exists.
        self.shared = shared;
    }

    fn encryptedExtensions(self: *Client, body: []const u8) Error!void {
        var extensions: Reader = .{ .buffer = try (Reader{ .buffer = body }).lengthPrefixedOf(2) };
        // Bounded by the block, as in `serverHello`.
        while (!extensions.done()) {
            const id: Extension = @enumFromInt(try extensions.int(u16));
            const value = try extensions.lengthPrefixed(2);
            if (id != .quic_transport_parameters) continue;
            if (value.len > self.peer_parameters.len) return error.TooLarge;
            @memcpy(self.peer_parameters[0..value.len], value);
            self.peer_parameters_len = @intCast(value.len);
            self.peer_parameters_seen = true;
        }
        // RFC 9001 section 8.2 makes the extension mandatory in both
        // directions, and a server that omits it has told this client nothing
        // about its limits — including the ones it will enforce.
        if (!self.peer_parameters_seen) return error.Unsupported;
    }

    fn verifyFinished(self: *Client, body: []const u8) Error!void {
        var expected: [Hmac.mac_length]u8 = undefined;
        self.finishedData(&self.server_handshake_traffic, &expected);
        if (body.len != expected.len) return error.BadFinished;
        // Constant-time, because this is a MAC comparison and the timing of a
        // byte-by-byte one is the classic way to forge one.
        if (!std.crypto.timing_safe.eql([Hmac.mac_length]u8, expected, body[0..Hmac.mac_length].*)) {
            return error.BadFinished;
        }
    }

    fn writeFinished(self: *Client) void {
        var verify: [Hmac.mac_length]u8 = undefined;
        self.finishedData(&self.client_handshake_traffic, &verify);
        self.finished[0] = @intFromEnum(MessageType.finished);
        writeInt(u24, self.finished[1..4], @intCast(verify.len));
        @memcpy(self.finished[4..][0..verify.len], &verify);
        self.finished_len = @intCast(4 + verify.len);
        std.debug.assert(self.finished_len == self.finished.len);
    }

    /// RFC 8446 section 4.4.4's `verify_data`, over the transcript as it
    /// stands.
    fn finishedData(self: *Client, traffic: *const [secret_octets]u8, out: *[Hmac.mac_length]u8) void {
        var key: [secret_octets]u8 = undefined;
        expandLabel(&key, traffic, "finished", "");
        var digest: [Hash.digest_length]u8 = undefined;
        var copy = self.transcript;
        copy.final(&digest);
        Hmac.create(out, &digest, &key);
    }

    // -------------------------------------------------------- the schedule

    /// RFC 8446 section 7.1, as far as the handshake traffic secrets.
    fn deriveHandshake(self: *Client) void {
        const zero: [secret_octets]u8 = @splat(0);
        const early = Hkdf.extract(&.{}, &zero);
        var derived: [secret_octets]u8 = undefined;
        self.deriveSecretEmpty(&derived, &early, "derived");

        self.handshake_secret = Hkdf.extract(&derived, &self.shared);
        self.deriveSecret(&self.client_handshake_traffic, &self.handshake_secret, "c hs traffic");
        self.deriveSecret(&self.server_handshake_traffic, &self.handshake_secret, "s hs traffic");

        self.install(.handshake, .send, &self.client_handshake_traffic, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        self.install(.handshake, .receive, &self.server_handshake_traffic, "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    }

    /// The rest of section 7.1: the master secret, and the two 1-RTT secrets
    /// that QUIC turns into packet protection keys.
    fn deriveApplication(self: *Client) void {
        const zero: [secret_octets]u8 = @splat(0);
        var derived: [secret_octets]u8 = undefined;
        self.deriveSecretEmpty(&derived, &self.handshake_secret, "derived");
        const master = Hkdf.extract(&derived, &zero);

        var client_traffic: [secret_octets]u8 = undefined;
        var server_traffic: [secret_octets]u8 = undefined;
        self.deriveSecret(&client_traffic, &master, "c ap traffic");
        self.deriveSecret(&server_traffic, &master, "s ap traffic");

        self.install(.one_rtt, .send, &client_traffic, "CLIENT_TRAFFIC_SECRET_0");
        self.install(.one_rtt, .receive, &server_traffic, "SERVER_TRAFFIC_SECRET_0");
    }

    /// `Derive-Secret(secret, label, Messages)` with `Messages` the transcript
    /// so far.
    fn deriveSecret(self: *Client, out: *[secret_octets]u8, secret: *const [secret_octets]u8, label: []const u8) void {
        var digest: [Hash.digest_length]u8 = undefined;
        var copy = self.transcript;
        copy.final(&digest);
        expandLabel(out, secret, label, &digest);
    }

    /// The same, with `Messages` empty — which is a different value from the
    /// transcript being empty only because `Derive-Secret` hashes it either
    /// way. Separate so the two cannot be confused at a call site.
    fn deriveSecretEmpty(self: *Client, out: *[secret_octets]u8, secret: *const [secret_octets]u8, label: []const u8) void {
        _ = self;
        var digest: [Hash.digest_length]u8 = undefined;
        Hash.hash("", &digest, .{});
        expandLabel(out, secret, label, &digest);
    }

    fn install(self: *Client, level: Level, direction: @FieldType(Install, "direction"), secret: *const [secret_octets]u8, label: []const u8) void {
        // Four is the whole handshake; a fifth would mean a state machine that
        // derived a level twice.
        std.debug.assert(self.installs_len < self.installs.len);
        self.installs[self.installs_len] = .{
            .level = level,
            .direction = direction,
            .secret = secret.*,
            .suite = self.suite.quic(),
            .label = label,
        };
        self.installs_len += 1;
    }

    /// Secrets produced since the last call, and none of them again.
    /// RFC 8446 section 4.4.2's `Certificate`: a request context nobody sends
    /// for a server certificate, then the chain.
    ///
    /// Two things come out of it. The chain goes to the embedder's verifier
    /// while its octets are still live — chain building and name matching are
    /// not this file's job and are already written once, for the other engine.
    /// The leaf's public key is copied out, because it is what checks the
    /// signature that arrives in the next message.
    fn certificate(self: *Client, body: []const u8) Error!void {
        if (body.len < 1) return error.Malformed;
        const context_octets: usize = body[0];
        if (body.len - 1 < context_octets + 3) return error.Malformed;
        const at = 1 + context_octets;
        const list_octets = readInt(u24, body[at..][0..3]);
        if (body.len - at - 3 < list_octets) return error.Malformed;
        const list = body[at + 3 ..][0..list_octets];

        // Section 4.4.2: the sender's certificate comes first, and it is the
        // one the signature below has to belong to.
        if (list.len < 3) return error.BadCertificate;
        const leaf_octets = readInt(u24, list[0..3]);
        if (leaf_octets == 0 or list.len - 3 < leaf_octets) return error.BadCertificate;
        const leaf: Certificate = .{ .buffer = list[3..][0..leaf_octets], .index = 0 };
        const parsed = leaf.parse() catch return error.BadCertificate;
        const key = parsed.pubKey();
        if (key.len > self.leaf_key.len) return error.BadCertificate;
        @memcpy(self.leaf_key[0..key.len], key);
        self.leaf_key_len = @intCast(key.len);
        self.leaf_algo = parsed.pub_key_algo;

        const verifier = self.chain_verifier orelse return;
        if (!verifier.verify(verifier.context, list)) return error.BadCertificate;
    }

    /// RFC 8446 section 4.4.3: the peer proves it holds the key its leaf names,
    /// by signing the transcript through `Certificate` under a context string.
    ///
    /// Without this the chain says only that *somebody* was issued a
    /// certificate for the name — anyone who can reach the client could replay
    /// a chain they do not hold the key for.
    fn certificateVerify(self: *Client, body: []const u8) Error!void {
        if (body.len < 4) return error.Malformed;
        const scheme = readInt(u16, body[0..2]);
        const signature_octets = readInt(u16, body[2..4]);
        if (body.len - 4 < signature_octets) return error.Malformed;
        const signature = body[4..][0..signature_octets];

        // The hash through `Certificate`, which is why this runs before the
        // transcript takes the message carrying it.
        var digest: [Hash.digest_length]u8 = undefined;
        var through_certificate = self.transcript;
        through_certificate.final(&digest);
        const signed = [_][]const u8{ certificate_verify_context, &digest };

        const key = self.leaf_key[0..self.leaf_key_len];
        if (key.len == 0) return error.BadCertificate;

        // The scheme has to agree with the key the leaf actually carries, or a
        // peer could name a scheme whose verifier is happier with its bytes.
        switch (scheme) {
            0x0403, 0x0503 => if (self.leaf_algo != .X9_62_id_ecPublicKey) return error.BadSignature,
            0x0804, 0x0805, 0x0806 => if (self.leaf_algo != .rsaEncryption) return error.BadSignature,
            else => return error.Unsupported,
        }
        switch (scheme) {
            0x0403 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, key, signature, &signed),
            0x0503 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, key, signature, &signed),
            0x0804 => try verifyRsaPss(std.crypto.hash.sha2.Sha256, key, signature, &signed),
            0x0805 => try verifyRsaPss(std.crypto.hash.sha2.Sha384, key, signature, &signed),
            0x0806 => try verifyRsaPss(std.crypto.hash.sha2.Sha512, key, signature, &signed),
            // Unreachable: the switch above already refused anything else, and
            // `clientHello` offers exactly these five.
            else => return error.Unsupported,
        }
    }

    pub fn drainInstalls(self: *Client) []const Install {
        const out = self.installs[0..self.installs_len];
        self.installs_len = 0;
        return out;
    }

    /// The client's `Finished`, once, or an empty slice.
    pub fn drainFinished(self: *Client) []const u8 {
        const out = self.finished[0..self.finished_len];
        self.finished_len = 0;
        return out;
    }

    /// The server's transport parameters, once, or null.
    pub fn drainTransportParameters(self: *Client) ?[]const u8 {
        if (!self.peer_parameters_seen) return null;
        self.peer_parameters_seen = false;
        return self.peer_parameters[0..self.peer_parameters_len];
    }
};

/// `HKDF-Expand-Label` from RFC 8446 section 7.1, with the "tls13 " prefix.
/// QUIC's own labels go through `src/quic/crypto/secrets.zig` instead; this one
/// is only ever used on the TLS side of the schedule.
fn expandLabel(out: []u8, secret: *const [secret_octets]u8, label: []const u8, context: []const u8) void {
    const prefix = "tls13 ";
    // The longest label here is "s hs traffic" at twelve, and the longest
    // context is a SHA-256 digest.
    var info: [2 + 1 + prefix.len + 16 + 1 + Hash.digest_length]u8 = undefined;
    std.debug.assert(label.len <= 16);
    std.debug.assert(context.len <= Hash.digest_length);

    var offset: usize = 0;
    writeInt(u16, info[offset..][0..2], @intCast(out.len));
    offset += 2;
    info[offset] = @intCast(prefix.len + label.len);
    offset += 1;
    @memcpy(info[offset..][0..prefix.len], prefix);
    offset += prefix.len;
    @memcpy(info[offset..][0..label.len], label);
    offset += label.len;
    info[offset] = @intCast(context.len);
    offset += 1;
    @memcpy(info[offset..][0..context.len], context);
    offset += context.len;

    Hkdf.expand(out, info[0..offset], secret.*);
}

fn readInt(comptime T: type, source: *const [@divExact(@typeInfo(T).int.bits, 8)]u8) T {
    return std.mem.readInt(T, source, .big);
}

fn writeInt(comptime T: type, target: *[@divExact(@typeInfo(T).int.bits, 8)]u8, value: T) void {
    std.mem.writeInt(T, target, value, .big);
}

/// A cursor over a caller-owned buffer, with the length-prefix patching TLS
/// needs: every structure in a hello is preceded by its own length, and the
/// length is only known once the structure is written.
const Writer = struct {
    buffer: []u8,
    offset: usize = 0,

    const Pending = struct { at: usize, octets: u8 };

    fn byte(self: *Writer, value: u8) Error!void {
        if (self.offset + 1 > self.buffer.len) return error.TooLarge;
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    fn int(self: *Writer, comptime T: type, value: T) Error!void {
        const octets = @divExact(@typeInfo(T).int.bits, 8);
        if (self.offset + octets > self.buffer.len) return error.TooLarge;
        writeInt(T, self.buffer[self.offset..][0..octets], value);
        self.offset += octets;
    }

    fn bytes(self: *Writer, value: []const u8) Error!void {
        if (self.offset + value.len > self.buffer.len) return error.TooLarge;
        @memcpy(self.buffer[self.offset..][0..value.len], value);
        self.offset += value.len;
    }

    /// Reserve `octets` for a length, to be filled in by `endLength`.
    fn beginLength(self: *Writer, octets: u8) Error!Pending {
        std.debug.assert(octets == 1 or octets == 2 or octets == 3);
        if (self.offset + octets > self.buffer.len) return error.TooLarge;
        const at = self.offset;
        @memset(self.buffer[at..][0..octets], 0);
        self.offset += octets;
        return .{ .at = at, .octets = octets };
    }

    fn endLength(self: *Writer, pending: Pending) Error!void {
        const length = self.offset - pending.at - pending.octets;
        switch (pending.octets) {
            1 => {
                if (length > std.math.maxInt(u8)) return error.TooLarge;
                self.buffer[pending.at] = @intCast(length);
            },
            2 => {
                if (length > std.math.maxInt(u16)) return error.TooLarge;
                writeInt(u16, self.buffer[pending.at..][0..2], @intCast(length));
            },
            3 => {
                if (length > std.math.maxInt(u24)) return error.TooLarge;
                writeInt(u24, self.buffer[pending.at..][0..3], @intCast(length));
            },
            else => unreachable, // `beginLength` asserts the width.
        }
    }

    fn written(self: *const Writer) []const u8 {
        return self.buffer[0..self.offset];
    }
};

/// The reading half. Every accessor is bounds-checked against the buffer it was
/// given, because a hello is peer-supplied and this file is the first thing in
/// the tree to parse one.
const Reader = struct {
    buffer: []const u8,
    offset: usize = 0,

    fn done(self: *const Reader) bool {
        return self.offset >= self.buffer.len;
    }

    fn byte(self: *Reader) Error!u8 {
        if (self.offset + 1 > self.buffer.len) return error.Malformed;
        defer self.offset += 1;
        return self.buffer[self.offset];
    }

    fn int(self: *Reader, comptime T: type) Error!T {
        const octets = @divExact(@typeInfo(T).int.bits, 8);
        if (self.offset + octets > self.buffer.len) return error.Malformed;
        defer self.offset += octets;
        return readInt(T, self.buffer[self.offset..][0..octets]);
    }

    fn take(self: *Reader, count: usize) Error![]const u8 {
        if (self.offset + count > self.buffer.len) return error.Malformed;
        defer self.offset += count;
        return self.buffer[self.offset..][0..count];
    }

    fn lengthPrefixed(self: *Reader, octets: u8) Error![]const u8 {
        const length: usize = switch (octets) {
            1 => try self.byte(),
            2 => try self.int(u16),
            3 => try self.int(u24),
            else => unreachable, // Only these three widths appear in TLS.
        };
        return self.take(length);
    }

    /// `lengthPrefixed` on a temporary, for the one call site that reads a
    /// prefix off the front of a message body and keeps only the contents.
    fn lengthPrefixedOf(self: Reader, octets: u8) Error![]const u8 {
        var copy = self;
        return copy.lengthPrefixed(octets);
    }
};

const testing = std.testing;

const test_leaf_der = @embedFile("testdata/leaf.der");

fn testClient(verifier: ?ChainVerifier) Client {
    return .init(.{
        .server_name = "zrk.test",
        .alpn = "h3",
        .transport_parameters = &.{},
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
        .chain_verifier = verifier,
    });
}

/// A `Certificate` message body — the part after the four-octet handshake
/// header — carrying `leaf` as its only entry.
fn testCertificateBody(buffer: []u8, leaf: []const u8) []const u8 {
    var at: usize = 0;
    buffer[at] = 0; // empty certificate_request_context
    at += 1;
    writeInt(u24, buffer[at..][0..3], @intCast(3 + leaf.len + 2));
    at += 3;
    writeInt(u24, buffer[at..][0..3], @intCast(leaf.len));
    at += 3;
    @memcpy(buffer[at..][0..leaf.len], leaf);
    at += leaf.len;
    writeInt(u16, buffer[at..][0..2], 0); // no extensions
    at += 2;
    return buffer[0..at];
}

test "a Certificate message keeps the leaf's key and shows the chain to the verifier" {
    const Seen = struct {
        var octets: usize = 0;
        fn verify(_: *anyopaque, list: []const u8) bool {
            octets = list.len;
            return true;
        }
    };
    Seen.octets = 0;
    var anchor_value: u8 = 0;
    var client = testClient(.{ .context = &anchor_value, .verify = Seen.verify });

    var buffer: [4096]u8 = undefined;
    const body = testCertificateBody(&buffer, test_leaf_der);
    try client.certificate(body);

    // The key outlives the chain, which is the point of copying it.
    try testing.expect(client.leaf_key_len > 0);
    try testing.expectEqual(Certificate.AlgorithmCategory.X9_62_id_ecPublicKey, client.leaf_algo);
    // And the verifier saw the whole `certificate_list`, entry framing
    // included — which is the shape `Trust.verifyList` hands to zssl's reader.
    try testing.expectEqual(@as(usize, 3 + test_leaf_der.len + 2), Seen.octets);
}

test "a verifier that says no is a refused chain" {
    const Refuse = struct {
        fn verify(_: *anyopaque, _: []const u8) bool {
            return false;
        }
    };
    var anchor_value: u8 = 0;
    var client = testClient(.{ .context = &anchor_value, .verify = Refuse.verify });

    var buffer: [4096]u8 = undefined;
    const body = testCertificateBody(&buffer, test_leaf_der);
    try testing.expectError(error.BadCertificate, client.certificate(body));
}

test "a Certificate message whose lengths do not fit is refused, not read past" {
    var client = testClient(null);
    var buffer: [4096]u8 = undefined;
    const body = testCertificateBody(&buffer, test_leaf_der);

    // Nothing at all, and a context length with no room for the list after it.
    try testing.expectError(error.Malformed, client.certificate(&.{}));
    try testing.expectError(error.Malformed, client.certificate(body[0..2]));

    // A `certificate_list` length that runs past the message.
    var overlong: [4096]u8 = undefined;
    @memcpy(overlong[0..body.len], body);
    writeInt(u24, overlong[1..][0..3], @intCast(body.len + 64));
    try testing.expectError(error.Malformed, client.certificate(overlong[0..body.len]));

    // An entry length that runs past the list.
    @memcpy(overlong[0..body.len], body);
    writeInt(u24, overlong[4..][0..3], @intCast(test_leaf_der.len + 64));
    try testing.expectError(error.BadCertificate, client.certificate(overlong[0..body.len]));

    // An empty leaf, which section 4.4.2 does not permit and `parse` would
    // otherwise be asked to make sense of.
    var empty: [16]u8 = @splat(0);
    writeInt(u24, empty[1..][0..3], 5);
    writeInt(u24, empty[4..][0..3], 0);
    try testing.expectError(error.BadCertificate, client.certificate(empty[0..9]));
}

test "a CertificateVerify is refused unless it matches the key the leaf carried" {
    var anchor_value: u8 = 0;
    const Accept = struct {
        fn verify(_: *anyopaque, _: []const u8) bool {
            return true;
        }
    };
    var client = testClient(.{ .context = &anchor_value, .verify = Accept.verify });

    var buffer: [4096]u8 = undefined;
    try client.certificate(testCertificateBody(&buffer, test_leaf_der));
    // The fixture is a P-256 leaf, so ECDSA schemes are the ones that agree
    // with it.
    try testing.expectEqual(Certificate.AlgorithmCategory.X9_62_id_ecPublicKey, client.leaf_algo);

    var body: [128]u8 = @splat(0);

    // Too short to carry a scheme and a length at all.
    try testing.expectError(error.Malformed, client.certificateVerify(body[0..3]));

    // A signature length running past the message: refused rather than sliced.
    writeInt(u16, body[0..2], 0x0403);
    writeInt(u16, body[2..4], 64);
    try testing.expectError(error.Malformed, client.certificateVerify(body[0..8]));

    // An RSA scheme against an EC key. Without this check a peer could name
    // whichever verifier is happiest with the bytes it has.
    writeInt(u16, body[0..2], 0x0804);
    writeInt(u16, body[2..4], 8);
    try testing.expectError(error.BadSignature, client.certificateVerify(body[0..12]));

    // A scheme this client never offered.
    writeInt(u16, body[0..2], 0x0201); // rsa_pkcs1_sha1
    writeInt(u16, body[2..4], 8);
    try testing.expectError(error.Unsupported, client.certificateVerify(body[0..12]));

    // And a well-formed ECDSA signature that is simply not the right one.
    writeInt(u16, body[0..2], 0x0403);
    writeInt(u16, body[2..4], 8);
    try testing.expectError(error.BadSignature, client.certificateVerify(body[0..12]));
}

test "the ClientHello parses as one handshake message of the length it declares" {
    var buffer: [1024]u8 = undefined;
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &.{ 0x01, 0x02, 0x67, 0x10 },
        .offer = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256 },
        .random = @splat(0xa5),
        .key_seed = @splat(0x5a),
    });
    const hello = try client.clientHello(&buffer);

    try testing.expectEqual(@as(u8, @intFromEnum(MessageType.client_hello)), hello[0]);
    try testing.expectEqual(hello.len - 4, readInt(u24, hello[1..4]));
    try testing.expectEqual(@as(u16, 0x0303), readInt(u16, hello[4..6]));
    // The session ID is empty, which RFC 9001 section 8.4 requires over QUIC.
    try testing.expectEqual(@as(u8, 0), hello[38]);
}

test "the ClientHello carries the transport parameters it was given" {
    var buffer: [1024]u8 = undefined;
    const parameters = [_]u8{ 0x0f, 0x04, 0xde, 0xad, 0xbe, 0xef };
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &parameters,
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
    });
    const hello = try client.clientHello(&buffer);
    // Extension 57, its length, and then the body verbatim.
    const wanted = [_]u8{ 0x00, 0x39, 0x00, parameters.len } ++ parameters;
    try testing.expect(std.mem.indexOf(u8, hello, &wanted) != null);
}

test "a buffer too small for the ClientHello is refused rather than truncated" {
    var buffer: [16]u8 = undefined;
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &.{},
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
    });
    try testing.expectError(error.TooLarge, client.clientHello(&buffer));
}

test "a partial handshake message is left for the next call" {
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &.{},
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
    });
    // A ServerHello header claiming 64 octets, with two of them present.
    const partial = [_]u8{ 0x02, 0x00, 0x00, 0x40, 0x03, 0x03 };
    try testing.expectEqual(@as(usize, 0), try client.read(.initial, &partial));
    // And a header that is itself incomplete.
    try testing.expectEqual(@as(usize, 0), try client.read(.initial, partial[0..3]));
}

test "a HelloRetryRequest is refused by name rather than parsed as a ServerHello" {
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &.{},
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
    });
    var message: [4 + 2 + 32 + 1]u8 = @splat(0);
    message[0] = @intFromEnum(MessageType.server_hello);
    writeInt(u24, message[1..4], message.len - 4);
    writeInt(u16, message[4..6], 0x0303);
    @memcpy(message[6..38], &hello_retry_request_random);
    try testing.expectError(error.Unsupported, client.read(.initial, &message));
}

test "a message arriving at the wrong encryption level is refused" {
    var client: Client = .init(.{
        .server_name = "server4",
        .alpn = "hq-interop",
        .transport_parameters = &.{},
        .offer = &.{.aes_128_gcm_sha256},
        .random = @splat(0),
        .key_seed = @splat(1),
    });
    // EncryptedExtensions belongs at Handshake; RFC 8446 puts nothing but the
    // ServerHello at Initial.
    const message = [_]u8{ 0x08, 0x00, 0x00, 0x02, 0x00, 0x00 };
    try testing.expectError(error.Unsupported, client.read(.initial, &message));
}

test "expandLabel reproduces RFC 8448's derived secret" {
    // RFC 8448 section 3, the "derived" secret of the early stage: the input
    // is the early secret of a zero PSK and the context is the hash of the
    // empty string. Both are constants of TLS 1.3 rather than of a session,
    // which is what makes them a usable vector for a handshake with no peer.
    const zero: [secret_octets]u8 = @splat(0);
    const early = Hkdf.extract(&.{}, &zero);
    const early_expected = [_]u8{
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98,
        0x93, 0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
    };
    try testing.expectEqualSlices(u8, &early_expected, &early);

    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash("", &digest, .{});
    var derived: [secret_octets]u8 = undefined;
    expandLabel(&derived, &early, "derived", &digest);
    const derived_expected = [_]u8{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc,
        0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
        0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
    };
    try testing.expectEqualSlices(u8, &derived_expected, &derived);
}

/// One ECDSA signature, over the parts in order.
fn verifyEcdsa(
    comptime Scheme: type,
    key: []const u8,
    signature: []const u8,
    parts: []const []const u8,
) Error!void {
    const parsed = Scheme.Signature.fromDer(signature) catch return error.BadSignature;
    const public = Scheme.PublicKey.fromSec1(key) catch return error.BadSignature;
    var verifier = parsed.verifier(public) catch return error.BadSignature;
    // Bounded by `parts`, which is two.
    for (parts) |part| verifier.update(part);
    verifier.verify() catch return error.BadSignature;
}

/// One RSA-PSS signature, over the parts in order.
///
/// The modulus length is switched over rather than passed, because
/// `Certificate.rsa` is generic in it: the four cases are 1024 through 4096
/// bits, and a key outside them is refused rather than verified by some other
/// size's arithmetic.
fn verifyRsaPss(
    comptime H: type,
    key: []const u8,
    signature: []const u8,
    parts: []const []const u8,
) Error!void {
    const rsa = Certificate.rsa;
    const components = rsa.PublicKey.parseDer(key) catch return error.BadSignature;
    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_octets| {
            const public: rsa.PublicKey = rsa.PublicKey.fromBytes(
                components.exponent,
                components.modulus,
            ) catch return error.BadSignature;
            const parsed = rsa.PSSSignature.fromBytes(modulus_octets, signature);
            rsa.PSSSignature.concatVerify(modulus_octets, parsed, parts, public, H) catch
                return error.BadSignature;
        },
        else => return error.BadSignature,
    }
}

/// `Derive-Secret(secret, label, Messages)` over a transcript, shared by both
/// roles. A free function rather than a method, because `Client` and `Server`
/// hold the same schedule and only differ in which secret goes which way.
fn deriveSecret(
    transcript: *const Hash,
    out: *[secret_octets]u8,
    secret: *const [secret_octets]u8,
    label: []const u8,
) void {
    var digest: [Hash.digest_length]u8 = undefined;
    var copy = transcript.*;
    copy.final(&digest);
    expandLabel(out, secret, label, &digest);
}

fn deriveSecretEmpty(out: *[secret_octets]u8, secret: *const [secret_octets]u8, label: []const u8) void {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash("", &digest, .{});
    expandLabel(out, secret, label, &digest);
}

/// RFC 8446 section 4.4.4's `verify_data`, over a transcript.
fn finishedData(
    transcript: *const Hash,
    traffic: *const [secret_octets]u8,
    out: *[Hmac.mac_length]u8,
) void {
    var key: [secret_octets]u8 = undefined;
    expandLabel(&key, traffic, "finished", "");
    var digest: [Hash.digest_length]u8 = undefined;
    var copy = transcript.*;
    copy.final(&digest);
    Hmac.create(out, &digest, &key);
}
