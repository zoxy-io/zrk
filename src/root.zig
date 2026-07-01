//! zrk — a constant-throughput HTTP load generator (a Zig rewrite of wrk2).
//!
//! This root module re-exports the pure, independently testable pieces so they
//! can be unit-tested via `zig build test` and embedded by other programs.

const std = @import("std");

pub const hdr = @import("hdr.zig");
pub const Histogram = hdr.Histogram;

pub const cli = @import("cli.zig");
pub const http = @import("http.zig");
pub const connection = @import("connection.zig");
pub const stats = @import("stats.zig");
pub const tui = @import("tui.zig");
pub const tls = @import("tls.zig");

test {
    std.testing.refAllDecls(@This());
}
