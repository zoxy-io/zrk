//! zrk — a constant-throughput HTTP load generator (a Zig rewrite of wrk2).
//!
//! This root module re-exports the pure, independently testable pieces so they
//! can be unit-tested via `zig build test` and embedded by other programs.

const std = @import("std");

pub const hdr = @import("hdr.zig");
pub const Histogram = hdr.Histogram;

pub const cli = @import("cli.zig");
pub const http = @import("http.zig");
pub const pace = @import("pace.zig");
pub const connection = @import("connection.zig");
pub const runner = @import("runner.zig");
pub const stats = @import("stats.zig");
pub const report = @import("report.zig");
pub const tui = @import("tui.zig");
pub const tls = @import("tls.zig");
pub const h2conn = @import("h2conn.zig");
pub const workload = @import("workload.zig");
pub const Workload = workload.Workload;
pub const lua = @import("lua.zig");
pub const script = @import("script.zig");

test {
    std.testing.refAllDecls(@This());
}
