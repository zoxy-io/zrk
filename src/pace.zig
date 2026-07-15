//! Send scheduling: maps a per-connection request index `k` to the intended
//! (coordinated-omission-correct) send time, as a nanosecond offset from the
//! connection's anchor. Send times are *predetermined* — a function of `k`
//! alone, never of server responses — which is what preserves zrk's coordinated
//! omission correction under both constant and ramping load.
//!
//! Two shapes:
//!   - constant: send k at `k * interval` (total rate split evenly across conns).
//!   - linear:   per-connection rate ramps as r(t) = r0 + slope·t; send k is the
//!               t solving the cumulative integral r0·t + ½·slope·t² = k, i.e.
//!               t = (−r0 + √(r0² + 2·slope·k)) / slope. The constant case is the
//!               slope→0 limit; this closed form avoids drift across the run.

const std = @import("std");

const ns_per_s: f64 = @floatFromInt(std.time.ns_per_s);

/// A send schedule, expressed in per-connection terms.
pub const Schedule = union(enum) {
    /// Nanoseconds between successive sends on this connection.
    constant: struct { interval_ns: f64 },
    /// Per-connection ramp: `r0` req/s at t=0, changing by `slope` req/s per
    /// second. `slope` may be negative (ramp down).
    linear: struct { r0: f64, slope: f64 },

    /// Constant total `rate` (req/s) split evenly across `connections`.
    pub fn constantTotal(rate: u64, connections: u32) Schedule {
        const interval = ns_per_s * @as(f64, @floatFromInt(connections)) / @as(f64, @floatFromInt(rate));
        return .{ .constant = .{ .interval_ns = interval } };
    }

    /// Total rate ramping linearly from `start` to `end` req/s over
    /// `duration_s` seconds, split evenly across `connections`.
    pub fn linearTotal(start: u64, end: u64, connections: u32, duration_s: f64) Schedule {
        const c: f64 = @floatFromInt(connections);
        const r0 = @as(f64, @floatFromInt(start)) / c;
        const r1 = @as(f64, @floatFromInt(end)) / c;
        const slope = if (duration_s > 0) (r1 - r0) / duration_s else 0;
        return .{ .linear = .{ .r0 = r0, .slope = slope } };
    }

    /// Nanosecond offset from the anchor for this connection's `k`-th send
    /// (k = 0, 1, 2, …). `k = 0` is always offset 0 (the anchor itself).
    pub fn offsetNs(self: Schedule, k: u64) u64 {
        const kf: f64 = @floatFromInt(k);
        switch (self) {
            .constant => |c| return @intFromFloat(kf * c.interval_ns),
            .linear => |l| {
                if (l.slope == 0) return @intFromFloat((kf / l.r0) * ns_per_s);
                const disc = l.r0 * l.r0 + 2.0 * l.slope * kf;
                // Past the schedulable horizon (only reachable for a ramp toward
                // ≤ 0 req/s, which the CLI rejects): park this send far in the
                // future so the connection idles until end-of-test.
                if (disc < 0) return std.math.maxInt(u64) >> 2;
                const t = (-l.r0 + @sqrt(disc)) / l.slope;
                return @intFromFloat(t * ns_per_s);
            },
        }
    }

    /// Instantaneous per-connection target rate (req/s) at elapsed `t_s` seconds
    /// — used to annotate the offered load in the time-series report.
    pub fn rateAt(self: Schedule, t_s: f64) f64 {
        return switch (self) {
            .constant => |c| if (c.interval_ns > 0) ns_per_s / c.interval_ns else 0,
            .linear => |l| l.r0 + l.slope * t_s,
        };
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "constant schedule spaces sends evenly" {
    // 1000 req/s over 10 connections => 100 req/s per conn => 10ms interval.
    const s = Schedule.constantTotal(1000, 10);
    try testing.expectEqual(@as(u64, 0), s.offsetNs(0));
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_ms), s.offsetNs(1));
    try testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), s.offsetNs(10));
    try testing.expectApproxEqAbs(@as(f64, 100), s.rateAt(0), 1e-9);
}

test "linear schedule with zero slope matches constant" {
    const lin = Schedule.linearTotal(1000, 1000, 10, 30);
    const con = Schedule.constantTotal(1000, 10);
    var k: u64 = 0;
    while (k <= 100) : (k += 10) {
        // Within a nanosecond of each other (float path differences aside).
        const a = lin.offsetNs(k);
        const b = con.offsetNs(k);
        const diff = if (a > b) a - b else b - a;
        try testing.expect(diff <= 1);
    }
}

test "linear ramp send times satisfy the cumulative integral" {
    // Ramp total 100 -> 1100 req/s over 10s across 1 connection.
    // Per-conn r0=100, slope=100. Cumulative N(t)=100t+50t^2; check a few k.
    const s = Schedule.linearTotal(100, 1100, 1, 10);
    try testing.expectEqual(@as(u64, 0), s.offsetNs(0));

    // For each k, the recovered t must reproduce k via the integral.
    for ([_]u64{ 1, 50, 100, 500, 1000 }) |k| {
        const t_s = @as(f64, @floatFromInt(s.offsetNs(k))) / @as(f64, @floatFromInt(std.time.ns_per_s));
        const n = 100.0 * t_s + 50.0 * t_s * t_s;
        try testing.expectApproxEqAbs(@as(f64, @floatFromInt(k)), n, 0.5);
    }

    // Offered rate climbs over time.
    try testing.expectApproxEqAbs(@as(f64, 100), s.rateAt(0), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 1100), s.rateAt(10), 1e-6);
}

test "linear ramp offsets are strictly increasing" {
    const s = Schedule.linearTotal(100, 5000, 8, 20);
    var prev: u64 = 0;
    var k: u64 = 1;
    while (k < 2000) : (k += 1) {
        const off = s.offsetNs(k);
        try testing.expect(off > prev);
        prev = off;
    }
}
