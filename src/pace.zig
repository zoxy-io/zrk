//! Send scheduling: maps a per-connection request index `k` to the intended
//! (coordinated-omission-correct) send time, as a nanosecond offset from the
//! connection's anchor. Send times are *predetermined* — a function of `k`
//! and a fixed per-connection `phase`, never of server responses — which is
//! what preserves zrk's coordinated omission correction under both constant
//! and ramping load.
//!
//! Two shapes:
//!   - constant: send k at `k * interval` (total rate split evenly across conns).
//!   - linear:   per-connection rate ramps as r(t) = r0 + slope·t; send k is the
//!               t solving the cumulative integral r0·t + ½·slope·t² = k, i.e.
//!               t = (−r0 + √(r0² + 2·slope·k)) / slope. The constant case is the
//!               slope→0 limit; this closed form avoids drift across the run.
//!
//! `phase` staggers a fleet: all connections launch together and share the
//! anchor instant, so with identical schedules every send of the fleet fires
//! simultaneously — N-request lockstep waves that quantize per-interval
//! throughput to multiples of N. Connection i of n instead solves the schedule
//! at k + i/n, interleaving the fleet's sends uniformly across each per-conn
//! gap while keeping each connection's average rate (and CO correction) intact.

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
    /// (k = 0, 1, 2, …), shifted by `phase` ∈ [0, 1) of the schedule's gap:
    /// the send time solves the cumulative schedule at k + phase. With
    /// phase = 0 the k = 0 send is the anchor itself; a fleet staggered by
    /// phase = i/n spreads its sends uniformly instead of firing in lockstep.
    pub fn offsetNs(self: Schedule, k: u64, phase: f64) u64 {
        const kf = @as(f64, @floatFromInt(k)) + phase;
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
    try testing.expectEqual(@as(u64, 0), s.offsetNs(0, 0));
    try testing.expectEqual(@as(u64, 10 * std.time.ns_per_ms), s.offsetNs(1, 0));
    try testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), s.offsetNs(10, 0));
    try testing.expectApproxEqAbs(@as(f64, 100), s.rateAt(0), 1e-9);
}

test "linear schedule with zero slope matches constant" {
    const lin = Schedule.linearTotal(1000, 1000, 10, 30);
    const con = Schedule.constantTotal(1000, 10);
    var k: u64 = 0;
    while (k <= 100) : (k += 10) {
        // Within a nanosecond of each other (float path differences aside).
        const a = lin.offsetNs(k, 0);
        const b = con.offsetNs(k, 0);
        const diff = if (a > b) a - b else b - a;
        try testing.expect(diff <= 1);
    }
}

test "phase shifts a constant schedule by a fraction of the gap" {
    // 100 req/s per conn => 10ms gap; phase 0.5 => every send lands 5ms late.
    const s = Schedule.constantTotal(1000, 10);
    try testing.expectEqual(@as(u64, 5 * std.time.ns_per_ms), s.offsetNs(0, 0.5));
    try testing.expectEqual(@as(u64, 15 * std.time.ns_per_ms), s.offsetNs(1, 0.5));
}

test "staggered fleet interleaves sends uniformly" {
    // 4 connections, 10ms per-conn gap: fleet sends must land every 2.5ms
    // instead of 4-at-once on the 10ms grid.
    const s = Schedule.constantTotal(400, 4);
    const n: u64 = 4;
    var expected: u64 = 0;
    var k: u64 = 0;
    while (k < 3) : (k += 1) {
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const phase = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(n));
            const off = s.offsetNs(k, phase);
            try testing.expectApproxEqAbs(
                @as(f64, @floatFromInt(expected)),
                @as(f64, @floatFromInt(off)),
                1.0,
            );
            expected += 2_500_000; // 10ms / 4 connections
        }
    }
}

test "phased linear sends satisfy the cumulative integral at k + phase" {
    // Per-conn r0=100, slope=100 (as below); N(t) = 100t + 50t² must equal
    // k + phase at the scheduled instant.
    const s = Schedule.linearTotal(100, 1100, 1, 10);
    for ([_]u64{ 0, 1, 50, 500 }) |k| {
        for ([_]f64{ 0.25, 0.75 }) |phase| {
            const t_s = @as(f64, @floatFromInt(s.offsetNs(k, phase))) / ns_per_s;
            const n = 100.0 * t_s + 50.0 * t_s * t_s;
            try testing.expectApproxEqAbs(@as(f64, @floatFromInt(k)) + phase, n, 0.5);
        }
    }
}

test "linear ramp send times satisfy the cumulative integral" {
    // Ramp total 100 -> 1100 req/s over 10s across 1 connection.
    // Per-conn r0=100, slope=100. Cumulative N(t)=100t+50t^2; check a few k.
    const s = Schedule.linearTotal(100, 1100, 1, 10);
    try testing.expectEqual(@as(u64, 0), s.offsetNs(0, 0));

    // For each k, the recovered t must reproduce k via the integral.
    for ([_]u64{ 1, 50, 100, 500, 1000 }) |k| {
        const t_s = @as(f64, @floatFromInt(s.offsetNs(k, 0))) / @as(f64, @floatFromInt(std.time.ns_per_s));
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
        const off = s.offsetNs(k, 0);
        try testing.expect(off > prev);
        prev = off;
    }
}
