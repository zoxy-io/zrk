//! Ownership and aggregation of per-connection statistics.
//!
//! Each connection writes only to its own live histogram/counters (no locking
//! on the hot path). Once per dashboard interval a connection publishes a copy
//! into a mutex-guarded snapshot slot; the dashboard reads those snapshots. The
//! final report aggregates the live histograms directly after all connections
//! have stopped, so no locking is needed there.

const std = @import("std");
const Allocator = std.mem.Allocator;

const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const tlsmod = @import("tls.zig");

/// Latency histogram configuration: 1µs .. 1h at 3 significant figures.
pub const hist_lowest: u64 = 1;
pub const hist_highest: u64 = 3_600_000_000;
pub const hist_sig_figs: u8 = 3;

pub fn newHistogram(allocator: Allocator) !hdr.Histogram {
    return hdr.Histogram.init(allocator, hist_lowest, hist_highest, hist_sig_figs);
}

/// A point-in-time aggregate across all connections.
pub const Snapshot = struct {
    hist: hdr.Histogram,
    counters: connection.Counters,

    pub fn deinit(self: *Snapshot) void {
        self.hist.deinit();
    }
};

/// Owns all per-connection state and hands out `connection.Params`.
pub const Fleet = struct {
    allocator: Allocator,
    n: u32,
    live_hist: []hdr.Histogram,
    live_counters: []connection.Counters,
    snap_hist: []hdr.Histogram,
    publish: []connection.Publish,
    params: []connection.Params,
    /// Per-connection TLS state, allocated only for HTTPS targets.
    tls_state: ?[]tlsmod.State,

    pub fn init(allocator: Allocator, n: u32, publish_interval_ns: u64, enable_tls: bool) !Fleet {
        const live_hist = try allocator.alloc(hdr.Histogram, n);
        errdefer allocator.free(live_hist);
        const live_counters = try allocator.alloc(connection.Counters, n);
        errdefer allocator.free(live_counters);
        const snap_hist = try allocator.alloc(hdr.Histogram, n);
        errdefer allocator.free(snap_hist);
        const publish = try allocator.alloc(connection.Publish, n);
        errdefer allocator.free(publish);
        const params = try allocator.alloc(connection.Params, n);
        errdefer allocator.free(params);
        const tls_state: ?[]tlsmod.State = if (enable_tls) try allocator.alloc(tlsmod.State, n) else null;
        errdefer if (tls_state) |ts| allocator.free(ts);

        var live_inited: usize = 0;
        errdefer for (live_hist[0..live_inited]) |*h| h.deinit();
        for (live_hist) |*h| {
            h.* = try newHistogram(allocator);
            live_inited += 1;
        }
        var snap_inited: usize = 0;
        errdefer for (snap_hist[0..snap_inited]) |*h| h.deinit();
        for (snap_hist) |*h| {
            h.* = try newHistogram(allocator);
            snap_inited += 1;
        }
        @memset(live_counters, .{});
        for (publish, snap_hist) |*p, *sh| {
            p.* = .{ .hist = sh, .interval_ns = publish_interval_ns };
        }

        return .{
            .allocator = allocator,
            .n = n,
            .live_hist = live_hist,
            .live_counters = live_counters,
            .snap_hist = snap_hist,
            .publish = publish,
            .params = params,
            .tls_state = tls_state,
        };
    }

    /// Fill in the per-connection `Params`. All connections share the same
    /// target address/request/schedule; `interval_ns` is the per-connection
    /// send spacing (total-rate / connections).
    pub fn buildParams(
        self: *Fleet,
        template: connection.Params,
    ) []connection.Params {
        for (self.params, 0..) |*p, i| {
            p.* = template;
            p.histogram = &self.live_hist[i];
            p.counters = &self.live_counters[i];
            p.publish = &self.publish[i];
            if (self.tls_state) |ts| p.tls_state = &ts[i];
        }
        return self.params;
    }

    /// Aggregate the most recently published snapshot from every connection.
    /// Safe to call concurrently with running connections.
    pub fn readSnapshot(self: *Fleet, io: std.Io, dst: *Snapshot) void {
        dst.hist.reset();
        dst.counters = .{};
        for (self.publish) |*p| {
            p.mutex.lockUncancelable(io);
            defer p.mutex.unlock(io);
            dst.hist.add(p.hist);
            dst.counters.add(p.counters);
        }
    }

    /// Aggregate the live histograms/counters. Only call once all connections
    /// have stopped (no synchronization is performed).
    pub fn readFinal(self: *Fleet, dst: *Snapshot) void {
        dst.hist.reset();
        dst.counters = .{};
        for (self.live_hist) |*h| dst.hist.add(h);
        for (self.live_counters) |c| dst.counters.add(c);
    }

    pub fn deinit(self: *Fleet) void {
        for (self.live_hist) |*h| h.deinit();
        for (self.snap_hist) |*h| h.deinit();
        self.allocator.free(self.live_hist);
        self.allocator.free(self.live_counters);
        self.allocator.free(self.snap_hist);
        self.allocator.free(self.publish);
        self.allocator.free(self.params);
        if (self.tls_state) |ts| self.allocator.free(ts);
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "fleet aggregates live counters and histograms" {
    var fleet = try Fleet.init(testing.allocator, 3, std.time.ns_per_s, false);
    defer fleet.deinit();

    // Simulate each connection having done some work.
    for (fleet.live_hist, fleet.live_counters, 0..) |*h, *c, i| {
        h.record(1000 * (@as(u64, @intCast(i)) + 1));
        c.completed = 10;
        c.bytes = 100;
    }

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    fleet.readFinal(&snap);

    try testing.expectEqual(@as(u64, 30), snap.counters.completed);
    try testing.expectEqual(@as(u64, 300), snap.counters.bytes);
    try testing.expectEqual(@as(u64, 3), snap.hist.count());
}

test "Fleet.init leaks nothing when any allocation fails" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn initAndDeinit(allocator: Allocator) !void {
            var fleet = try Fleet.init(allocator, 3, std.time.ns_per_s, true);
            fleet.deinit();
        }
    }.initAndDeinit, .{});
}

test "readSnapshot reflects published state" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fleet = try Fleet.init(testing.allocator, 2, std.time.ns_per_s, false);
    defer fleet.deinit();

    // Publish some values into each connection's snapshot slot directly.
    for (fleet.publish) |*p| {
        p.hist.record(5000);
        p.counters.completed = 7;
    }

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    fleet.readSnapshot(io, &snap);

    try testing.expectEqual(@as(u64, 14), snap.counters.completed);
    try testing.expectEqual(@as(u64, 2), snap.hist.count());
}
