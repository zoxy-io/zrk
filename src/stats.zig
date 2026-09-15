//! Ownership and aggregation of per-connection statistics.
//!
//! Each connection writes only to its own live histogram/counters (no locking
//! on the hot path). Once per dashboard interval a connection publishes a copy
//! into a mutex-guarded snapshot slot; the dashboard reads those snapshots. The
//! final report aggregates the live histograms directly after all connections
//! have stopped, so no locking is needed there.
//!
//! Reading those snapshots costs O(connections), so `Sweeper` runs it on a
//! dedicated thread rather than on an executor — see its doc comment.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const h3conn = @import("h3conn.zig");
const tlsmod = @import("tls.zig");

/// Latency histogram configuration: 1µs .. 60s at 3 significant figures.
///
/// The ceiling is a memory decision, not a resolution one: `counts_len` grows
/// by `sub_bucket_half_count` (1024 u64 = 8KiB) per power-of-two of range, and
/// every connection owns two of these histograms (live + snapshot slot). A 1h
/// ceiling cost 184KiB each — 3.8GB of resident memory at `-c10000`. 60s brings
/// that to 136KiB, and the buckets above it only ever held latencies that no
/// longer describe a system anyone is still measuring.
///
/// Values above the ceiling are clamped into the top bucket, never dropped
/// (see `hdr.recordCount`), so a run that blows past 60s still reports every
/// request — the tail just saturates at "60s or worse" instead of resolving how
/// much worse. `--timeout` (2s by default) bounds wire time; only the
/// coordinated-omission correction can reach this far, and only when the client
/// or server has already fallen catastrophically behind.
pub const hist_lowest: u64 = 1;
pub const hist_highest: u64 = 60_000_000;
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
    /// Per-connection QUIC/HTTP-3 transport state, allocated only for
    /// `--http3`. Megabytes apiece rather than kilobytes — see
    /// `h3conn.footprint_octets` — which is exactly why it is allocated here,
    /// once for the run, and not on a coroutine's frame per reconnect.
    h3_state: ?[]h3conn.State,

    pub fn init(
        allocator: Allocator,
        n: u32,
        publish_interval_ns: u64,
        enable_tls: bool,
        enable_h3: bool,
    ) !Fleet {
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
        // The block arrives undefined and `State` reads its own fields to
        // decide whether a previous session needs tearing down, so nothing may
        // touch one before this runs.
        if (tls_state) |ts| for (ts) |*state| state.init();
        const h3_state: ?[]h3conn.State = if (enable_h3) try allocator.alloc(h3conn.State, n) else null;
        errdefer if (h3_state) |hs| allocator.free(hs);
        // Same contract as `tls_state` above: the block arrives undefined and
        // nothing may read a field before this runs.
        if (h3_state) |hs| for (hs) |*state| state.init();

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
            .h3_state = h3_state,
        };
    }

    /// Fill in the per-connection `Params`. All connections share the same
    /// target address/request/schedule; `interval_ns` is the per-connection
    /// send spacing (total-rate / connections). Each connection gets a stagger
    /// phase of i/n so the fleet's sends interleave uniformly instead of
    /// firing in lockstep waves (see pace.Schedule.offsetNs).
    pub fn buildParams(
        self: *Fleet,
        template: connection.Params,
    ) []connection.Params {
        const n: f64 = @floatFromInt(self.params.len);
        for (self.params, 0..) |*p, i| {
            p.* = template;
            p.histogram = &self.live_hist[i];
            p.counters = &self.live_counters[i];
            p.publish = &self.publish[i];
            p.phase = @as(f64, @floatFromInt(i)) / n;
            if (self.tls_state) |ts| p.tls_state = &ts[i];
            if (self.h3_state) |hs| p.h3_state = &hs[i];
        }
        return self.params;
    }

    /// Aggregate the most recently published snapshot from every connection.
    /// Safe to call concurrently with running connections.
    ///
    /// O(connections) in full histograms merged, so this is the pass `Sweeper`
    /// exists to keep off the executor threads; call it directly only when
    /// nothing is racing for the CPU.
    pub fn readSnapshot(self: *Fleet, io: Io, dst: *Snapshot) void {
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
        // Each session holds libcrypto objects; freeing the block without
        // this leaks one set per connection that ever handshook.
        if (self.tls_state) |ts| {
            for (ts) |*state| state.deinit();
            self.allocator.free(ts);
        }
        // Nothing to tear down per state: `h3conn.State` owns no handle and no
        // allocation — the transport's whole memory is the block itself.
        if (self.h3_state) |hs| self.allocator.free(hs);
    }
};

/// Runs `Fleet.readSnapshot` on a dedicated OS thread.
///
/// The merge adds one full histogram per connection, so its cost scales with
/// `-c`: at `-c10000` a single pass is ~10^8 u64 adds, on the order of 100ms.
/// Running that inline stalled the calling thread — which is also zio's
/// executor 0, servicing 1/threads of the connections — for that whole time,
/// once per publish interval. Those connections then missed their paced sends,
/// and because latency is measured from the *scheduled* send, the stall was
/// charged to the server under test. Bumping `--threads` only shrank the share
/// of connections caught behind it; moving the work off the executor removes it.
///
/// The handshake is a plain condvar, but which side it parks differs by caller:
/// `Io.Mutex`/`Io.Condition` are futex-backed and dispatch through the `Io`
/// vtable, and zio parks a task on its scheduler while parking a foreign thread
/// on an OS futex (see zio's `Waiter.wait`). So the same two primitives block
/// this thread outright, while `snapshot` suspends only the calling *coroutine*
/// — its executor keeps running connections for the length of the merge.
///
/// `snapshot` waits for a merge that started after it asked, so the result is
/// exactly as fresh as the inline call it replaces; per-interval timeseries
/// rows keep lining up with the wall-clock window they claim to cover. A single
/// caller is assumed (the runner's progress loop).
pub const Sweeper = struct {
    fleet: *Fleet,
    io: Io,

    mutex: Io.Mutex = .init,
    /// Carries both directions: a request to the thread, a result to the caller.
    cond: Io.Condition = .init,
    /// A merge has been asked for and has not been picked up yet.
    requested: bool = false,
    /// Bumped every time a merged result lands in `result`.
    completed: u64 = 0,
    quit: bool = false,

    /// Merge target. Private to the thread while a pass runs, which is what
    /// keeps the time spent holding `mutex` down to one buffer swap.
    scratch: Snapshot,
    /// Most recent completed merge; guarded by `mutex`.
    result: Snapshot,

    /// Null when the thread could not be spawned; `snapshot` then falls back to
    /// merging inline, which is slow but correct.
    thread: ?std.Thread = null,

    pub fn init(allocator: Allocator, fleet: *Fleet, io: Io) !Sweeper {
        var scratch: Snapshot = .{ .hist = try newHistogram(allocator), .counters = .{} };
        errdefer scratch.deinit();
        const result: Snapshot = .{ .hist = try newHistogram(allocator), .counters = .{} };
        return .{ .fleet = fleet, .io = io, .scratch = scratch, .result = result };
    }

    /// Spawn the sweeper thread. Must be called on a pinned `Sweeper` (the
    /// thread keeps the pointer). Spawn failure is not fatal: `snapshot` then
    /// merges inline on the caller's thread.
    pub fn start(self: *Sweeper) void {
        self.thread = std.Thread.spawn(.{}, run, .{self}) catch null;
    }

    fn run(self: *Sweeper) void {
        const io = self.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (true) {
            while (!self.requested and !self.quit) self.cond.waitUncancelable(io, &self.mutex);
            if (self.quit) return;
            self.requested = false;

            // Merge unlocked: holding `mutex` across the expensive pass would
            // just relocate the stall onto whoever calls `snapshot` next.
            self.mutex.unlock(io);
            self.fleet.readSnapshot(io, &self.scratch);
            self.mutex.lockUncancelable(io);

            std.mem.swap(Snapshot, &self.scratch, &self.result);
            self.completed += 1;
            self.cond.broadcast(io);
        }
    }

    /// Request a fresh merge and block until it lands, then copy it into `dst`.
    /// Suspends the calling coroutine rather than its executor thread.
    pub fn snapshot(self: *Sweeper, dst: *Snapshot) void {
        const io = self.io;
        if (self.thread == null) return self.fleet.readSnapshot(io, dst);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        // Wait for a merge that completes *after* this call: a pass already in
        // flight may have read half the fleet before we asked.
        const target = self.completed + 1;
        self.requested = true;
        self.cond.broadcast(io);
        while (self.completed < target and !self.quit) self.cond.waitUncancelable(io, &self.mutex);

        self.result.hist.copyInto(&dst.hist);
        dst.counters = self.result.counters;
    }

    /// Stop and join the thread, then release the merge buffers. Must run
    /// before the `Fleet` it borrows is torn down.
    pub fn deinit(self: *Sweeper) void {
        if (self.thread) |thread| {
            self.mutex.lockUncancelable(self.io);
            self.quit = true;
            self.cond.broadcast(self.io);
            self.mutex.unlock(self.io);
            thread.join();
            self.thread = null;
        }
        self.scratch.deinit();
        self.result.deinit();
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;
const zio = @import("zio");

test "the default histogram's footprint stays within budget" {
    var h = try newHistogram(testing.allocator);
    defer h.deinit();
    // Every connection owns two of these (live + snapshot slot), so counts_len
    // is a memory budget rather than an implementation detail: each additional
    // power-of-two of range adds 1024 u64 = 8KiB here, which is another 160MiB
    // resident at `-c10000`. Raising `hist_highest` should be a deliberate
    // trade, so pin the geometry.
    try testing.expectEqual(@as(u32, 17 * 1024), h.counts_len);
    try testing.expectEqual(@as(usize, 136 * 1024), h.counts.len * @sizeOf(u64));

    // The ceiling clamps rather than drops: a 10-minute outlier still counts.
    h.record(600 * std.time.us_per_s);
    try testing.expectEqual(@as(u64, 1), h.count());
    try testing.expectEqual(hist_highest, h.max_value);
}

test "fleet aggregates live counters and histograms" {
    var fleet = try Fleet.init(testing.allocator, 3, std.time.ns_per_s, false, false);
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
            var fleet = try Fleet.init(allocator, 3, std.time.ns_per_s, true, false);
            fleet.deinit();
        }
    }.initAndDeinit, .{});
}

test "readSnapshot reflects published state" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var fleet = try Fleet.init(testing.allocator, 2, std.time.ns_per_s, false, false);
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

test "Sweeper returns the same aggregate as an inline readSnapshot" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var fleet = try Fleet.init(testing.allocator, 8, std.time.ns_per_s, false, false);
    defer fleet.deinit();
    for (fleet.publish, 0..) |*p, i| {
        p.hist.record(1000 * (@as(u64, @intCast(i)) + 1));
        p.counters.completed = 7;
        p.counters.bytes = 100;
    }

    var inline_snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer inline_snap.deinit();
    fleet.readSnapshot(io, &inline_snap);

    var sweeper = try Sweeper.init(testing.allocator, &fleet, io);
    defer sweeper.deinit();
    sweeper.start();
    try testing.expect(sweeper.thread != null); // else the fallback path is under test, not the thread

    var swept: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer swept.deinit();
    sweeper.snapshot(&swept);

    try testing.expectEqual(inline_snap.counters.completed, swept.counters.completed);
    try testing.expectEqual(inline_snap.counters.bytes, swept.counters.bytes);
    try testing.expectEqual(inline_snap.hist.count(), swept.hist.count());
    try testing.expectEqual(inline_snap.hist.max_value, swept.hist.max_value);
    try testing.expectEqual(inline_snap.hist.min_value, swept.hist.min_value);
}

test "each Sweeper.snapshot waits for a merge newer than the request" {
    // Freshness is the property that keeps --timeseries rows aligned with the
    // wall-clock window they claim to cover: returning the previous pass's
    // result would credit this interval's counter delta to the wrong duration.
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var fleet = try Fleet.init(testing.allocator, 4, std.time.ns_per_s, false, false);
    defer fleet.deinit();

    var sweeper = try Sweeper.init(testing.allocator, &fleet, io);
    defer sweeper.deinit();
    sweeper.start();

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();

    // Every round publishes one more request per connection; the very next
    // snapshot must already see it, with no intervening sleep.
    for (1..6) |round| {
        for (fleet.publish) |*p| {
            p.mutex.lockUncancelable(io);
            defer p.mutex.unlock(io);
            p.hist.record(1000);
            p.counters.completed = round;
        }
        sweeper.snapshot(&snap);
        try testing.expectEqual(@as(u64, round * 4), snap.counters.completed);
        try testing.expectEqual(@as(u64, round * 4), snap.hist.count());
    }
}

test "Sweeper stops cleanly when no snapshot was ever taken" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();

    var fleet = try Fleet.init(testing.allocator, 2, std.time.ns_per_s, false, false);
    defer fleet.deinit();

    var sweeper = try Sweeper.init(testing.allocator, &fleet, rt.io());
    sweeper.start();
    sweeper.deinit(); // must join the idle thread rather than hang
}
