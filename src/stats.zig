//! Ownership and aggregation of sharded statistics.
//!
//! Connections share one histogram and counter set per shard, guarded by a
//! short spin lock because zio can move a coroutine between executor threads.
//! Responses update their latency and counters under the same lock, so a live
//! snapshot sees matching samples and completions. Histogram storage and merge
//! work scale with threads rather than connections.
//!
//! `Sweeper` reads the shards on a dedicated thread, keeping merges off the
//! executor threads that serve the connections. The final report reads them
//! without locking after all connections have stopped.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const hdr = @import("hdr.zig");
const connection = @import("connection.zig");
const h3conn = @import("h3conn.zig");
const tlsmod = @import("tls.zig");

/// Latency histogram configuration: 1µs .. 60s at 3 significant figures.
///
/// Each shard owns one 136KiB histogram. The range and precision stay the same
/// regardless of connection count: one million connections on sixteen threads
/// still need only sixteen of these, plus the fixed reporting histograms.
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

/// Shared by a subset of the fleet's connections. The lock protects the whole
/// statistics update, including its counters, and never spans I/O. Align it to
/// keep different shards' locks off the same cache line.
pub const Shard = struct {
    mutex: std.atomic.Mutex align(std.atomic.cache_line) = .unlocked,
    hist: hdr.Histogram,
    counters: connection.Counters = .{},

    fn lock(self: *Shard) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

/// Owns shared statistics and per-connection transport state, and hands out
/// `connection.Params`. Connections are assigned to shards by index, so their
/// statistics remain safe when the runtime migrates them between executors.
pub const Fleet = struct {
    allocator: Allocator,
    n: u32,
    shards: []Shard,
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
        /// Normally `cfg.threads`; clamped to 1..max(n, 1).
        requested_shards: u32,
        enable_tls: bool,
        enable_h3: bool,
    ) !Fleet {
        const shard_count = @min(@max(requested_shards, 1), @max(n, 1));
        const shards = try allocator.alloc(Shard, shard_count);
        errdefer allocator.free(shards);
        var shards_inited: usize = 0;
        errdefer for (shards[0..shards_inited]) |*shard| shard.hist.deinit();
        for (shards) |*shard| {
            shard.* = .{ .hist = try newHistogram(allocator) };
            shards_inited += 1;
        }
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

        return .{
            .allocator = allocator,
            .n = n,
            .shards = shards,
            .params = params,
            .tls_state = tls_state,
            .h3_state = h3_state,
        };
    }

    /// Fill in the per-connection `Params`. All connections share the same
    /// target address/request/schedule. Each connection gets a stagger
    /// phase of i/n so the fleet's sends interleave uniformly instead of
    /// firing in lockstep waves (see pace.Schedule.offsetNs).
    pub fn buildParams(
        self: *Fleet,
        template: connection.Params,
    ) []connection.Params {
        const n: f64 = @floatFromInt(self.params.len);
        for (self.params, 0..) |*p, i| {
            const shard = &self.shards[i % self.shards.len];
            p.* = template;
            p.histogram = &shard.hist;
            p.counters = &shard.counters;
            p.stats_mutex = &shard.mutex;
            p.publish = null;
            p.phase = @as(f64, @floatFromInt(i)) / n;
            p.index = @intCast(i);
            if (self.tls_state) |ts| p.tls_state = &ts[i];
            if (self.h3_state) |hs| p.h3_state = &hs[i];
        }
        return self.params;
    }

    /// Aggregate the current statistics from every shard.
    /// Safe to call concurrently with running connections.
    ///
    /// Each shard is read under its recording lock, so its histogram and
    /// counters describe the same events. The merge costs O(shards), and no
    /// connection needs to copy or publish its own histogram.
    pub fn readSnapshot(self: *Fleet, io: Io, dst: *Snapshot) void {
        _ = io;
        dst.hist.reset();
        dst.counters = .{};
        for (self.shards) |*shard| {
            shard.lock();
            defer shard.mutex.unlock();
            dst.hist.add(&shard.hist);
            dst.counters.add(shard.counters);
        }
    }

    /// Aggregate the live shards. Only call once all connections
    /// have stopped (no synchronization is performed).
    pub fn readFinal(self: *Fleet, dst: *Snapshot) void {
        dst.hist.reset();
        dst.counters = .{};
        for (self.shards) |*shard| {
            dst.hist.add(&shard.hist);
            dst.counters.add(shard.counters);
        }
    }

    pub fn deinit(self: *Fleet) void {
        for (self.shards) |*shard| shard.hist.deinit();
        self.allocator.free(self.shards);
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
/// The merge adds one histogram per shard. Keeping this work off executor 0
/// avoids delaying that executor's scheduled sends while the dashboard reads
/// statistics. Each shard's recording lock is held only for its own merge.
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
    // Keep the existing range and precision while changing ownership. Each
    // additional power-of-two of range costs 1024 u64 = 8KiB per shard.
    try testing.expectEqual(@as(u32, 17 * 1024), h.counts_len);
    try testing.expectEqual(@as(usize, 136 * 1024), h.counts.len * @sizeOf(u64));

    // The ceiling clamps rather than drops: a 10-minute outlier still counts.
    h.record(600 * std.time.us_per_s);
    try testing.expectEqual(@as(u64, 1), h.count());
    try testing.expectEqual(hist_highest, h.max_value);
}

fn testParams(io: Io, stop: *std.atomic.Value(bool)) connection.Params {
    return .{
        .io = io,
        .address = std.Io.net.IpAddress.parse("127.0.0.1", 80) catch unreachable,
        .host = "127.0.0.1",
        .request = "",
        .is_tls = false,
        .insecure = false,
        .schedule = .closed,
        .timeout_ns = 0,
        .end = .zero,
        .stop = stop,
        .histogram = undefined,
        .counters = undefined,
    };
}

test "fleet preserves the full distribution when connections share shards" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var fleet = try Fleet.init(testing.allocator, 8, 2, false, false);
    defer fleet.deinit();
    const params = fleet.buildParams(testParams(threaded.io(), &stop));

    var reference = try newHistogram(testing.allocator);
    defer reference.deinit();

    for (params, 0..) |*p, i| {
        const latency = 1000 * (@as(u64, @intCast(i)) + 1);
        connection.noteResponse(p, latency, 100, 200, 0);
        reference.record(latency);
        try testing.expect(p.publish == null);
    }

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    fleet.readFinal(&snap);

    try testing.expectEqual(@as(u64, 8), snap.counters.completed);
    try testing.expectEqual(@as(u64, 800), snap.counters.bytes);
    try testing.expectEqual(@as(u64, 8), snap.counters.status_class[2]);
    try testing.expectEqualSlices(u64, reference.counts, snap.hist.counts);
}

test "ten thousand connections fit in a fixed statistics budget" {
    // Per-connection histograms needed over 2.5GiB for this fleet. The budget
    // includes Params for every connection and four full-precision shards.
    const buffer = try testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer testing.allocator.free(buffer);
    var fixed = std.heap.FixedBufferAllocator.init(buffer);
    var fleet = try Fleet.init(fixed.allocator(), 10_000, 4, false, false);
    defer fleet.deinit();
    try testing.expectEqual(@as(usize, 4), fleet.shards.len);
    try testing.expectEqual(@as(usize, 10_000), fleet.params.len);
}

test "shard count has a nonzero floor and does not exceed connections" {
    var single = try Fleet.init(testing.allocator, 3, 0, false, false);
    defer single.deinit();
    try testing.expectEqual(@as(usize, 1), single.shards.len);
    var capped = try Fleet.init(testing.allocator, 3, 16, false, false);
    defer capped.deinit();
    try testing.expectEqual(@as(usize, 3), capped.shards.len);
}

test "Fleet.init leaks nothing when any allocation fails" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn initAndDeinit(allocator: Allocator) !void {
            var fleet = try Fleet.init(allocator, 3, 2, true, false);
            fleet.deinit();
        }
    }.initAndDeinit, .{});
}

test "readSnapshot sees shared updates without per-connection publication" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var fleet = try Fleet.init(testing.allocator, 2, 1, false, false);
    defer fleet.deinit();
    var stop = std.atomic.Value(bool).init(false);
    const params = fleet.buildParams(testParams(io, &stop));

    for (params) |*p| {
        for (0..7) |_| connection.noteResponse(p, 5000, 1, 200, 0);
    }

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    fleet.readSnapshot(io, &snap);

    try testing.expectEqual(@as(u64, 14), snap.counters.completed);
    try testing.expectEqual(@as(u64, 14), snap.hist.count());
}

test "concurrent writers and snapshots preserve samples and all counter kinds" {
    var threaded = Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const writers = 8;
    const iterations = 8192;
    var fleet = try Fleet.init(testing.allocator, writers, 2, false, false);
    defer fleet.deinit();
    var stop = std.atomic.Value(bool).init(false);
    const params = fleet.buildParams(testParams(io, &stop));
    var finished = std.atomic.Value(u32).init(0);

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();
    var sweeper = try Sweeper.init(testing.allocator, &fleet, io);
    defer sweeper.deinit();
    sweeper.start();

    const Worker = struct {
        fn run(p: *connection.Params, done: *std.atomic.Value(u32)) void {
            for (0..iterations) |i| {
                const status: u16 = if (i % 4 == 0) 500 else 200;
                connection.noteResponse(p, 1000 * (@as(u64, p.index) + 1), 31, status, 0);
                connection.noteBehind(p, @as(u64, p.index) + 1);
                if (i % 16 == 0) connection.noteTimeout(p, p.io, connection.now(p.io));
                if (i % 32 == 0) connection.noteDeadline(p);
                if (i % 64 == 0) {
                    connection.noteConnectFailure(p, error.TestConnectFailure);
                    connection.noteError(p, .read);
                    connection.noteError(p, .write);
                }
            }
            _ = done.fetchAdd(1, .release);
        }
    };

    // Four OS threads write each shard, while the sweeper reads the same
    // shards. This exercises migration-like contention rather than relying on
    // the scheduler to happen to run connections on different executors.
    {
        var threads: [writers]std.Thread = undefined;
        var launched: usize = 0;
        defer for (threads[0..launched]) |thread| thread.join();
        for (params) |*p| {
            threads[launched] = try std.Thread.spawn(.{}, Worker.run, .{ p, &finished });
            launched += 1;
        }
        var previous: u64 = 0;
        while (finished.load(.acquire) < writers) {
            sweeper.snapshot(&snap);
            try testing.expect(snap.counters.completed >= previous);
            try testing.expectEqual(snap.counters.completed + snap.counters.timeouts, snap.hist.count());
            try testing.expectEqual(snap.counters.completed * 31, snap.counters.bytes);
            try testing.expectEqual(snap.counters.completed, snap.counters.status_class[2] + snap.counters.status_class[5]);
            previous = snap.counters.completed;
            std.Thread.yield() catch {};
        }
    }
    fleet.readFinal(&snap);
    const completed = writers * iterations;
    try testing.expectEqual(@as(u64, completed), snap.counters.completed);
    try testing.expectEqual(@as(u64, completed / 4), snap.counters.status_errors);
    try testing.expectEqual(@as(u64, completed / 16), snap.counters.timeouts);
    try testing.expectEqual(@as(u64, completed / 32), snap.counters.deadline_errors);
    try testing.expectEqual(@as(u64, completed / 64), snap.counters.connect_errors);
    try testing.expectEqual(@as(u64, completed / 64), snap.counters.read_errors);
    try testing.expectEqual(@as(u64, completed / 64), snap.counters.write_errors);
    try testing.expectEqual(@as(u64, writers), snap.counters.max_behind_ns);
    try testing.expectEqual(@as(?anyerror, error.TestConnectFailure), snap.counters.first_connect_error);
    try testing.expectEqual(snap.counters.completed + snap.counters.timeouts, snap.hist.count());
}

test "Sweeper returns the same aggregate as an inline readSnapshot" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();
    const io = rt.io();

    var fleet = try Fleet.init(testing.allocator, 8, 2, false, false);
    defer fleet.deinit();
    for (fleet.shards, 0..) |*p, i| {
        p.hist.recordCount(1000 * (@as(u64, @intCast(i)) + 1), 7);
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

    var fleet = try Fleet.init(testing.allocator, 4, 2, false, false);
    defer fleet.deinit();

    var sweeper = try Sweeper.init(testing.allocator, &fleet, io);
    defer sweeper.deinit();
    sweeper.start();
    var stop = std.atomic.Value(bool).init(false);
    const params = fleet.buildParams(testParams(io, &stop));

    var snap: Snapshot = .{ .hist = try newHistogram(testing.allocator), .counters = .{} };
    defer snap.deinit();

    // Every round records one more request per connection; the very next
    // snapshot must already see it, with no intervening sleep.
    for (1..6) |round| {
        for (params) |*p| connection.noteResponse(p, 1000, 1, 200, 0);
        sweeper.snapshot(&snap);
        try testing.expectEqual(@as(u64, round * 4), snap.counters.completed);
        try testing.expectEqual(@as(u64, round * 4), snap.hist.count());
    }
}

test "Sweeper stops cleanly when no snapshot was ever taken" {
    var rt = try zio.Runtime.init(testing.allocator, .{});
    defer rt.deinit();

    var fleet = try Fleet.init(testing.allocator, 2, 2, false, false);
    defer fleet.deinit();

    var sweeper = try Sweeper.init(testing.allocator, &fleet, rt.io());
    sweeper.start();
    sweeper.deinit(); // must join the idle thread rather than hang
}
