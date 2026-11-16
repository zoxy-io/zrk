//! Microbenchmark for shared histogram recording and aggregation.
//!
//! Measures concurrent response recording into shared shards, copying an
//! aggregate snapshot, and merging a realistic number of statistics shards.
//!
//! Build/run:  zig build bench
//! Both run over a realistic latency distribution so the touched index range
//! reflects real use (which is what the range-limited variant exploits).

const std = @import("std");
const Io = std.Io;
const zrk = @import("zrk");
const hdr = zrk.hdr;
const stats = zrk.stats;
const connection = zrk.connection;

fn nowNs(io: Io) i128 {
    return Io.Timestamp.now(io, .awake).nanoseconds;
}

// Production histogram parameters (mirror stats.zig: 1µs .. 60s, 3 sig figs).
const lowest: u64 = 1;
const highest: u64 = 60_000_000;
const sig_figs: u8 = 3;

/// Fill `h` with a log-normal-ish latency spread (median ~3ms, tail to ~80ms,
/// a sub-ms floor) plus a few outliers, so min/max span a realistic band.
fn recordRealistic(h: *hdr.Histogram, rng: std.Random, n: usize) void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        // exp(normal) around ln(3000µs); clamp to a sane floor.
        const z = rng.floatNorm(f64);
        const us = @exp(@log(3000.0) + 0.6 * z);
        const v: u64 = @intFromFloat(@max(us, 200.0));
        h.record(v);
    }
    // A handful of tail outliers (slow requests / GC pauses).
    var k: usize = 0;
    while (k < n / 500 + 1) : (k += 1) {
        h.record(20_000 + rng.uintLessThan(u64, 60_000));
    }
}

const print = std.debug.print;

fn recordBench(a: std.mem.Allocator, io: Io) !void {
    const writers = 8;
    const iterations = 100_000;
    for ([_]u32{ 1, writers }) |shard_count| {
        var fleet = try stats.Fleet.init(a, writers, shard_count, false, false);
        defer fleet.deinit();
        var stop = std.atomic.Value(bool).init(false);
        const params = fleet.buildParams(.{
            .io = io,
            .address = std.Io.net.IpAddress.parse("127.0.0.1", 80) catch unreachable,
            .host = "127.0.0.1",
            .request = "",
            .is_tls = false,
            .insecure = false,
            .schedule = .closed,
            .timeout_ns = 0,
            .end = .zero,
            .stop = &stop,
            .histogram = undefined,
            .counters = undefined,
        });
        var ready = std.atomic.Value(u32).init(0);
        var go = std.atomic.Value(bool).init(false);
        const Worker = struct {
            fn run(p: *connection.Params, started: *std.atomic.Value(u32), begin: *std.atomic.Value(bool)) void {
                _ = started.fetchAdd(1, .release);
                while (!begin.load(.acquire)) std.atomic.spinLoopHint();
                for (0..iterations) |i| connection.noteResponse(p, 1000 + i % 1000, 64, 200, 0);
                std.mem.doNotOptimizeAway(p.histogram);
                std.mem.doNotOptimizeAway(p.counters);
            }
        };
        var threads: [writers]std.Thread = undefined;
        var launched: usize = 0;
        errdefer {
            go.store(true, .release);
            for (threads[0..launched]) |thread| thread.join();
        }
        for (params) |*p| {
            threads[launched] = try std.Thread.spawn(.{}, Worker.run, .{ p, &ready, &go });
            launched += 1;
        }
        while (ready.load(.acquire) < writers) std.atomic.spinLoopHint();
        const start = nowNs(io);
        go.store(true, .release);
        for (threads) |thread| thread.join();
        launched = 0;
        const elapsed: f64 = @floatFromInt(nowNs(io) - start);
        const records = writers * iterations;
        var samples: u64 = 0;
        var completed: u64 = 0;
        for (fleet.shards) |*shard| {
            for (shard.hist.counts) |count| samples += count;
            completed += shard.counters.completed;
        }
        if (samples != records or completed != records) return error.BenchmarkLostSamples;
        print("noteResponse {d} writers / {d} shards: {d:.1} ns/response, {d:.1}M responses/s\n", .{
            writers, shard_count, elapsed / records, records * 1000 / elapsed,
        });
    }
}

pub fn main() !void {
    const a = std.heap.page_allocator;

    var threaded = Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try recordBench(a, io);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rng = prng.random();

    // One representative source histogram.
    var src = try hdr.Histogram.init(a, lowest, highest, sig_figs);
    defer src.deinit();
    recordRealistic(&src, rng, 200_000);

    var dst = try hdr.Histogram.init(a, lowest, highest, sig_figs);
    defer dst.deinit();

    const counts_len = src.counts_len;
    const bytes = @as(usize, counts_len) * 8;

    // Touched span: first..last nonzero index, the ceiling a range-limited
    // copy/add could hit. Predicts the achievable speedup.
    var lo: usize = counts_len;
    var hi: usize = 0;
    for (src.counts, 0..) |c, i| {
        if (c != 0) {
            if (i < lo) lo = i;
            if (i > hi) hi = i;
        }
    }
    const span = if (hi >= lo) hi - lo + 1 else 0;

    print("histogram: counts_len={d}  ({d:.1} KiB)\n", .{ counts_len, @as(f64, @floatFromInt(bytes)) / 1024.0 });
    print("recorded:  n=200000  min={d}us max={d}us\n", .{ src.min_value, src.max_value });
    print("touched:   [{d}..{d}]  span={d}  ({d:.1}% of array)\n\n", .{
        lo, hi, span, 100.0 * @as(f64, @floatFromInt(span)) / @as(f64, @floatFromInt(counts_len)),
    });

    // --- copyInto (aggregate snapshot) -------------------------------------
    const K = 20_000;
    const ci_start = nowNs(io);
    {
        var i: usize = 0;
        while (i < K) : (i += 1) {
            src.copyInto(&dst);
            std.mem.doNotOptimizeAway(dst.counts[hi]);
        }
    }
    const ci_ns: u64 = @intCast(@divTrunc(nowNs(io) - ci_start, K));
    print("copyInto:            {d:>7} ns/op   ({d:.1} GB/s)\n", .{
        ci_ns, @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(ci_ns)),
    });

    // --- reset + N×add (per readSnapshot frame) ----------------------------
    //
    // Merge distinct shards with the production snapshot path, including its
    // locks. Shard count follows --threads rather than -c.
    var snap: stats.Snapshot = .{ .hist = try stats.newHistogram(a), .counters = .{} };
    defer snap.deinit();
    for ([_]u32{ 1, 8, 32, 128 }) |nshards| {
        var fleet = try stats.Fleet.init(a, nshards, nshards, false, false);
        defer fleet.deinit();
        for (fleet.shards, 0..) |*shard, i| {
            var p = std.Random.DefaultPrng.init(0xC0FFEE +% i);
            recordRealistic(&shard.hist, p.random(), 2_000);
            shard.counters.completed = shard.hist.count();
        }

        const resident = @as(f64, @floatFromInt(nshards * span * 8)) / (1024.0 * 1024.0);
        const iters = 1000;
        const start = nowNs(io);
        var it: usize = 0;
        while (it < iters) : (it += 1) {
            fleet.readSnapshot(io, &snap);
            std.mem.doNotOptimizeAway(snap.hist.counts[hi]);
        }
        const per_frame: u64 = @intCast(@divTrunc(nowNs(io) - start, iters));
        const gbs = @as(f64, @floatFromInt(nshards * span * 8)) / @as(f64, @floatFromInt(per_frame));
        // Live TUI redraws at --refresh (80ms) => 12.5 frames/s.
        const core_frac = @as(f64, @floatFromInt(per_frame)) * 12.5 / 1e9;
        print("readSnapshot shards={d:>3}: {d:>9} ns/pass  ({d:>5.1} MiB read, {d:.1} GB/s, {d:.1}% of a core @12.5fps)\n", .{
            nshards, per_frame, resident, gbs, core_frac * 100.0,
        });
    }
}
