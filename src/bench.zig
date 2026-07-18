//! Microbenchmark for the histogram publish/aggregate path.
//!
//! These two operations are the dashboard's per-frame cost (see tui/runner):
//!   - `copyInto`  — a connection publishes its live histogram once per publish
//!                   interval (now the `--refresh` cadence with a live TUI).
//!   - reset + N×`add` — `stats.readSnapshot` merges every connection's snapshot
//!                   into one aggregate, once per frame.
//!
//! Build/run:  zig build bench
//! Both run over a realistic latency distribution so the touched index range
//! reflects real use (which is what the range-limited variant exploits).

const std = @import("std");
const Io = std.Io;
const zrk = @import("zrk");
const hdr = zrk.hdr;

fn nowNs(io: Io) i128 {
    return Io.Timestamp.now(io, .awake).nanoseconds;
}

// Production histogram parameters (mirror stats.zig: 1µs .. 1h, 3 sig figs).
const lowest: u64 = 1;
const highest: u64 = 3_600_000_000;
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

pub fn main() !void {
    const a = std.heap.page_allocator;

    var threaded = Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

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

    // --- copyInto (per publish) --------------------------------------------
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
    for ([_]usize{ 10, 100, 1000 }) |nconns| {
        const iters = 2000;
        const start = nowNs(io);
        var it: usize = 0;
        while (it < iters) : (it += 1) {
            dst.reset();
            var c: usize = 0;
            while (c < nconns) : (c += 1) dst.add(&src);
            std.mem.doNotOptimizeAway(dst.counts[hi]);
        }
        const per_frame: u64 = @intCast(@divTrunc(nowNs(io) - start, iters));
        // Live TUI redraws at --refresh (80ms) => 12.5 frames/s.
        const per_sec_us = @as(f64, @floatFromInt(per_frame)) * 12.5 / 1000.0;
        print("readSnapshot N={d:>4}:  {d:>9} ns/frame   ({d:.2} ms/s of runner CPU @12.5fps)\n", .{
            nconns, per_frame, per_sec_us / 1000.0,
        });
    }
}
