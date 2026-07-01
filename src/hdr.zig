//! A minimal HdrHistogram (High Dynamic Range histogram).
//!
//! Records integer values (microseconds, in zrk's use) into logarithmically
//! sized buckets, each subdivided linearly so that every value is recorded with
//! a bounded relative error determined by `sig_figs`. This gives lossless-enough
//! recording across a huge dynamic range (e.g. 1µs .. 1h) in a fixed, small
//! amount of memory, and O(1) recording.
//!
//! Layout follows the canonical HdrHistogram design: values are split into a
//! series of power-of-two "buckets"; within a bucket there are
//! `sub_bucket_count` linearly spaced "sub-buckets". Bucket 0 covers the range
//! that the sub-buckets can represent at unit resolution; each subsequent bucket
//! doubles the unit resolution, extending the range while keeping the relative
//! error bounded.
//!
//! Only the counts array is stored, so a histogram can be copied/merged by a
//! simple element-wise add of the counts — this is what the snapshot publishing
//! and final aggregation rely on.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Histogram = struct {
    /// Smallest value that can be distinguished from 0. Values below this are
    /// clamped up to it when recorded.
    lowest_discernible: u64,
    /// Largest value the histogram is configured to track. Values above this
    /// are clamped down to it (and counted, never dropped).
    highest_trackable: u64,
    /// Number of significant decimal digits of resolution (1..=5).
    sig_figs: u8,

    /// log2 of the sub-bucket count (unit magnitude).
    sub_bucket_half_count_magnitude: u5,
    sub_bucket_count: u32,
    sub_bucket_half_count: u32,
    sub_bucket_mask: u64,
    /// Number of power-of-two buckets.
    bucket_count: u32,
    /// Length of `counts` = (bucket_count + 1) * sub_bucket_half_count.
    counts_len: u32,
    unit_magnitude: u5,

    counts: []u64,

    total_count: u64 = 0,
    min_value: u64 = std.math.maxInt(u64),
    max_value: u64 = 0,

    allocator: Allocator,

    pub const InitError = Allocator.Error || error{InvalidArguments};

    pub fn init(
        allocator: Allocator,
        lowest_discernible: u64,
        highest_trackable: u64,
        sig_figs: u8,
    ) InitError!Histogram {
        if (lowest_discernible < 1) return error.InvalidArguments;
        if (sig_figs < 1 or sig_figs > 5) return error.InvalidArguments;
        if (highest_trackable < 2 * lowest_discernible) return error.InvalidArguments;

        // largest_value_with_single_unit_resolution = 2 * 10^sig_figs
        const largest_single_unit: u64 = 2 * std.math.pow(u64, 10, sig_figs);

        // sub_bucket_count is the next power of two >= largest_single_unit.
        const sub_bucket_count_magnitude: u5 = @intCast(std.math.log2_int_ceil(u64, largest_single_unit));
        const sub_bucket_half_count_magnitude: u5 =
            if (sub_bucket_count_magnitude > 0) sub_bucket_count_magnitude - 1 else 0;

        const unit_magnitude: u5 = @intCast(std.math.log2_int(u64, lowest_discernible));

        const sub_bucket_count: u32 = @as(u32, 1) << (sub_bucket_half_count_magnitude + 1);
        const sub_bucket_half_count: u32 = sub_bucket_count / 2;
        const sub_bucket_mask: u64 = (@as(u64, sub_bucket_count) - 1) << unit_magnitude;

        var self: Histogram = .{
            .lowest_discernible = lowest_discernible,
            .highest_trackable = highest_trackable,
            .sig_figs = sig_figs,
            .sub_bucket_half_count_magnitude = sub_bucket_half_count_magnitude,
            .sub_bucket_count = sub_bucket_count,
            .sub_bucket_half_count = sub_bucket_half_count,
            .sub_bucket_mask = sub_bucket_mask,
            .bucket_count = 0,
            .counts_len = 0,
            .unit_magnitude = unit_magnitude,
            .counts = &.{},
            .allocator = allocator,
        };

        self.bucket_count = self.bucketsNeededFor(highest_trackable);
        self.counts_len = (self.bucket_count + 1) * sub_bucket_half_count;

        self.counts = try allocator.alloc(u64, self.counts_len);
        @memset(self.counts, 0);
        return self;
    }

    pub fn deinit(self: *Histogram) void {
        self.allocator.free(self.counts);
        self.* = undefined;
    }

    /// How many power-of-two buckets are needed to represent `value`.
    fn bucketsNeededFor(self: *const Histogram, value: u64) u32 {
        var smallest_untrackable: u64 = (@as(u64, self.sub_bucket_count)) << self.unit_magnitude;
        var buckets_needed: u32 = 1;
        while (smallest_untrackable <= value) {
            if (smallest_untrackable > std.math.maxInt(u64) / 2) {
                // Would overflow on next doubling: this bucket covers everything.
                return buckets_needed + 1;
            }
            smallest_untrackable <<= 1;
            buckets_needed += 1;
        }
        return buckets_needed;
    }

    // --- index math ----------------------------------------------------------

    fn bucketIndex(self: *const Histogram, value: u64) u32 {
        // Leading-zero based: the position of the highest set bit above the
        // sub-bucket window determines the bucket.
        const pow2ceiling: u32 = @intCast(64 - @clz(value | self.sub_bucket_mask));
        return pow2ceiling - self.unit_magnitude - (self.sub_bucket_half_count_magnitude + 1);
    }

    fn subBucketIndex(self: *const Histogram, value: u64, bucket_index: u32) u32 {
        return @intCast(value >> @intCast(@as(u32, bucket_index) + self.unit_magnitude));
    }

    fn countsIndex(self: *const Histogram, bucket_index: u32, sub_bucket_index: u32) u32 {
        assert(sub_bucket_index < self.sub_bucket_count);
        assert(bucket_index == 0 or sub_bucket_index >= self.sub_bucket_half_count);
        const bucket_base_index: i64 = @as(i64, bucket_index + 1) << self.sub_bucket_half_count_magnitude;
        const offset_in_bucket: i64 = @as(i64, sub_bucket_index) - @as(i64, @intCast(self.sub_bucket_half_count));
        return @intCast(bucket_base_index + offset_in_bucket);
    }

    fn countsIndexFor(self: *const Histogram, value: u64) u32 {
        const bi = self.bucketIndex(value);
        const sbi = self.subBucketIndex(value, bi);
        return self.countsIndex(bi, sbi);
    }

    /// The lowest value stored at a given counts-array index (bucket bottom).
    fn valueFromIndex(self: *const Histogram, index: u32) u64 {
        var bucket_index: i32 = @as(i32, @intCast(index >> self.sub_bucket_half_count_magnitude)) - 1;
        var sub_bucket_index: u32 = (index & (self.sub_bucket_half_count - 1)) + self.sub_bucket_half_count;
        if (bucket_index < 0) {
            sub_bucket_index -= self.sub_bucket_half_count;
            bucket_index = 0;
        }
        return @as(u64, sub_bucket_index) << @intCast(@as(u32, @intCast(bucket_index)) + self.unit_magnitude);
    }

    /// Size, in value units, of the buckets at a given counts index. Used to
    /// return the midpoint of a bucket for percentile/iteration queries.
    fn sizeOfEquivalentRange(self: *const Histogram, value: u64) u64 {
        const bi = self.bucketIndex(value);
        return @as(u64, 1) << @intCast(@as(u32, bi) + self.unit_magnitude);
    }

    /// Lowest value that maps to the same bucket as `value`.
    pub fn lowestEquivalentValue(self: *const Histogram, value: u64) u64 {
        const bi = self.bucketIndex(value);
        const sbi = self.subBucketIndex(value, bi);
        return @as(u64, sbi) << @intCast(@as(u32, bi) + self.unit_magnitude);
    }

    /// Highest value that maps to the same bucket as `value`.
    pub fn highestEquivalentValue(self: *const Histogram, value: u64) u64 {
        return self.lowestEquivalentValue(value) + self.sizeOfEquivalentRange(value) - 1;
    }

    /// Midpoint of the bucket that `value` falls into — the representative value
    /// reported by percentile queries.
    pub fn medianEquivalentValue(self: *const Histogram, value: u64) u64 {
        return self.lowestEquivalentValue(value) + (self.sizeOfEquivalentRange(value) >> 1);
    }

    // --- recording -----------------------------------------------------------

    /// Record a single occurrence of `raw_value`. Values outside the trackable
    /// range are clamped (never dropped) so tail behavior is preserved.
    pub fn record(self: *Histogram, raw_value: u64) void {
        self.recordCount(raw_value, 1);
    }

    pub fn recordCount(self: *Histogram, raw_value: u64, n: u64) void {
        var value = raw_value;
        if (value < self.lowest_discernible) value = self.lowest_discernible;
        if (value > self.highest_trackable) value = self.highest_trackable;

        const index = self.countsIndexFor(value);
        self.counts[index] += n;
        self.total_count += n;
        if (value < self.min_value) self.min_value = value;
        if (value > self.max_value) self.max_value = value;
    }

    pub fn reset(self: *Histogram) void {
        @memset(self.counts, 0);
        self.total_count = 0;
        self.min_value = std.math.maxInt(u64);
        self.max_value = 0;
    }

    // --- merging / snapshotting ---------------------------------------------

    /// Add every count from `other` into `self`. Both histograms must have been
    /// created with identical parameters (same counts layout).
    pub fn add(self: *Histogram, other: *const Histogram) void {
        assert(self.counts_len == other.counts_len);
        for (self.counts, other.counts) |*dst, src| dst.* += src;
        self.total_count += other.total_count;
        if (other.min_value < self.min_value) self.min_value = other.min_value;
        if (other.max_value > self.max_value) self.max_value = other.max_value;
    }

    /// Copy this histogram's contents into `dst` (which must share the layout).
    /// Used to publish a snapshot without allocating.
    pub fn copyInto(self: *const Histogram, dst: *Histogram) void {
        assert(self.counts_len == dst.counts_len);
        @memcpy(dst.counts, self.counts);
        dst.total_count = self.total_count;
        dst.min_value = self.min_value;
        dst.max_value = self.max_value;
    }

    // --- queries -------------------------------------------------------------

    pub fn count(self: *const Histogram) u64 {
        return self.total_count;
    }

    pub fn min(self: *const Histogram) u64 {
        return if (self.total_count == 0) 0 else self.min_value;
    }

    pub fn max(self: *const Histogram) u64 {
        return if (self.total_count == 0) 0 else self.highestEquivalentValue(self.max_value);
    }

    pub fn mean(self: *const Histogram) f64 {
        if (self.total_count == 0) return 0;
        var total: f64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c == 0) continue;
            const v: f64 = @floatFromInt(self.medianEquivalentValue(self.valueFromIndex(@intCast(i))));
            total += v * @as(f64, @floatFromInt(c));
        }
        return total / @as(f64, @floatFromInt(self.total_count));
    }

    pub fn stdDev(self: *const Histogram) f64 {
        if (self.total_count == 0) return 0;
        const m = self.mean();
        var geometric_sum: f64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c == 0) continue;
            const v: f64 = @floatFromInt(self.medianEquivalentValue(self.valueFromIndex(@intCast(i))));
            const dev = v - m;
            geometric_sum += (dev * dev) * @as(f64, @floatFromInt(c));
        }
        return @sqrt(geometric_sum / @as(f64, @floatFromInt(self.total_count)));
    }

    /// Value at the given percentile (0..100). Returns the midpoint of the
    /// bucket whose cumulative count first reaches the requested rank.
    pub fn valueAtPercentile(self: *const Histogram, percentile: f64) u64 {
        if (self.total_count == 0) return 0;
        const clamped = std.math.clamp(percentile, 0.0, 100.0);
        // Rank of the requested percentile, rounded to the nearest count.
        var wanted: u64 = @intFromFloat(@round((clamped / 100.0) * @as(f64, @floatFromInt(self.total_count))));
        if (wanted == 0) wanted = 1;

        var running: u64 = 0;
        for (self.counts, 0..) |c, i| {
            running += c;
            if (running >= wanted) {
                const v = self.valueFromIndex(@intCast(i));
                return self.medianEquivalentValue(v);
            }
        }
        return self.max();
    }

    /// True if `a` and `b` fall into the same histogram bucket (indistinguishable).
    pub fn valuesAreEquivalent(self: *const Histogram, a: u64, b: u64) bool {
        return self.lowestEquivalentValue(a) == self.lowestEquivalentValue(b);
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;

fn newDefault() !Histogram {
    // 1µs .. 1 hour, 3 significant figures — zrk's default latency histogram.
    return Histogram.init(testing.allocator, 1, 3_600_000_000, 3);
}

test "init produces sane geometry" {
    var h = try newDefault();
    defer h.deinit();
    try testing.expect(h.sub_bucket_count == 2048); // 2*10^3 -> next pow2 = 2048
    try testing.expect(h.counts_len > 0);
    try testing.expectEqual(@as(u64, 0), h.count());
}

test "record and count" {
    var h = try newDefault();
    defer h.deinit();
    h.record(100);
    h.record(200);
    h.record(300);
    try testing.expectEqual(@as(u64, 3), h.count());
    try testing.expect(h.valuesAreEquivalent(h.min(), 100));
}

test "percentiles on uniform 1..1000" {
    var h = try newDefault();
    defer h.deinit();
    var i: u64 = 1;
    while (i <= 1000) : (i += 1) h.record(i);
    try testing.expectEqual(@as(u64, 1000), h.count());

    // Within 3-sig-fig resolution the reported percentile value should be very
    // close to the true one.
    const p50 = h.valueAtPercentile(50.0);
    try testing.expect(p50 >= 495 and p50 <= 505);
    const p90 = h.valueAtPercentile(90.0);
    try testing.expect(p90 >= 895 and p90 <= 905);
    const p99 = h.valueAtPercentile(99.0);
    try testing.expect(p99 >= 985 and p99 <= 995);
    const p100 = h.valueAtPercentile(100.0);
    try testing.expect(h.valuesAreEquivalent(p100, 1000));
}

test "high dynamic range: mix of small and huge values" {
    var h = try newDefault();
    defer h.deinit();
    // 999 fast requests at 500µs, one catastrophic 10s outlier.
    var i: u64 = 0;
    while (i < 999) : (i += 1) h.record(500);
    h.record(10_000_000);

    const p50 = h.valueAtPercentile(50.0);
    try testing.expect(h.valuesAreEquivalent(p50, 500));
    // The tail must reflect the outlier, not hide it (the whole point of HDR).
    const p100 = h.valueAtPercentile(100.0);
    try testing.expect(p100 >= 9_900_000);
    try testing.expect(h.max() >= 9_900_000);
}

test "clamping out-of-range values" {
    var h = try Histogram.init(testing.allocator, 1, 1000, 3);
    defer h.deinit();
    h.record(0); // clamps up to lowest_discernible (1)
    h.record(1_000_000); // clamps down to highest_trackable (1000)
    try testing.expectEqual(@as(u64, 2), h.count());
    try testing.expect(h.max() <= h.highestEquivalentValue(1000));
    try testing.expect(h.min() >= 1);
}

test "merge via add" {
    var a = try newDefault();
    defer a.deinit();
    var b = try newDefault();
    defer b.deinit();
    var i: u64 = 1;
    while (i <= 500) : (i += 1) a.record(i);
    while (i <= 1000) : (i += 1) b.record(i);
    a.add(&b);
    try testing.expectEqual(@as(u64, 1000), a.count());
    const p50 = a.valueAtPercentile(50.0);
    try testing.expect(p50 >= 495 and p50 <= 505);
}

test "copyInto snapshot" {
    var a = try newDefault();
    defer a.deinit();
    var snap = try newDefault();
    defer snap.deinit();
    a.record(1234);
    a.record(5678);
    a.copyInto(&snap);
    try testing.expectEqual(a.count(), snap.count());
    try testing.expectEqual(a.valueAtPercentile(99.0), snap.valueAtPercentile(99.0));
}

test "empty histogram queries are zero" {
    var h = try newDefault();
    defer h.deinit();
    try testing.expectEqual(@as(u64, 0), h.count());
    try testing.expectEqual(@as(u64, 0), h.min());
    try testing.expectEqual(@as(u64, 0), h.max());
    try testing.expectEqual(@as(f64, 0), h.mean());
    try testing.expectEqual(@as(u64, 0), h.valueAtPercentile(99.0));
}

test "mean of constant distribution" {
    var h = try newDefault();
    defer h.deinit();
    var i: u64 = 0;
    while (i < 100) : (i += 1) h.record(1000);
    const m = h.mean();
    try testing.expect(m >= 999 and m <= 1001);
    try testing.expect(h.stdDev() < 1.0);
}
