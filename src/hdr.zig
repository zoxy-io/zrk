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

// HdrHistogram V2 interchange cookies (see `encodeBase64`). The low nibble of
// the cookie's third byte carries a word-size marker that decoders mask off with
// `cookie_base_mask`; the canonical library sets it to 0x10, which we match for
// byte-identical output.
const v2_encoding_base: u32 = 0x1c849303;
const v2_compressed_base: u32 = 0x1c849304;
const encoding_cookie: u32 = v2_encoding_base | 0x10; // 0x1c849313
const compressed_cookie: u32 = v2_compressed_base | 0x10; // 0x1c849314
const cookie_base_mask: u32 = ~@as(u32, 0xf0);

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
        // The doubling below must not overflow (decoded headers can carry
        // arbitrary values here).
        if (lowest_discernible > std.math.maxInt(u64) / 2) return error.InvalidArguments;
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

    /// Inclusive counts-index span covering every nonzero bucket, or null when
    /// empty. Counts indices increase monotonically with value, so every value
    /// ever recorded — and thus every nonzero bucket — lies within
    /// [index(min_value), index(max_value)]. Lets `add`/`copyInto` touch only
    /// the occupied region instead of the whole (mostly-zero) array, which for
    /// a clustered latency distribution is a fraction of `counts_len`.
    const IndexSpan = struct { lo: u32, hi: u32 };
    fn touchedSpan(self: *const Histogram) ?IndexSpan {
        if (self.total_count == 0) return null;
        return .{ .lo = self.countsIndexFor(self.min_value), .hi = self.countsIndexFor(self.max_value) };
    }

    /// Add every count from `other` into `self`. Both histograms must have been
    /// created with identical parameters (same counts layout). Only `other`'s
    /// occupied span is walked — adding its zero region is a no-op, so this is
    /// exact regardless of `self`'s contents.
    pub fn add(self: *Histogram, other: *const Histogram) void {
        assert(self.counts_len == other.counts_len);
        const s = other.touchedSpan() orelse return;
        for (self.counts[s.lo .. s.hi + 1], other.counts[s.lo .. s.hi + 1]) |*dst, src| dst.* += src;
        self.total_count += other.total_count;
        if (other.min_value < self.min_value) self.min_value = other.min_value;
        if (other.max_value > self.max_value) self.max_value = other.max_value;
    }

    /// Copy this histogram's contents into `dst` (which must share the layout).
    /// Used to publish a snapshot without allocating. Copies only the occupied
    /// span; any region `dst` still holds outside it is zeroed first, so the
    /// result equals `self` even when `dst` was previously wider. (For the
    /// monotonic cumulative snapshots this serves, the range only grows and the
    /// zeroing is a no-op.)
    pub fn copyInto(self: *const Histogram, dst: *Histogram) void {
        assert(self.counts_len == dst.counts_len);
        const src = self.touchedSpan();
        if (dst.touchedSpan()) |d| {
            if (src) |s| {
                if (d.lo < s.lo) @memset(dst.counts[d.lo..s.lo], 0);
                if (d.hi > s.hi) @memset(dst.counts[s.hi + 1 .. d.hi + 1], 0);
            } else {
                @memset(dst.counts[d.lo .. d.hi + 1], 0);
            }
        }
        if (src) |s| @memcpy(dst.counts[s.lo .. s.hi + 1], self.counts[s.lo .. s.hi + 1]);
        dst.total_count = self.total_count;
        dst.min_value = self.min_value;
        dst.max_value = self.max_value;
    }

    /// Set `self` to the element-wise difference `a - b` (all three sharing the
    /// layout). Turns two cumulative snapshots into the interval between them.
    /// The subtraction saturates (so a transiently-racy `b > a` can't underflow),
    /// and total/min/max are rebuilt by scanning so percentile queries on the
    /// result are correct.
    pub fn setToDifference(self: *Histogram, a: *const Histogram, b: *const Histogram) void {
        assert(self.counts_len == a.counts_len and a.counts_len == b.counts_len);
        self.total_count = 0;
        self.min_value = std.math.maxInt(u64);
        self.max_value = 0;
        for (self.counts, a.counts, b.counts, 0..) |*dst, av, bv, i| {
            const c = av -| bv;
            dst.* = c;
            if (c != 0) {
                self.total_count += c;
                const v = self.valueFromIndex(@intCast(i));
                if (v < self.min_value) self.min_value = v;
                if (v > self.max_value) self.max_value = v;
            }
        }
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
        var sum_sq_dev: f64 = 0;
        for (self.counts, 0..) |c, i| {
            if (c == 0) continue;
            const v: f64 = @floatFromInt(self.medianEquivalentValue(self.valueFromIndex(@intCast(i))));
            const dev = v - m;
            sum_sq_dev += (dev * dev) * @as(f64, @floatFromInt(c));
        }
        return @sqrt(sum_sq_dev / @as(f64, @floatFromInt(self.total_count)));
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

    // --- export --------------------------------------------------------------

    /// Write the classic HdrHistogram percentile distribution (`.hgrm`) — the
    /// same four-column format produced by `outputPercentileDistribution` and by
    /// wrk2's `--latency`, directly loadable by the HdrHistogram online plotter.
    ///
    /// `value_scale` divides each recorded value before printing (e.g. pass 1000
    /// to render microsecond samples as milliseconds). `ticks_per_half_distance`
    /// controls tail resolution; 5 matches HdrHistogram's default.
    pub fn writePercentileDistribution(
        self: *const Histogram,
        w: *std.Io.Writer,
        value_scale: f64,
        ticks_per_half_distance: u32,
    ) !void {
        try w.writeAll("       Value     Percentile TotalCount 1/(1-Percentile)\n\n");

        if (self.total_count != 0) {
            var percentile_to_iterate_to: f64 = 0;
            var running: u64 = 0;
            var done = false;
            var i: usize = 0;
            while (i < self.counts.len and !done) : (i += 1) {
                running += self.counts[i];
                while (running >= countAtPercentile(self.total_count, percentile_to_iterate_to)) {
                    const at_top = running >= self.total_count;
                    const value = self.highestEquivalentValue(self.valueFromIndex(@intCast(i)));
                    const level: f64 = if (at_top) 100.0 else percentile_to_iterate_to;
                    try w.print("{d:15.3} {d:14.6} {d:10} ", .{
                        @as(f64, @floatFromInt(value)) / value_scale,
                        level / 100.0,
                        running,
                    });
                    if (level < 100.0) {
                        try w.print("{d:14.2}\n", .{1.0 / (1.0 - level / 100.0)});
                    } else {
                        try w.writeAll("           inf\n");
                    }
                    if (at_top) {
                        done = true;
                        break;
                    }
                    percentile_to_iterate_to += nextPercentileStep(percentile_to_iterate_to, ticks_per_half_distance);
                    if (percentile_to_iterate_to > 100.0) {
                        done = true;
                        break;
                    }
                }
            }
        }

        try w.print("#[Mean    = {d:12.3}, StdDeviation   = {d:12.3}]\n", .{
            self.mean() / value_scale, self.stdDev() / value_scale,
        });
        try w.print("#[Max     = {d:12.3}, Total count    = {d:12}]\n", .{
            @as(f64, @floatFromInt(self.max())) / value_scale, self.total_count,
        });
        try w.print("#[Buckets = {d:12}, SubBuckets     = {d:12}]\n", .{
            self.bucket_count, self.sub_bucket_count,
        });
    }

    /// Encode this histogram as an HdrHistogram **V2 compressed** base64 string —
    /// the canonical interchange form. It is losslessly decodable and mergeable
    /// by any HdrHistogram library (Java/Go/JS/Rust/…), so a harness can store
    /// the raw distribution and re-percentile or merge runs after the fact.
    ///
    /// Layout: base64( compressedCookie:u32be, len:u32be, zlib( encodedForm ) ),
    /// where the encoded form is a 40-byte header (cookie, payload length,
    /// normalizing offset, sig figs, lowest, highest, int→double ratio) followed
    /// by the counts as ZigZag LEB128 varints with negative values run-length
    /// encoding consecutive zeros. Caller owns the returned slice.
    pub fn encodeBase64(self: *const Histogram, gpa: Allocator) ![]u8 {
        // Payload: counts[0..=index(maxValue)] as ZigZag varints, zeros RLE'd.
        const counts_limit: u32 = self.countsIndexFor(self.max_value) + 1;
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(gpa);
        var i: u32 = 0;
        while (i < counts_limit) {
            if (self.counts[i] == 0) {
                var zeros: u64 = 1;
                i += 1;
                while (i < counts_limit and self.counts[i] == 0) : (i += 1) zeros += 1;
                try appendZigZag(&payload, gpa, if (zeros > 1) -@as(i64, @intCast(zeros)) else 0);
            } else {
                try appendZigZag(&payload, gpa, @intCast(self.counts[i]));
                i += 1;
            }
        }

        // Uncompressed encoded form: 40-byte header + payload.
        const encoded = try gpa.alloc(u8, 40 + payload.items.len);
        defer gpa.free(encoded);
        std.mem.writeInt(u32, encoded[0..][0..4], encoding_cookie, .big);
        std.mem.writeInt(u32, encoded[4..][0..4], @intCast(payload.items.len), .big);
        std.mem.writeInt(u32, encoded[8..][0..4], 0, .big); // normalizing index offset
        std.mem.writeInt(u32, encoded[12..][0..4], @as(u32, self.sig_figs), .big);
        std.mem.writeInt(u64, encoded[16..][0..8], self.lowest_discernible, .big);
        std.mem.writeInt(u64, encoded[24..][0..8], self.highest_trackable, .big);
        std.mem.writeInt(u64, encoded[32..][0..8], @bitCast(@as(f64, 1.0)), .big); // int→double ratio
        @memcpy(encoded[40..], payload.items);

        // zlib-compress, then frame with the compressed cookie + length.
        const zbytes = try zlibCompress(gpa, encoded);
        defer gpa.free(zbytes);
        const framed = try gpa.alloc(u8, 8 + zbytes.len);
        defer gpa.free(framed);
        std.mem.writeInt(u32, framed[0..][0..4], compressed_cookie, .big);
        std.mem.writeInt(u32, framed[4..][0..4], @intCast(zbytes.len), .big);
        @memcpy(framed[8..], zbytes);

        // Standard base64 (padded), matching the canonical library.
        const enc = std.base64.standard.Encoder;
        const out = try gpa.alloc(u8, enc.calcSize(framed.len));
        _ = enc.encode(out, framed);
        return out;
    }
};

/// Decode an HdrHistogram V2 compressed base64 string (as produced by
/// `encodeBase64` or any HdrHistogram library) into a fresh histogram. The
/// caller owns it and must `deinit`. Enables merging previously-stored runs.
pub fn decodeBase64(gpa: Allocator, str: []const u8) !Histogram {
    const dec = std.base64.standard.Decoder;
    const framed = try gpa.alloc(u8, try dec.calcSizeForSlice(str));
    defer gpa.free(framed);
    try dec.decode(framed, str);
    if (framed.len < 8) return error.InvalidHistogram;

    const cookie = std.mem.readInt(u32, framed[0..][0..4], .big);
    if ((cookie & cookie_base_mask) != v2_compressed_base) return error.InvalidCookie;
    const zlen = std.mem.readInt(u32, framed[4..][0..4], .big);
    if (8 + @as(usize, zlen) > framed.len) return error.InvalidHistogram;

    const encoded = try zlibDecompress(gpa, framed[8 .. 8 + zlen]);
    defer gpa.free(encoded);
    if (encoded.len < 40) return error.InvalidHistogram;

    const enc_cookie = std.mem.readInt(u32, encoded[0..][0..4], .big);
    if ((enc_cookie & cookie_base_mask) != v2_encoding_base) return error.InvalidCookie;
    const payload_len = std.mem.readInt(u32, encoded[4..][0..4], .big);
    const sig_figs_raw = std.mem.readInt(u32, encoded[12..][0..4], .big);
    if (sig_figs_raw < 1 or sig_figs_raw > 5) return error.InvalidHistogram;
    const sig_figs: u8 = @intCast(sig_figs_raw);
    const lowest = std.mem.readInt(u64, encoded[16..][0..8], .big);
    const highest = std.mem.readInt(u64, encoded[24..][0..8], .big);
    if (40 + @as(usize, payload_len) > encoded.len) return error.InvalidHistogram;

    var hist = try Histogram.init(gpa, lowest, highest, sig_figs);
    errdefer hist.deinit();

    // Expand the ZigZag/RLE payload back into the counts array. The payload is
    // untrusted: truncated varints error, and a hostile zero-run length only
    // saturates the (u64) index, ending the loop, rather than overflowing.
    const payload = encoded[40 .. 40 + payload_len];
    var idx: u64 = 0;
    var pos: usize = 0;
    while (pos < payload.len and idx < hist.counts_len) {
        const v = readZigZag(payload, &pos) catch return error.InvalidHistogram;
        if (v < 0) {
            idx +|= @intCast(-@as(i128, v)); // run of zeros
        } else {
            hist.counts[@intCast(idx)] = @intCast(v);
            idx += 1;
        }
    }

    // Rebuild total/min/max from the restored counts.
    hist.total_count = 0;
    hist.min_value = std.math.maxInt(u64);
    hist.max_value = 0;
    for (hist.counts, 0..) |c, j| {
        if (c == 0) continue;
        hist.total_count += c;
        const val = hist.valueFromIndex(@intCast(j));
        if (val < hist.min_value) hist.min_value = val;
        if (val > hist.max_value) hist.max_value = val;
    }
    return hist;
}

/// Append `v` as a ZigZag LEB128-64b9B varint (HdrHistogram's V2 scheme): 7 bits
/// per byte with a high continuation bit, and a full 8-bit ninth byte.
fn appendZigZag(list: *std.ArrayList(u8), gpa: Allocator, v: i64) !void {
    const uv: u64 = @bitCast(v);
    var value: u64 = (uv << 1) ^ @as(u64, @bitCast(v >> 63)); // ZigZag encode
    var emitted: usize = 0;
    while (emitted < 8) : (emitted += 1) {
        if (value >> 7 == 0) {
            try list.append(gpa, @intCast(value));
            return;
        }
        try list.append(gpa, @as(u8, @intCast(value & 0x7f)) | 0x80);
        value >>= 7;
    }
    try list.append(gpa, @intCast(value & 0xff)); // 9th byte: full 8 bits
}

/// Inverse of `appendZigZag`, advancing `pos` past the consumed bytes. Errors
/// instead of reading past the end of a truncated buffer.
fn readZigZag(bytes: []const u8, pos: *usize) error{Truncated}!i64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (pos.* >= bytes.len) return error.Truncated;
        const b = bytes[pos.*];
        pos.* += 1;
        if (i == 8) {
            value |= @as(u64, b) << 56; // 9th byte carries the top 8 bits
            break;
        }
        value |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) break;
        shift += 7;
    }
    const neg: u64 = ~(value & 1) +% 1; // 0 -> 0, 1 -> all-ones
    return @bitCast((value >> 1) ^ neg); // ZigZag decode
}

/// zlib-compress `data` (the format HdrHistogram's Java `Deflater` produces).
fn zlibCompress(gpa: Allocator, data: []const u8) ![]u8 {
    const flate = std.compress.flate;
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const scratch = try gpa.alloc(u8, data.len + data.len / 2 + 256);
    defer gpa.free(scratch);
    var out: std.Io.Writer = .fixed(scratch);
    var comp = try flate.Compress.init(&out, window, .zlib, .default);
    try comp.writer.writeAll(data);
    try comp.finish();
    return gpa.dupe(u8, out.buffered());
}

/// Inflate a zlib stream produced by `zlibCompress` (or any conformant encoder).
fn zlibDecompress(gpa: Allocator, data: []const u8) ![]u8 {
    const flate = std.compress.flate;
    var in: std.Io.Reader = .fixed(data);
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    var decomp = flate.Decompress.init(&in, .zlib, window);
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = try decomp.reader.streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

/// Cumulative-count rank corresponding to a percentile (rounded, min 1).
fn countAtPercentile(total: u64, percentile: f64) u64 {
    const p = std.math.clamp(percentile, 0.0, 100.0);
    const c: u64 = @intFromFloat(@round((p / 100.0) * @as(f64, @floatFromInt(total))));
    return @max(c, 1);
}

/// Next percentile checkpoint step: the tail is sampled progressively finer,
/// doubling the number of ticks at each "half distance" toward 100%.
fn nextPercentileStep(current: f64, ticks_per_half_distance: u32) f64 {
    const half_distance_exp = @floor(std.math.log2(100.0 / (100.0 - current))) + 1;
    const reporting_ticks = @as(f64, @floatFromInt(ticks_per_half_distance)) *
        std.math.pow(f64, 2, half_distance_exp);
    return 100.0 / reporting_ticks;
}

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

/// Independent percentile oracle over a *sorted* multiset of raw samples, using
/// HdrHistogram's rank convention: rank = round(p/100 · N), floored to at least
/// 1; the value at that percentile is the rank-th smallest sample. No bucketing
/// is involved — this is the ground truth the histogram is checked against.
fn referenceValueAtPercentile(sorted: []const u64, percentile: f64) u64 {
    std.debug.assert(sorted.len > 0);
    const n: f64 = @floatFromInt(sorted.len);
    var rank: u64 = @intFromFloat(@round((std.math.clamp(percentile, 0.0, 100.0) / 100.0) * n));
    if (rank == 0) rank = 1;
    return sorted[@intCast(rank - 1)];
}

test "valueAtPercentile matches an independent oracle across the full range" {
    // Cross-check the bucketed percentile query against a naive rank-in-a-sorted-
    // array oracle. This must match *exactly* (bucket-equivalent) for any
    // distribution: the rank-th smallest sample lies in some bucket B; every
    // sample before it maps to a bucket <= B (so cumulative(B) >= rank) and every
    // sample strictly below B's floor precedes it in sorted order (so
    // cumulative(B-1) < rank), which is precisely the bucket valueAtPercentile
    // selects. So this is deterministic, not a tolerance/statistical check.
    var h = try newDefault();
    defer h.deinit();

    const n = 100_000;
    const samples = try testing.allocator.alloc(u64, n);
    defer testing.allocator.free(samples);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();
    const max_exp = std.math.log2(@as(f64, @floatFromInt(h.highest_trackable)));
    for (samples) |*s| {
        // Log-uniform over 1µs..1h so coarse high buckets and fine low buckets
        // are both exercised, then clamp exactly as recordCount would.
        const raw: u64 = @intFromFloat(std.math.pow(f64, 2, rand.float(f64) * max_exp));
        const v = std.math.clamp(raw, h.lowest_discernible, h.highest_trackable);
        s.* = v;
        h.record(v);
    }
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));

    for ([_]f64{ 0, 0.001, 1, 10, 25, 50, 75, 90, 99, 99.9, 99.99, 100 }) |p| {
        const got = h.valueAtPercentile(p);
        const want = referenceValueAtPercentile(samples, p);
        try testing.expect(h.valuesAreEquivalent(got, want));
    }
}

test "valueAtPercentile: exact, precomputed values in the unit-resolution region" {
    // Values small enough to each occupy their own unit-resolution sub-bucket,
    // so the reported percentile value is exact — no bucket quantization. This
    // pins the rank arithmetic (round(p/100 · N), min 1) and the cumulative walk
    // to hand-verifiable numbers.
    var h = try newDefault();
    defer h.deinit();
    h.recordCount(1, 50);
    h.recordCount(2, 30);
    h.recordCount(3, 20); // N=100; cumulative: value 1 -> 50, 2 -> 80, 3 -> 100

    const cases = [_]struct { p: f64, v: u64 }{
        .{ .p = 0, .v = 1 }, // rank floored to 1
        .{ .p = 1, .v = 1 }, // rank 1
        .{ .p = 50, .v = 1 }, // rank 50 == cumulative at value 1
        .{ .p = 51, .v = 2 }, // rank 51 -> first bucket past 50
        .{ .p = 80, .v = 2 }, // rank 80 == cumulative at value 2
        .{ .p = 81, .v = 3 }, // rank 81 -> into value 3
        .{ .p = 90, .v = 3 }, // rank 90
        .{ .p = 100, .v = 3 }, // rank 100 == N
    };
    for (cases) |c| {
        try testing.expectEqual(c.v, h.valueAtPercentile(c.p));
    }
}

test "valueAtPercentile is monotonic non-decreasing in p" {
    var h = try newDefault();
    defer h.deinit();
    var prng = std.Random.DefaultPrng.init(1);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 5000) : (i += 1) h.record(rand.intRangeAtMost(u64, 1, 2_000_000));

    var p: f64 = 0;
    var prev: u64 = 0;
    while (p <= 100.0) : (p += 0.25) {
        const v = h.valueAtPercentile(p);
        try testing.expect(v >= prev);
        prev = v;
    }
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

test "setToDifference yields the interval between two cumulative snapshots" {
    var early = try newDefault(); // cumulative snapshot at t1
    defer early.deinit();
    var late = try newDefault(); // cumulative snapshot at t2 (superset)
    defer late.deinit();
    var delta = try newDefault();
    defer delta.deinit();

    // t1: 100 samples at ~1ms.
    var i: u64 = 0;
    while (i < 100) : (i += 1) early.record(1000);
    early.copyInto(&late);
    // t2 adds 50 samples at ~9ms on top of the earlier 100.
    i = 0;
    while (i < 50) : (i += 1) late.record(9000);

    delta.setToDifference(&late, &early);
    try testing.expectEqual(@as(u64, 50), delta.count());
    // The interval contains only the new (9ms) samples.
    try testing.expect(delta.valuesAreEquivalent(delta.valueAtPercentile(50), 9000));
    try testing.expect(delta.valuesAreEquivalent(delta.min(), 9000));
}

test "copyInto onto a previously-wider dst drops the stale tail" {
    // Guards the range-limited copyInto: when dst already holds a wider
    // distribution than the source, the region the source doesn't cover must
    // be zeroed, or a stale tail would survive and corrupt percentiles.
    var wide = try newDefault();
    defer wide.deinit();
    var narrow = try newDefault();
    defer narrow.deinit();
    var dst = try newDefault();
    defer dst.deinit();

    wide.record(1000);
    wide.record(500_000); // far tail → high counts index
    wide.copyInto(&dst);
    try testing.expectEqual(@as(u64, 2), dst.count());

    narrow.record(1000); // narrower: never reaches the old tail
    narrow.copyInto(&dst);

    try testing.expectEqual(@as(u64, 1), dst.count());
    try testing.expect(dst.valuesAreEquivalent(dst.max(), 1000));
    try testing.expect(dst.valueAtPercentile(100) < 2000); // old 500ms tail is gone
}

test "copyInto from an empty source clears dst" {
    var empty = try newDefault();
    defer empty.deinit();
    var dst = try newDefault();
    defer dst.deinit();

    dst.record(1234);
    empty.copyInto(&dst);
    try testing.expectEqual(@as(u64, 0), dst.count());
    try testing.expectEqual(@as(u64, 0), dst.max());
}

test "zigzag varint: explicit encodings and round-trip" {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    // ZigZag: 0->0, 1->2, -1->1, -2->3.
    try appendZigZag(&list, testing.allocator, 0);
    try appendZigZag(&list, testing.allocator, 1);
    try appendZigZag(&list, testing.allocator, -1);
    try appendZigZag(&list, testing.allocator, -2);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x02, 0x01, 0x03 }, list.items);

    // Round-trip a spread incl. multi-byte and full-width magnitudes.
    const vals = [_]i64{ 0, 1, -1, 63, 64, -64, 1000, -1000, 1 << 20, -(1 << 40), std.math.maxInt(i64), std.math.minInt(i64) };
    var enc: std.ArrayList(u8) = .empty;
    defer enc.deinit(testing.allocator);
    for (vals) |v| try appendZigZag(&enc, testing.allocator, v);
    var pos: usize = 0;
    for (vals) |v| try testing.expectEqual(v, try readZigZag(enc.items, &pos));
    try testing.expectEqual(enc.items.len, pos);

    // A truncated buffer (continuation bit on the final byte) errors.
    pos = 0;
    try testing.expectError(error.Truncated, readZigZag(&.{0x80}, &pos));
}

test "encodeBase64/decodeBase64 round-trip preserves the distribution" {
    var h = try newDefault();
    defer h.deinit();
    // Clusters with zero-runs between them and a far tail outlier.
    var i: u64 = 0;
    while (i < 500) : (i += 1) h.record(200 + i);
    while (i < 800) : (i += 1) h.record(5000 + (i - 500) * 3);
    h.record(30_000_000); // 30s outlier

    const b64 = try h.encodeBase64(testing.allocator);
    defer testing.allocator.free(b64);
    // Base64 of the compressed V2 form always begins "HIST".
    try testing.expect(std.mem.startsWith(u8, b64, "HIST"));

    var d = try decodeBase64(testing.allocator, b64);
    defer d.deinit();

    try testing.expectEqual(h.count(), d.count());
    try testing.expectEqual(h.min(), d.min());
    try testing.expectEqual(h.max(), d.max());
    // Bucket-for-bucket identical => every percentile matches.
    try testing.expectEqualSlices(u64, h.counts, d.counts);
    try testing.expectEqual(h.valueAtPercentile(99.9), d.valueAtPercentile(99.9));
}

test "empty histogram encodes and decodes" {
    var h = try newDefault();
    defer h.deinit();
    const b64 = try h.encodeBase64(testing.allocator);
    defer testing.allocator.free(b64);
    var d = try decodeBase64(testing.allocator, b64);
    defer d.deinit();
    try testing.expectEqual(@as(u64, 0), d.count());
}

test "decodeBase64 rejects a bad cookie" {
    // Valid base64 (12 zero bytes), but the leading cookie is wrong.
    try testing.expectError(error.InvalidCookie, decodeBase64(testing.allocator, "AAAAAAAAAAAAAAAA"));
}

/// Build a structurally valid compressed V2 base64 blob from raw header
/// fields and payload bytes, for exercising the decoder against inputs the
/// encoder would never produce. Caller owns the result.
fn buildTestBlob(
    gpa: Allocator,
    sig_figs: u32,
    lowest: u64,
    highest: u64,
    payload: []const u8,
) ![]u8 {
    const encoded = try gpa.alloc(u8, 40 + payload.len);
    defer gpa.free(encoded);
    std.mem.writeInt(u32, encoded[0..][0..4], encoding_cookie, .big);
    std.mem.writeInt(u32, encoded[4..][0..4], @intCast(payload.len), .big);
    std.mem.writeInt(u32, encoded[8..][0..4], 0, .big);
    std.mem.writeInt(u32, encoded[12..][0..4], sig_figs, .big);
    std.mem.writeInt(u64, encoded[16..][0..8], lowest, .big);
    std.mem.writeInt(u64, encoded[24..][0..8], highest, .big);
    std.mem.writeInt(u64, encoded[32..][0..8], @bitCast(@as(f64, 1.0)), .big);
    @memcpy(encoded[40..], payload);

    const zbytes = try zlibCompress(gpa, encoded);
    defer gpa.free(zbytes);
    const framed = try gpa.alloc(u8, 8 + zbytes.len);
    defer gpa.free(framed);
    std.mem.writeInt(u32, framed[0..][0..4], compressed_cookie, .big);
    std.mem.writeInt(u32, framed[4..][0..4], @intCast(zbytes.len), .big);
    @memcpy(framed[8..], zbytes);

    const enc = std.base64.standard.Encoder;
    const out = try gpa.alloc(u8, enc.calcSize(framed.len));
    _ = enc.encode(out, framed);
    return out;
}

test "decodeBase64 errors (never panics) on malformed blobs" {
    const gpa = testing.allocator;

    // Truncated varint payload: continuation bit set on the final byte.
    {
        const b64 = try buildTestBlob(gpa, 3, 1, 1000, &.{0x80});
        defer gpa.free(b64);
        try testing.expectError(error.InvalidHistogram, decodeBase64(gpa, b64));
    }
    // Out-of-range significant figures in the header.
    {
        const b64 = try buildTestBlob(gpa, 9, 1, 1000, &.{});
        defer gpa.free(b64);
        try testing.expectError(error.InvalidHistogram, decodeBase64(gpa, b64));
    }
    // A lowest/highest pair whose validation math would overflow.
    {
        const b64 = try buildTestBlob(gpa, 3, std.math.maxInt(u64), std.math.maxInt(u64), &.{});
        defer gpa.free(b64);
        try testing.expectError(error.InvalidArguments, decodeBase64(gpa, b64));
    }
}

test "decodeBase64 tolerates an absurd zero-run length" {
    const gpa = testing.allocator;
    // Encode a zero-run of 2^62 — vastly beyond counts_len. The index
    // saturates and the loop ends; the result is simply an empty histogram.
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    try appendZigZag(&payload, gpa, -(@as(i64, 1) << 62));
    const b64 = try buildTestBlob(gpa, 3, 1, 3_600_000_000, payload.items);
    defer gpa.free(b64);

    var d = try decodeBase64(gpa, b64);
    defer d.deinit();
    try testing.expectEqual(@as(u64, 0), d.count());
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

test "percentile distribution export is well-formed and terminates" {
    var h = try newDefault();
    defer h.deinit();
    var i: u64 = 1;
    while (i <= 1000) : (i += 1) h.record(i);

    var alloc = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    try h.writePercentileDistribution(&alloc.writer, 1.0, 5);
    const out = alloc.written();

    try testing.expect(std.mem.startsWith(u8, out, "       Value     Percentile TotalCount"));
    // First data line is the 0th percentile; the distribution ends at 1.000000.
    try testing.expect(std.mem.indexOf(u8, out, " 0.000000 ") != null);
    try testing.expect(std.mem.indexOf(u8, out, " 1.000000 ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "#[Mean") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Total count    =         1000") != null);
}

test "percentile distribution export on empty histogram" {
    var h = try newDefault();
    defer h.deinit();
    var alloc = std.Io.Writer.Allocating.init(testing.allocator);
    defer alloc.deinit();
    try h.writePercentileDistribution(&alloc.writer, 1.0, 5);
    // No data rows, but the header and footer stats must still be present.
    try testing.expect(std.mem.indexOf(u8, alloc.written(), "#[Buckets") != null);
}
