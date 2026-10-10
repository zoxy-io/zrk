# Library usage

zrk's core is a reusable Zig module, not just a CLI: `runner.run` drives the
same load-test loop the CLI does (see `src/runner.zig`) and returns a typed
`Report`, with an optional progress callback for the periodic snapshots the
dashboard renders. The lower-level pieces it's built from (`hdr`, `cli`,
`http`, `connection`, `stats`, `report`, `tls`) are exported too.

Add it as a dependency:

```sh
zig fetch --save git+https://github.com/zoxy-io/zrk#<commit-or-tag>
```

```zig
// build.zig
const zrk_dep = b.dependency("zrk", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("zrk", zrk_dep.module("zrk"));
```

```zig
const std = @import("std");
const zio = @import("zio");
const zrk = @import("zrk");

var rt = try zio.Runtime.init(allocator, .{});
defer rt.deinit();
const io = rt.io();

var arena = std.heap.ArenaAllocator.init(allocator);
defer arena.deinit();

var cfg: zrk.cli.Config = .{
    .connections = 50,
    .rate = 1000,
    .duration_ns = 10 * std.time.ns_per_s,
    .interval_ns = 1 * std.time.ns_per_s,
    .url = try zrk.cli.parseUrl("http://127.0.0.1:8080/"),
};
const report = try zrk.runner.run(arena.allocator(), io, &cfg, 0, null, null, null);
```

`Report` carries the merged `snapshot` (counters plus the
coordinated-omission-corrected histogram), `elapsed_s`, `launched`, and
`interrupted`. It also carries `end_rate` / `end_bytes_per_sec` /
`end_window_s` / `end_window_at_s`: throughput over the run's *last*
`--interval` and where that window sat, rather than
`completed / elapsed_s`. Under a ramp those differ by design — the whole-run
average is the midpoint of the offered range and reports ~550 for `-R100:1000`
no matter what the target did at the top of it, while `end_rate` is the rate it
was actually serving when the run ended. A run shorter than one interval has no
window of its own and falls back to the average.

`report.writeJson` takes those as a `report.Run` alongside the snapshot, and
reports `end_rate` as the summary's `achieved_rate` whenever `cfg.rate_end` is
set (see [output.md](output.md)); an embedder computing its own headline number
should make the same choice. Leaving `end_window_s` at 0 says "no window
measured", and the whole run stands in for it.

## Generating requests

By default every send replays one request, built once at startup from
`cfg.method`, `cfg.headers`, `cfg.body` and the URL's path. Set `cfg.workload`
to generate each request instead — a different path, header or body per send,
which is what a benchmark needs once a server could answer from a cache keyed
on the request bytes.

```zig
const Numbered = struct {
    const State = struct { connection: u32, path: [48]u8 = undefined };

    fn workload(self: *Numbered) zrk.Workload {
        return .{ .ptr = self, .vtable = &.{ .open = open, .next = next, .close = close } };
    }

    // Once per connection. What it returns is that connection's alone.
    fn open(_: *anyopaque, connection: u32) anyerror!*anyopaque {
        const s = try std.heap.smp_allocator.create(State);
        s.* = .{ .connection = connection };
        return s;
    }

    // Once per send. `seq` is the connection's position in its schedule,
    // counting from 0 on every connection, so the connection's index goes in
    // the path too: every request names a different user.
    fn next(_: *anyopaque, state: *anyopaque, seq: u64) anyerror!zrk.workload.Request {
        const s: *State = @ptrCast(@alignCast(state));
        return .{ .target = try std.fmt.bufPrint(&s.path, "/user/{d}-{d}", .{ s.connection, seq }) };
    }

    fn close(_: *anyopaque, state: *anyopaque) void {
        std.heap.smp_allocator.destroy(@as(*State, @ptrCast(@alignCast(state))));
    }
};

var numbered: Numbered = .{};
cfg.workload = numbered.workload();
const report = try zrk.runner.run(arena.allocator(), io, &cfg, 0, null, null, null);
```

A `Request` is a method, a target, headers and a body. zrk encodes it for
whichever transport the run speaks, through the same code that builds the fixed
request, so it gets the same defaults (`Host` or `:authority`, `User-Agent`,
`Connection`, `Content-Length`, each skipped when the request names it) and the
same validation. The scheme, host and port stay the run's, because they decide
which connection a request travels on.

What the contract guarantees, and what it asks of an implementation:

- **Threads.** Connections call concurrently from different threads, and the
  runtime moves a connection between threads as it steals work. State behind
  `ptr` is shared and is yours to synchronise; state returned by `open` is
  touched by one connection only, one call at a time.
- **Lifetimes.** Slices in a returned `Request` must stay valid until the next
  `next` or `close` on the same connection state.
- **Timing.** `next` runs ahead of the send where the schedule allows, before
  the pacing wait, and before the clock read a closed-loop latency starts
  from, so the generator's cost is not charged to the server. A connection
  that is already behind schedule has no wait to hide it in, and the cost then
  shows as schedule lag.
- **Numbering.** `seq` counts from 0 per connection. It skips when
  `--deadline` sheds a send, and repeats when an HTTP/2 or HTTP/3 peer
  declines a request unprocessed and zrk sends it again. A workload that
  derives its request from `seq` resends the same request.
- **Failure.** An error from `open`, `next` or `response` stops every
  connection, and `runner.run` returns that error instead of a `Report`.
- **Responses.** `response` is optional. Leave it null and zrk keeps no
  response header or body, as without a workload. Set it, and it receives
  every completed response's status, header fields and body, after the
  latency is recorded. On a multiplexed HTTP/2 connection it runs on the
  receiver while the sender may be in `next` on the same connection state,
  so state the two share needs a lock.

`zrk.script.Script` is the `--script` implementation, built on this
interface: `Script.load` checks a wrk script, and `apply` puts it into effect
on a `Config`, as its fixed request or as its workload.

`zrk.workload.Fixed` is the fixed request as a `Workload`. A run with no
workload does not go through it; it replays prebuilt bytes, and its throughput
is unaffected by any of this.

## Which `std.Io` to pass

`runner.run` takes a `std.Io` instance as a plain parameter, so any conforming
`std.Io` implementation can be passed in. In practice, zrk dials each
connection with a connect timeout (`address.connect(io, .{ .timeout = ... })`),
and Zig 0.16's default `std.Io.Threaded` backend hasn't implemented
connect-with-timeout yet (it's a TODO panic there). [zio](https://github.com/lalinsky/zio)
does implement it, which is why zio is a hard dependency of the `zrk` package
itself (see `build.zig.zon`) and the runtime zrk's own CLI constructs at
startup (`src/main.zig`). Embedders should do the same — construct a
`zio.Runtime` and pass its `.io()` to `runner.run` — unless you bring another
`std.Io` implementation that you've verified covers what zrk needs.
