const std = @import("std");

const manifest = @import("build.zig.zon");
const luajit_build = @import("build/luajit.zig");

/// Refuse to build the vendored C against a libc Zig could not find.
///
/// libcrypto is C, and for a native target Zig locates the host's libc headers
/// and CRT objects by running the system C compiler
/// (`cc -E -Wp,-v -xc /dev/null`). With no `cc` on PATH that detection fails —
/// and the build DOES NOT. It reports its steps as succeeding and emits
/// binaries that die in `_start`, before `main`, on a call through a null
/// pointer, so a whole test run becomes one SIGSEGV with no output. That reads
/// like a bug in the code; it is a missing compiler.
///
/// Returns a step that fails with that explanation, or null when the machine
/// is fine. Callers hang it off the artifacts that will actually be RUN — a
/// mis-built libcrypto cannot hurt `zig build check`, which produces an object
/// and executes nothing, and that step exists precisely to work where a full
/// build cannot.
fn nativeLibcGuard(b: *std.Build, target: std.Build.ResolvedTarget) ?*std.Build.Step {
    // Only native builds probe this machine; a cross target uses the libc Zig
    // ships for it.
    if (!target.query.isNative()) return null;
    // An explicit libc description answers the same question `cc` would.
    if (b.graph.environ_map.get("ZIG_LIBC") != null) return null;
    if (b.findProgram(&.{ "cc", "gcc", "clang" }, &.{})) |_| return null else |_| {}

    return &b.addFail(
        \\no C compiler on PATH, so Zig cannot detect this machine's libc.
        \\
        \\libcrypto is built from vendored C, and without a detected libc that
        \\link silently produces binaries which segfault in _start before main
        \\— a whole test run dying as one SIGSEGV with no output.
        \\
        \\Build inside the pinned toolchain: `nix develop`, or `direnv allow`
        \\once and let it load. `zig build check` type-checks without any of
        \\this, cross-compiling (-Dtarget=...) needs none of it, and ZIG_LIBC
        \\overrides the check if you know better.
    ).step;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zio = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
    });

    // The HTTP/2 frame codec and HPACK, shared with zoxy. `assertions = false`
    // is deliberate and is the whole reason that option exists: h2's checks are
    // on by default because zoxy points it at the open internet, and zrk is a
    // latency-measuring tool whose pitch is not injecting client-side noise
    // into the measurement. See zoxy-io/h2#6.
    const h2 = b.dependency("h2", .{
        .target = target,
        .optimize = optimize,
        .assertions = false,
    });

    // The HTTP/1.1 response parser (see build.zig.zon for why only the parser).
    const zurl = b.dependency("zurl", .{
        .target = target,
        .optimize = optimize,
    });

    // Single-source the version from build.zig.zon: cli.zig imports it via
    // this options module, so --version and JSON reports can't drift from the
    // package version (v0.2.0 shipped binaries that still said 0.1.0).
    const build_info = b.addOptions();
    build_info.addOption([]const u8, "version", manifest.version);
    const build_info_mod = build_info.createModule();

    // TLS 1.3, and the libcrypto under it.
    //
    // One dependency, one module. zssl links its own Zig-built libcrypto into
    // the module it exports, so everything the ztls pin needed here is gone:
    // the `libcrypto.a` alias written so `linkSystemLibrary("crypto")` could
    // find an archive by that name, the search path pointed at it, the include
    // path pushed onto ztls's module, and the `crypto-pkg-config` opt-out that
    // kept a system OpenSSL's headers from colliding with ours on machines
    // where pkg-config knew about it. Cross-compilation still works for the
    // same reason it did before — nothing is resolved from the host — but it
    // is now zssl's build that says so.
    //
    // `sanitize_c = .off` for the vendored C moved there with it, which is
    // where it belongs: it is a property of building OpenSSL, not of building
    // zrk. See zssl's build.zig, and zoxy-io/zoxy#283 for what shipped without
    // it.
    const zssl = b.dependency("zssl", .{
        .target = target,
        .optimize = optimize,
    });
    const zssl_module = zssl.module("zssl");

    // QUIC, QPACK and HTTP/3. `assertions = false` for the same reason h2 gets
    // it above: h3's checks are on by default because zoxy points that code at
    // the open internet, and zrk is a latency-measuring tool whose pitch is not
    // injecting client-side noise into the measurement.
    const h3 = b.dependency("h3", .{
        .target = target,
        .optimize = optimize,
        .assertions = false,
    });

    // LuaJIT, for `--script`. Built from source like libcrypto, and statically
    // linked like it, so the release binaries stay single files; see
    // build/luajit.zig for how it cross-compiles.
    const luajit = luajit_build.build(b, target, optimize, b.dependency("luajit", .{}));

    // Hung off each runnable artifact below rather than off the dependency,
    // so `zig build check` keeps working without a C toolchain.
    const libc_guard = nativeLibcGuard(b, target);

    // The reusable library module: embedders `@import("zrk")` this.
    const mod = b.addModule("zrk", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_info", .module = build_info_mod },
            .{ .name = "zio", .module = zio.module("zio") },
            .{ .name = "h2", .module = h2.module("h2") },
            .{ .name = "zurl", .module = zurl.module("zurl") },
            .{ .name = "zssl", .module = zssl_module },
            .{ .name = "h3", .module = h3.module("h3") },
        },
    });
    // `cli.zig` checks the README's usage block against the real help text.
    // `@embedFile` cannot escape the module root, so the file arrives as a named
    // import instead.
    //
    // Added to both modules, because `main.zig` reaches `cli.zig` by file
    // import rather than through the `zrk` module — so it is compiled into the
    // executable's root module too, and an import given to only one of them is
    // missing from the other. Every other dependency here is already listed
    // twice for exactly that reason; this one was not, and CI caught it.
    mod.addAnonymousImport("readme", .{ .root_source_file = b.path("README.md") });
    mod.linkLibrary(luajit);

    // A standing check that the dependency options above actually applied.
    const pin_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/h2_pin_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "h2", .module = h2.module("h2") }},
        }),
    });

    // The CLI executable.
    const exe = b.addExecutable(.{
        .name = "zrk",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zrk", .module = mod },
                .{ .name = "build_info", .module = build_info_mod },
                .{ .name = "zio", .module = zio.module("zio") },
                .{ .name = "h2", .module = h2.module("h2") },
                .{ .name = "zurl", .module = zurl.module("zurl") },
                .{ .name = "zssl", .module = zssl_module },
                .{ .name = "h3", .module = h3.module("h3") },
            },
        }),
    });
    exe.root_module.addAnonymousImport("readme", .{ .root_source_file = b.path("README.md") });
    // Linked into both for the reason `readme` is imported into both:
    // `main.zig` compiles `script.zig` into this module by file import.
    exe.root_module.linkLibrary(luajit);
    if (libc_guard) |guard| exe.step.dependOn(guard);
    b.installArtifact(exe);

    // Type-check without linking.
    //
    // Does not cover `test` blocks: an object has no test runner, so their
    // bodies are never analysed. An import used only inside a test passes this
    // and fails `zig build test` — which is exactly how the `readme` import
    // above reached CI.
    //
    // `zig build` needs libcrypto, which means compiling OpenSSL from source —
    // minutes, and impossible in a sandbox that cannot reach the hosts its
    // package pulls from. An object needs no libraries, so this answers "does
    // the Zig compile" in seconds, which is the question most edits actually
    // raise.
    const check = b.addObject(.{
        .name = "zrk-check",
        .root_module = exe.root_module,
    });
    b.step("check", "Type-check without linking (no libcrypto needed)")
        .dependOn(&check.step);

    // `zig build run -- <args>` runs the installed binary.
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // `zig build bench`: the histogram publish/aggregate microbenchmark.
    // Always ReleaseFast so the numbers mean something.
    const bench_exe = b.addExecutable(.{
        .name = "zrk-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zrk", .module = mod },
            },
        }),
    });
    const bench_step = b.step("bench", "Run the histogram publish/aggregate benchmark");
    const run_bench = b.addRunArtifact(bench_exe);
    bench_step.dependOn(&run_bench.step);

    // `zig build test`: a test binary per module (a test executable covers
    // exactly one module, hence two of them).
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    if (libc_guard) |guard| {
        mod_tests.step.dependOn(guard);
        exe_tests.step.dependOn(guard);
        pin_tests.step.dependOn(guard);
        bench_exe.step.dependOn(guard);
    }

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&b.addRunArtifact(pin_tests).step);
}
