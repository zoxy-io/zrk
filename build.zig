const std = @import("std");

const manifest = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zio = b.dependency("zio", .{
        .target = target,
        .optimize = optimize,
    });

    // Single-source the version from build.zig.zon: cli.zig imports it via
    // this options module, so --version and JSON reports can't drift from the
    // package version (v0.2.0 shipped binaries that still said 0.1.0).
    const build_info = b.addOptions();
    build_info.addOption([]const u8, "version", manifest.version);
    const build_info_mod = build_info.createModule();

    // The reusable library module: embedders `@import("zrk")` this.
    const mod = b.addModule("zrk", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_info", .module = build_info_mod },
        },
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
            },
        }),
    });
    b.installArtifact(exe);

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

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
