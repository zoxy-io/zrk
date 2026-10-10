//! Build LuaJIT from its source tarball, for any target zrk ships.
//!
//! Adapted from ziglua's `build/luajit.zig` (MIT, Copyright (c) 2022 Nathan
//! Craddock), rather than depended on: ziglua's main branch tracks Zig master,
//! and its translate-c step cannot find a native libc's headers on NixOS. zrk
//! needs only the build half, and declares the frozen Lua 5.1 C API by hand in
//! `src/lua.zig`.
//!
//! LuaJIT's VM is assembly that LuaJIT generates for itself. `minilua` (a
//! bundled Lua 5.1) runs DynASM over `vm_<arch>.dasc` to produce
//! `buildvm_arch.h`; `buildvm`, built against that header, then emits the VM
//! (`lj_vm.S`) and the tables the C sources include. Both tools run on the
//! *host*, and are told the *target* explicitly, which is what makes this
//! cross-compile: the release matrix builds macOS VMs on a Linux runner.
//!
//! Two departures from ziglua, both for zrk's static release binaries:
//!
//! - `LUAJIT_NO_UNWIND`. ziglua links a system `libunwind` for LuaJIT's
//!   external unwinding, which a static musl binary and a macOS cross build do
//!   not have. With it off, a Lua error unwinds LuaJIT's own frames and skips
//!   any C frames in between like a `longjmp` — the mode iOS builds use. zrk
//!   calls Lua only through `lua_pcall`, and its C functions hold nothing that
//!   needs unwinding, so nothing is lost.
//! - The target OS is passed to `buildvm` (`LUAJIT_OS`), as LuaJIT's Makefile
//!   does for cross builds. Without it `buildvm` takes the *host's* OS from its
//!   own compiler's macros, and a Linux runner would generate a Linux-flavoured
//!   VM for macOS.

const std = @import("std");
const Build = std.Build;

pub fn build(
    b: *Build,
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    upstream: *Build.Dependency,
) *Build.Step.Compile {
    const arch = target.result.cpu.arch;
    const os = target.result.os.tag;

    const lib_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .unwind_tables = .sync,
        // LuaJIT relies on behaviour UBSan traps on (unaligned loads, signed
        // overflow in the hash functions), and is not ours to fix.
        .sanitize_c = .off,
    });
    const library = b.addLibrary(.{
        .name = "luajit",
        .root_module = lib_module,
        .linkage = .static,
    });

    // DynASM runs under minilua, a host executable.
    const minilua = b.addExecutable(.{
        .name = "minilua",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
            .sanitize_c = .off,
        }),
    });
    minilua.root_module.addCSourceFile(.{ .file = upstream.path("src/host/minilua.c") });
    minilua.root_module.linkSystemLibrary("m", .{});

    const dynasm = b.addRunArtifact(minilua);
    dynasm.addFileArg(upstream.path("dynasm/dynasm.lua"));
    dynasm.addArgs(&.{ "-D", if (arch.endian() == .little) "ENDIAN_LE" else "ENDIAN_BE" });
    if (target.result.ptrBitWidth() == 64) dynasm.addArgs(&.{ "-D", "P64" });
    dynasm.addArgs(&.{ "-D", "JIT", "-D", "FFI", "-D", "FPU", "-D", "HFABI", "-D", "NO_UNWIND" });
    if (arch == .aarch64) dynasm.addArgs(&.{ "-D", "DUALNUM" });
    dynasm.addArg("-o");
    const buildvm_arch_h = dynasm.addOutputFileArg("buildvm_arch.h");
    dynasm.addFileArg(upstream.path(switch (arch) {
        .x86_64 => "src/vm_x64.dasc",
        .aarch64 => "src/vm_arm64.dasc",
        // zrk's release matrix is these two; anything else is a port, not a
        // flag to add here.
        else => @panic("zrk builds LuaJIT for x86_64 and aarch64 only"),
    }));

    const genversion = b.addRunArtifact(minilua);
    genversion.addFileArg(upstream.path("src/host/genversion.lua"));
    genversion.addFileArg(upstream.path("src/luajit_rolling.h"));
    genversion.addFileArg(upstream.path(".relver"));
    const luajit_h = genversion.addOutputFileArg("luajit.h");

    // Flags that describe the TARGET to tools that run on the host.
    const target_flags: []const []const u8 = &.{
        switch (arch) {
            .x86_64 => "-DLUAJIT_TARGET=LUAJIT_ARCH_X64",
            .aarch64 => "-DLUAJIT_TARGET=LUAJIT_ARCH_arm64",
            else => unreachable,
        },
        switch (os) {
            .linux => "-DLUAJIT_OS=LUAJIT_OS_LINUX",
            .macos => "-DLUAJIT_OS=LUAJIT_OS_OSX",
            else => "-DLUAJIT_OS=LUAJIT_OS_POSIX",
        },
        "-DLJ_ARCH_HASFPU=1",
        "-DLJ_ABI_SOFTFP=0",
        "-DLUAJIT_NO_UNWIND",
    };

    const buildvm = b.addExecutable(.{
        .name = "buildvm",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
            .sanitize_c = .off,
        }),
    });
    buildvm.root_module.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = &.{
            "src/host/buildvm_asm.c",
            "src/host/buildvm_fold.c",
            "src/host/buildvm_lib.c",
            "src/host/buildvm_peobj.c",
            "src/host/buildvm.c",
        },
        .flags = target_flags,
    });
    buildvm.root_module.addIncludePath(upstream.path("src"));
    buildvm.root_module.addIncludePath(upstream.path("src/host"));
    buildvm.root_module.addIncludePath(buildvm_arch_h.dirname());
    buildvm.root_module.addIncludePath(luajit_h.dirname());

    // The tables the VM's C sources include, each generated from the library
    // sources' annotations.
    inline for (.{ "bcdef", "ffdef", "libdef", "recdef" }) |mode| {
        const run = b.addRunArtifact(buildvm);
        run.addArgs(&.{ "-m", mode, "-o" });
        const header = run.addOutputFileArg("lj_" ++ mode ++ ".h");
        for (lib_sources) |file| run.addFileArg(upstream.path(file));
        lib_module.addIncludePath(header.dirname());
    }
    const folddef = b.addRunArtifact(buildvm);
    folddef.addArgs(&.{ "-m", "folddef", "-o" });
    const folddef_h = folddef.addOutputFileArg("lj_folddef.h");
    folddef.addFileArg(upstream.path("src/lj_opt_fold.c"));
    lib_module.addIncludePath(folddef_h.dirname());

    // The VM itself.
    const vm = b.addRunArtifact(buildvm);
    vm.addArgs(&.{ "-m", if (os.isDarwin()) "machasm" else "elfasm", "-o" });
    lib_module.addAssemblyFile(vm.addOutputFileArg("lj_vm.S"));

    lib_module.addIncludePath(upstream.path("src"));
    lib_module.addIncludePath(luajit_h.dirname());
    lib_module.addCMacro("LUAJIT_NO_UNWIND", "");
    lib_module.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = &(lib_sources ++ vm_sources),
        .flags = &.{"-fno-strict-aliasing"},
    });

    return library;
}

/// The standard libraries. Also what `buildvm` scans for the fast-function,
/// library and recording tables, so the order is LuaJIT's Makefile's.
const lib_sources = [_][]const u8{
    "src/lib_base.c",
    "src/lib_math.c",
    "src/lib_bit.c",
    "src/lib_string.c",
    "src/lib_table.c",
    "src/lib_io.c",
    "src/lib_os.c",
    "src/lib_package.c",
    "src/lib_debug.c",
    "src/lib_jit.c",
    "src/lib_ffi.c",
    "src/lib_buffer.c",
};

const vm_sources = [_][]const u8{
    "src/lj_assert.c",
    "src/lj_gc.c",
    "src/lj_err.c",
    "src/lj_char.c",
    "src/lj_bc.c",
    "src/lj_obj.c",
    "src/lj_buf.c",
    "src/lj_str.c",
    "src/lj_tab.c",
    "src/lj_func.c",
    "src/lj_udata.c",
    "src/lj_meta.c",
    "src/lj_debug.c",
    "src/lj_prng.c",
    "src/lj_state.c",
    "src/lj_dispatch.c",
    "src/lj_vmevent.c",
    "src/lj_vmmath.c",
    "src/lj_strscan.c",
    "src/lj_strfmt.c",
    "src/lj_strfmt_num.c",
    "src/lj_serialize.c",
    "src/lj_api.c",
    "src/lj_profile.c",
    "src/lj_lex.c",
    "src/lj_parse.c",
    "src/lj_bcread.c",
    "src/lj_bcwrite.c",
    "src/lj_load.c",
    "src/lj_ir.c",
    "src/lj_opt_mem.c",
    "src/lj_opt_fold.c",
    "src/lj_opt_narrow.c",
    "src/lj_opt_dce.c",
    "src/lj_opt_loop.c",
    "src/lj_opt_split.c",
    "src/lj_opt_sink.c",
    "src/lj_mcode.c",
    "src/lj_snap.c",
    "src/lj_record.c",
    "src/lj_crecord.c",
    "src/lj_ffrecord.c",
    "src/lj_asm.c",
    "src/lj_trace.c",
    "src/lj_gdbjit.c",
    "src/lj_ctype.c",
    "src/lj_cdata.c",
    "src/lj_cconv.c",
    "src/lj_ccall.c",
    "src/lj_ccallback.c",
    "src/lj_carith.c",
    "src/lj_clib.c",
    "src/lj_cparse.c",
    "src/lj_lib.c",
    "src/lj_alloc.c",
    "src/lib_aux.c",
    "src/lib_init.c",
};
