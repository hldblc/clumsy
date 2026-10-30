const std = @import("std");
const Builder = std.build.Builder;
const Step = std.build.Step;
const debug = std.debug;
const CrossTarget = std.zig.CrossTarget;

const ClumsyArch = enum { x86, x64 };
const ClumsyConf = enum { Debug, Release, Ship };
const ClumsyWinDivertSign = enum { A, B, C };

const windows_kits_base = "C:/Program Files (x86)/Windows Kits/10/bin";

// Application sources. main.c holds the UI entry point.
const app_sources = [_][]const u8{
    "src/bandwidth.c",
    "src/cli.c",
    "src/clock.c",
    "src/config.c",
    "src/drop.c",
    "src/duplicate.c",
    "src/elevate.c",
    "src/engine.c",
    "src/fragment.c",
    "src/lag.c",
    "src/main.c",
    "src/profiles.c",
    "src/ood.c",
    "src/outage.c",
    "src/packet.c",
    "src/params.c",
    "src/procflow.c",
    "src/reset.c",
    "src/rng.c",
    "src/rules.c",
    "src/scenario.c",
    "src/tamper.c",
    "src/tcp.c",
    "src/throttle.c",
    "src/uibind.c",
    "src/utils.c",
};

// Sources exercised by the unit tests: everything except the engine and the UI.
// They link WinDivert.dll for its user-mode helpers (parsing, checksums,
// filter compilation) but never open the driver.
const test_sources = [_][]const u8{
    "tests/test_main.c",
    "tests/test_modules.c",
    "src/bandwidth.c",
    "src/clock.c",
    "src/config.c",
    "src/profiles.c",
    "src/drop.c",
    "src/duplicate.c",
    "src/fragment.c",
    "src/lag.c",
    "src/ood.c",
    "src/outage.c",
    "src/packet.c",
    "src/params.c",
    "src/procflow.c",
    "src/reset.c",
    "src/rng.c",
    "src/rules.c",
    "src/scenario.c",
    "src/tamper.c",
    "src/tcp.c",
    "src/throttle.c",
    "src/utils.c",
};

fn versionGreater(a: [4]u32, b: [4]u32) bool {
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return false;
}

// Find the newest installed Windows 10/11 SDK that ships rc.exe for the given arch.
fn detectWindowsKitBinRoot(b: *Builder, arch_tag: []const u8) ?[]const u8 {
    var dir = std.fs.openDirAbsolute(windows_kits_base, .{ .iterate = true }) catch return null;
    defer dir.close();
    var best: ?[]const u8 = null;
    var best_ver: [4]u32 = .{ 0, 0, 0, 0 };
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .Directory) continue;
        var ver: [4]u32 = .{ 0, 0, 0, 0 };
        var parts = std.mem.split(u8, entry.name, ".");
        var i: usize = 0;
        var ok = true;
        while (parts.next()) |p| : (i += 1) {
            if (i >= 4) {
                ok = false;
                break;
            }
            ver[i] = std.fmt.parseInt(u32, p, 10) catch {
                ok = false;
                break;
            };
        }
        if (!ok or i != 4) continue;
        const rc_path = b.fmt("{s}/{s}/{s}/rc.exe", .{ windows_kits_base, entry.name, arch_tag });
        std.fs.accessAbsolute(rc_path, .{}) catch continue;
        if (versionGreater(ver, best_ver)) {
            best_ver = ver;
            best = b.fmt("{s}/{s}", .{ windows_kits_base, entry.name });
        }
    }
    return best;
}

pub fn build(b: *Builder) void {
    const arch = b.option(ClumsyArch, "arch", "x86, x64") orelse .x64;
    const conf = b.option(ClumsyConf, "conf", "Debug, Release, Ship") orelse .Debug;
    const windivert_sign = b.option(ClumsyWinDivertSign, "sign", "A, B, C") orelse .A;
    const arch_tag = @tagName(arch);
    const conf_tag = @tagName(conf);
    const sign_tag = @tagName(windivert_sign);

    // SDK bin root: explicit option > WindowsSdkVerBinPath (set by VS developer prompts) > newest installed.
    var windows_kit_bin_root: []const u8 = undefined;
    if (b.option([]const u8, "windows_kit_bin_root", "Windows SDK bin root, e.g. C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0")) |opt| {
        windows_kit_bin_root = opt;
    } else if (std.process.getEnvVarOwned(b.allocator, "WindowsSdkVerBinPath") catch null) |env| {
        windows_kit_bin_root = env;
    } else if (detectWindowsKitBinRoot(b, arch_tag)) |found| {
        windows_kit_bin_root = found;
    } else {
        @panic("no Windows SDK with rc.exe found under " ++ windows_kits_base ++ "; install a Windows 10/11 SDK or pass -Dwindows_kit_bin_root=...");
    }

    const windivert_dir = b.fmt("WinDivert-2.2.0-{s}", .{sign_tag});

    debug.print("- arch: {s}, conf: {s}, sign: {s}\n", .{ arch_tag, conf_tag, sign_tag });
    debug.print("- windows_kit_bin_root: {s}\n", .{windows_kit_bin_root});
    _ = std.fs.realpathAlloc(b.allocator, windows_kit_bin_root) catch @panic("windows_kit_bin_root not found");

    const prefix = b.fmt("{s}_{s}_{s}", .{ arch_tag, conf_tag, sign_tag });
    b.exe_dir = b.fmt("{s}/{s}", .{ b.install_path, prefix });

    debug.print("- out: {s}\n", .{b.exe_dir});

    const tmp_path = b.fmt("tmp/{s}", .{prefix});
    b.makePath(tmp_path) catch @panic("unable to create tmp directory");

    b.installFile(b.fmt("external/{s}/{s}/WinDivert.dll", .{ windivert_dir, arch_tag }), b.fmt("{s}/WinDivert.dll", .{prefix}));
    switch (arch) {
        .x64 => b.installFile(b.fmt("external/{s}/{s}/WinDivert64.sys", .{ windivert_dir, arch_tag }), b.fmt("{s}/WinDivert64.sys", .{prefix})),
        .x86 => b.installFile(b.fmt("external/{s}/{s}/WinDivert32.sys", .{ windivert_dir, arch_tag }), b.fmt("{s}/WinDivert32.sys", .{prefix})),
    }

    b.installFile("etc/config.txt", b.fmt("{s}/config.txt", .{prefix}));
    if (conf == .Ship)
        b.installFile("LICENSE", b.fmt("{s}/License.txt", .{prefix}));

    const res_obj_path = b.fmt("{s}/clumsy_res.obj", .{tmp_path});

    const rc_exe = b.findProgram(&.{
        "rc",
    }, &.{
        b.pathJoin(&.{ windows_kit_bin_root, arch_tag }),
    }) catch @panic("unable to find rc.exe, check your windows_kit_bin_root");

    const archFlag = switch (arch) {
        .x86 => "X86",
        .x64 => "X64",
    };
    const cmd = b.addSystemCommand(&.{
        rc_exe,
        "/nologo",
        "/d",
        "NDEBUG",
        "/d",
        archFlag,
        "/r",
        "/fo",
        res_obj_path,
        "etc/clumsy.rc",
    });

    const exe = b.addExecutable("clumsy", null);

    switch (conf) {
        .Debug => {
            exe.setBuildMode(.Debug);
            exe.subsystem = .Console;
        },
        .Release => {
            exe.setBuildMode(.ReleaseSafe);
            exe.subsystem = .Windows;
        },
        .Ship => {
            exe.setBuildMode(.ReleaseFast);
            exe.subsystem = .Windows;
        },
    }
    const triple = switch (arch) {
        .x64 => "x86_64-windows-gnu",
        .x86 => "i386-windows-gnu",
    };

    const target = CrossTarget.parse(.{
        .arch_os_abi = triple,
    }) catch unreachable;
    exe.setTarget(target);

    exe.step.dependOn(&cmd.step);
    exe.addObjectFile(res_obj_path);
    const cflags: []const []const u8 = switch (conf) {
        .Debug => &[_][]const u8{ "-D_DEBUG", "-Wall", "-Wno-unused-function" },
        else => &[_][]const u8{ "-DNDEBUG", "-Wall", "-Wno-unused-function" },
    };
    for (app_sources) |src| {
        exe.addCSourceFile(src, cflags);
    }

    if (arch == .x86)
        exe.addCSourceFile("etc/chkstk.s", &.{""});

    exe.addIncludeDir(b.fmt("external/{s}/include", .{windivert_dir}));

    const iupLib = switch (arch) {
        .x64 => "external/iup-3.30_Win64_mingw6_lib",
        .x86 => "external/iup-3.30_Win32_mingw6_lib",
    };

    exe.addIncludeDir(b.pathJoin(&.{ iupLib, "include" }));
    exe.addCSourceFile(b.pathJoin(&.{ iupLib, "libiup.a" }), &.{""});

    exe.linkLibC();
    exe.addLibPath(b.fmt("external/{s}/{s}", .{ windivert_dir, arch_tag }));
    exe.linkSystemLibrary("WinDivert");
    exe.linkSystemLibrary("comctl32");
    exe.linkSystemLibrary("Winmm");
    exe.linkSystemLibrary("ws2_32");
    exe.linkSystemLibrary("kernel32");
    exe.linkSystemLibrary("gdi32");
    exe.linkSystemLibrary("comdlg32");
    exe.linkSystemLibrary("uuid");
    exe.linkSystemLibrary("ole32");
    exe.linkSystemLibrary("psapi");
    exe.linkSystemLibrary("advapi32");
    exe.linkSystemLibrary("shell32");

    const exe_install_step = b.addInstallArtifact(exe);
    if (conf == .Ship) {
        const remove_pdb_step = RemoveOutFile.create(b, "clumsy.pdb");
        remove_pdb_step.step.dependOn(&exe_install_step.step);
        b.getInstallStep().dependOn(&remove_pdb_step.step);
    } else {
        b.getInstallStep().dependOn(&exe_install_step.step);
    }

    const clean_all = b.step("clean", "purge zig-cache and zig-out");
    clean_all.dependOn(&b.addRemoveDirTree(b.install_path).step);

    // Unit tests for the driver-free code: `zig build test`
    const test_exe = b.addExecutable("clumsy_test", null);
    test_exe.setBuildMode(.Debug);
    test_exe.setTarget(target);
    for (test_sources) |src| {
        test_exe.addCSourceFile(src, &.{""});
    }
    test_exe.addIncludeDir("src");
    test_exe.addIncludeDir(b.fmt("external/{s}/include", .{windivert_dir}));
    test_exe.addLibPath(b.fmt("external/{s}/{s}", .{ windivert_dir, arch_tag }));
    test_exe.linkSystemLibrary("WinDivert");
    test_exe.linkSystemLibrary("Winmm");
    test_exe.linkSystemLibrary("psapi");
    test_exe.linkSystemLibrary("advapi32");
    test_exe.linkLibC();
    const run_tests = test_exe.run();
    run_tests.addPathDir(b.pathFromRoot(b.fmt("external/{s}/{s}", .{ windivert_dir, arch_tag })));
    const test_step = b.step("test", "build and run the unit tests");
    test_step.dependOn(&run_tests.step);
}

pub const RemoveOutFile = struct {
    step: Step,
    builder: *Builder,
    rel_path: []const u8,

    pub fn create(builder: *Builder, rel_path: []const u8) *@This() {
        const self = builder.allocator.create(@This()) catch unreachable;
        self.* = .{
            .step = Step.init(.custom, builder.fmt("RemoveOutFile {s}", .{rel_path}), builder.allocator, make),
            .builder = builder,
            .rel_path = rel_path,
        };
        return self;
    }

    fn make(step: *Step) anyerror!void {
        const self = @fieldParentPtr(RemoveOutFile, "step", step);
        const out_dir = try std.fs.openDirAbsolute(self.builder.exe_dir, .{});
        try out_dir.deleteFile(self.rel_path);
    }
};
