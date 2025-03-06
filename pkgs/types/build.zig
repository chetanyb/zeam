const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ssz = b.dependency("ssz.zig", .{
        .target = target,
        .optimize = optimize,
    }).module("ssz.zig");

    // add zeam-params
    const zeam_params = b.dependency("zeam-params", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-params");


    const mod = b.addModule("zeam-types", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ssz", .module = ssz },
            .{ .name = "zeam-params", .module = zeam_params },
        },
    });
    _ = mod;

    const lib = b.addStaticLibrary(.{
        .name = "zeam-types",
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("ssz", ssz);
    tests.root_module.addImport("zeam-params", zeam_params);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
