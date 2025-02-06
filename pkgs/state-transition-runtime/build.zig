const Builder = @import("std").Build;
const std = @import("std");

pub fn build(b: *Builder) void {
    const target_query = .{ .cpu_arch = .riscv32, .os_tag = .freestanding, .abi = .none, .cpu_model = .{ .explicit = &std.Target.riscv.cpu.generic_rv32 } };

    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    // add ssz
    const ssz = b.dependency("ssz.zig", .{
        .target = target,
        .optimize = optimize,
    }).module("ssz.zig");

    // add zeam-types
    const zeam_types = b.dependency("zeam-types", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-types");

    const zeam_state_transition = b.dependency("zeam-state-transition", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-state-transition");

    const mod = b.addModule("zeam-state-transition-runtime", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ssz", .module = ssz },
            .{ .name = "zeam-types", .module = zeam_types },
            .{ .name = "zeam-state-transition", .module = zeam_state_transition },
        },
    });
    _ = mod;

    // target has to be riscv5 runtime provable/verifiable on zkVMs
    const exe = b.addExecutable(.{
        .name = "zeam-state-transition-runtime",
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .optimize = optimize,
        .target = target,
    });
    // addimport to root module is even required afer declaring it in mod
    exe.root_module.addImport("ssz", ssz);
    exe.root_module.addImport("zeam-types", zeam_types);
    exe.root_module.addImport("zeam-state-transition", zeam_state_transition);
    b.installArtifact(exe);

    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/main.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("ssz", ssz);
    tests.root_module.addImport("zeam-types", zeam_types);
    tests.root_module.addImport("zeam-transition-runtime", zeam_state_transition);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
