const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
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
    // add state transition
    const zeam_state_transition = b.dependency("zeam-state-transition", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-state-transition");
    // add state transition manager
    const zeam_state_transition_manager = b.dependency("zeam-state-transition-manager", .{
        .target = target,
        .optimize = optimize,
    }).module("zeam-state-transition-manager");

    const mod = b.addModule("zeam-node", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/manager.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ssz", .module = ssz },
            .{ .name = "zeam-types", .module = zeam_types },
            .{ .name = "zeam-state-transition", .module = zeam_state_transition },
            .{ .name = "zeam-state-transition-manager", .module = zeam_state_transition_manager },
        },
    });
    _ = mod;

    const lib = b.addStaticLibrary(.{
        .name = "zeam-beam-chain",
        .root_source_file = .{ .cwd_relative = "src/chain.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/chain.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests.root_module.addImport("ssz", ssz);
    tests.root_module.addImport("zeam-types", zeam_types);
    tests.root_module.addImport("zeam-state-transition", zeam_state_transition);
    tests.root_module.addImport("zeam-state-transition-manager", zeam_state_transition);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
