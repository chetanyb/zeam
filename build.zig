const Builder = @import("std").Build;

// TODO build test monorepo
pub fn build(b: *Builder) void {
    const test_step = b.step("test", "Run unit tests");
    _ = test_step;
}
