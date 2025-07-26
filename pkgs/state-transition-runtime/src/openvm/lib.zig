pub const io = @import("./io.zig");
const std = @import("std");

pub fn get_input(_: std.mem.Allocator) []const u8 {
    @panic("not implemented");
}

pub fn halt(exit_code: u32) noreturn {
    asm volatile (".insn i 0x0b, 0, x0, x0, %[exit_code]"
        :
        : [exit_code] "i" (@as(u8, @truncate(exit_code))),
    );
    unreachable;
}

pub fn keccak(data: []const u8) []const u8 {
    var ret: usize = undefined;
    asm volatile (".insn r 0x0b, 100, 0, %[rd], %[rs1], %[rs2]"
        : [rd] "=r" (ret),
        : [rs1] "r" (data.ptr),
          [rs2] "r" (data.ptr + data.len),
    );
    const sliceptr: [*]const u8 = @ptrFromInt(ret);
    return sliceptr[0..32];
}

pub fn sha256(data: []const u8) []const u8 {
    var ret: usize = undefined;
    asm volatile (".insn r 0x0b, 100, 1, %[rd], %[rs1], %[rs2]"
        : [rd] "=r" (ret),
        : [rs1] "r" (data.ptr),
          [rs2] "r" (data.ptr + data.len),
    );
    const sliceptr: [*]const u8 = @ptrFromInt(ret);
    return sliceptr[0..32];
}
