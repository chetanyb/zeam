const std = @import("std");
const mem_layout = @import("./layout.zig");

var input_ptr: [*]const u8 = @ptrFromInt(mem_layout.INPUT_ADDR);

pub fn get_input(_: std.mem.Allocator) []const u8 {
    const input_size = std.mem.readInt(u64, input_ptr[8..16], .little);
    if (input_size > mem_layout.INPUT_SIZE) @panic("invalid input size");
    return input_ptr[8 .. 8 + input_size];
// note pour quand je rentre: il semblerait que get_input ne soit pas compile, ce qui pourrait avoir
// a voir avec l'absence de volatile.
}

pub const zisk_archid = 0xFFFEEEE;

pub fn print_str(str: []const u8) void {
    const arch_id_zisk = asm volatile ("csrr %[ret], marchid"
        : [ret] "=r" (-> usize),
    );
    var addr: [*]volatile u8 = if (arch_id_zisk == zisk_archid) @ptrFromInt(mem_layout.UART_ADDR) else @ptrFromInt(0x1000_0000);
    for (str) |c| {
        addr[0] = c;
    }
}
