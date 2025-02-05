const types = @import("zeam-types");
const ssz = @import("ssz");
const std = @import("std");

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "types import" {
    const b1 = types.Bytes32{ .data = "96357740ddd002408ce9cde66b7734b4" };
    _ = b1;
}
