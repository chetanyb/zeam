const ssz = @import("ssz");
const std = @import("std");

// just dummy type right now to test imports
pub const Bytes32 = [:32]const u8;
pub const Slot = u64;
pub const ValidatorIndex = u64;
pub const Bytes48 = [:48]const u8;

pub const BeamBlockHeader = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body_root: Bytes32,
};

pub const BeamBlockBody = struct {};

pub const BeamBlock = struct {
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
    body: BeamBlockBody,
};

pub const SignedBeamBlock = struct {
    message: BeamBlock,
    signature: Bytes48,
};

pub const BeamState = struct {
    genesis_time: u64,
    slot: u64,
    lastest_block_header: BeamBlockHeader,
};

pub const ZkVm = enum {
    ceno,
    powdr,
    sp1,
};

pub const BeamSTFProof = struct {
    zk_vm: ZkVm,
    proof: []u8,
};

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
