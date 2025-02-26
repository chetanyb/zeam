const ssz = @import("ssz");
const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("zeam-types");

pub const utils = @import("./utils.zig");

// setup a params repo sensitive to a preset
const SLOTS_PER_EPOCH = 32;

// pub fn process_epoch(state: types.BeamState) void {
//     // right now nothing to do
//     _ = state;
//     return;
// }

// prepare the state to be the post-state of the slot
pub fn process_slot(allocator: Allocator, state: *types.BeamState) !void {

    // update state root in latest block header if its zero hash
    // i.e. just after processing the lastest block of latest block header
    // this completes latest block header for parentRoot checks of new block

    if (std.mem.eql(u8, &state.lastest_block_header.state_root, &utils.ZERO_HASH)) {
        var prev_state_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamState, state.*, &prev_state_root, allocator);
        state.lastest_block_header.state_root = prev_state_root;
    }
}

// prepare the state to be pre state of the slot
pub fn process_slots(allocator: Allocator, state: *types.BeamState, slot: types.Slot) !void {
    while (state.slot < slot) {
        try process_slot(allocator, state);
        // There might not be epoch processing in beam
        // if ((state.slot + 1) % SLOTS_PER_EPOCH == 0) {
        //     process_epoch(state);
        // }

        state.slot += 1;
    }
}

fn process_block_header(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // very basic process block header
    if (state.slot != block.slot) {
        return StateTransitionError.InvalidPreState;
    }

    var head_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlockHeader, state.lastest_block_header, &head_root, allocator);
    if (!std.mem.eql(u8, &head_root, &block.parent_root)) {
        return StateTransitionError.InvalidParentRoot;
    }

    state.lastest_block_header = try utils.blockToLatestBlockHeader(allocator, block);
}

pub fn process_block(allocator: Allocator, state: *types.BeamState, block: types.BeamBlock) !void {
    // start block processing
    try process_block_header(allocator, state, block);
}

// fill this up when we have signature scheme
pub fn verify_signatures(signedBlock: types.SignedBeamBlock) !void {
    _ = signedBlock;
}

pub fn apply_transition(allocator: Allocator, state: *types.BeamState, signedBlock: types.SignedBeamBlock) !void {
    // verify the proposer and attestation signatures on signed block
    try verify_signatures(signedBlock);

    // prepare the pre state for this block slot
    const block = signedBlock.message;
    try process_slots(allocator, state, block.slot);

    // process the block
    try process_block(allocator, state, block);
}

const StateTransitionError = error{
    InvalidPreState,
    InvalidParentRoot,
};

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "genesis and state transition" {
    // 1. setup genesis config
    const test_config = types.ChainConfig{
        .genesis_time = 1234,
    };

    // 2. generate genesis state
    var test_genesis = try utils.genGenesisState(std.testing.allocator, test_config);

    var test_genesis_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, test_genesis, &test_genesis_root, std.testing.allocator);

    var expected_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_root[0..], "0d2ea8d3f6846e408db07fd6970d131533a7062ed973c8c4d4d64de8adad1bff");

    try std.testing.expect(std.mem.eql(u8, &test_genesis_root, &expected_root));
    std.debug.print("test_genesis: {any} {s}\n", .{ test_genesis, std.fmt.fmtSliceHexLower(&test_genesis_root) });

    // 3. generate genesis block
    const test_genesis_block = try utils.genGenesisBlock(std.testing.allocator, test_genesis);
    var test_genesis_block_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, test_genesis_block, &test_genesis_block_root, std.testing.allocator);

    var expected_genesis_block_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_genesis_block_root[0..], "5d476554c248a6f59082aabf1bf9cde041e7f9e0cf43990a22f42246dcfc1007");

    try std.testing.expect(std.mem.eql(u8, &test_genesis_root, &test_genesis_block.state_root));
    try std.testing.expect(std.mem.eql(u8, &test_genesis_block_root, &expected_genesis_block_root));
    std.debug.print("test_genesis: {any} {s} {s}\n", .{ test_genesis_block, std.fmt.fmtSliceHexLower(&test_genesis_block.state_root), std.fmt.fmtSliceHexLower(&test_genesis_block_root) });

    // 4. assemble a new block with zero state root
    var block1_state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(block1_state_root[0..], utils.ZERO_HASH_HEX);

    var block1 = types.BeamBlock{
        .slot = 1,
        .proposer_index = 1,
        .parent_root = test_genesis_block_root,
        .state_root = block1_state_root,
        .body = types.BeamBlockBody{},
    };

    // 5. clone genesis and get the prestate for the block
    // TODO clone
    try process_slots(std.testing.allocator, &test_genesis, block1.slot);

    // 6. apply the block to the genesis and get & fill the post state root for the block
    try process_block(std.testing.allocator, &test_genesis, block1);
    try ssz.hashTreeRoot(types.BeamState, test_genesis, &block1_state_root, std.testing.allocator);
    block1.state_root = block1_state_root;

    // 7. calc final block1 root which could be used in signing and creating the signed beam block
    var block1_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, block1, &block1_root, std.testing.allocator);

    var expected_block1_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_block1_root[0..], "5b0c264e75ce2fae8ec3c2e0c1debb81e023e62df737469be61acdb37b7ff9a3");
    try std.testing.expect(std.mem.eql(u8, &block1_root, &expected_block1_root));

    std.debug.print("post test_genesis: {any}, block1: {any} block1stateroot: {s} block1 root: {s}\n", .{ test_genesis, block1, std.fmt.fmtSliceHexLower(&block1_state_root), std.fmt.fmtSliceHexLower(&block1_root) });
}
