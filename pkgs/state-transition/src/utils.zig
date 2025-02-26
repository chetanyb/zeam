const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("zeam-types");
const ssz = @import("ssz");

const ZERO_HASH_HEX = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn blockToHeader(allocator: Allocator, block: types.BeamBlock) types.BeamBlockHeader {
    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamBlockBody,
        block.body,
        &body_root,
        allocator,
    );

    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .parent_root = block.parent_root,
        .state_root = block.state_root,
        .body_root = body_root,
    };
    return header;
}

// computing latest block header to be assigned to the state for processing the block
pub fn blockToLatestBlockHeader(allocator: Allocator, block: types.BeamBlock) !types.BeamBlockHeader {
    var state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(state_root[0..], ZERO_HASH_HEX);

    var body_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(
        types.BeamBlockBody,
        block.body,
        &body_root,
        allocator,
    );

    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .parent_root = block.parent_root,
        // zero hash the stateroot for purposes of state's latest block header
        .state_root = state_root,
        .body_root = body_root,
    };
    return header;
}

pub fn genGenesisState(allocator: Allocator, config: types.ChainConfig) !types.BeamState {
    var state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(state_root[0..], ZERO_HASH_HEX);

    var parent_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(parent_root[0..], ZERO_HASH_HEX);

    const genesis_block = types.BeamBlock{
        .slot = 0,
        .proposer_index = 0,
        .parent_root = parent_root,
        .state_root = state_root,
        .body = types.BeamBlockBody{},
    };

    const state = types.BeamState{
        .genesis_time = config.genesis_time,
        .slot = 0,
        .lastest_block_header = try blockToLatestBlockHeader(allocator, genesis_block),
    };

    return state;
}
