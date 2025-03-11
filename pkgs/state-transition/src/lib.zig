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

    // verify the post state root
    var state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, state.*, &state_root, allocator);
    if (!std.mem.eql(u8, &state_root, &block.state_root)) {
        return StateTransitionError.InvalidPostState;
    }
}

const StateTransitionError = error{
    InvalidParentRoot,
    InvalidPreState,
    InvalidPostState,
};

// refac into different files
const MockChainData = struct {
    genesis_config: types.GenesisSpec,
    genesis_state: types.BeamState,
    blocks: []types.SignedBeamBlock,
};

pub fn genMockChain(allocator: Allocator, numBlocks: usize, from_genesis: ?types.GenesisSpec) !MockChainData {
    const genesis_config = from_genesis orelse types.GenesisSpec{
        .genesis_time = 1234,
    };

    const genesis_state = try utils.genGenesisState(allocator, genesis_config);
    var blockList = std.ArrayList(types.SignedBeamBlock).init(allocator);

    // figure out a way to clone genesis_state
    var beam_state = try utils.genGenesisState(allocator, genesis_config);
    const genesis_block = try utils.genGenesisBlock(allocator, beam_state);

    var gen_signature: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(gen_signature[0..], utils.ZERO_HASH_48HEX);
    const gen_signed_block = types.SignedBeamBlock{
        .message = genesis_block,
        .signature = gen_signature,
    };
    try blockList.append(gen_signed_block);

    var prev_block = genesis_block;
    for (1..numBlocks) |slot| {
        var parent_root: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.BeamBlock, prev_block, &parent_root, allocator);

        var state_root: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(state_root[0..], utils.ZERO_HASH_HEX);

        var block = types.BeamBlock{
            .slot = slot,
            .proposer_index = 1,
            .parent_root = parent_root,
            .state_root = state_root,
            .body = types.BeamBlockBody{},
        };

        // prepare pre state to process block for that slot, may be rename prepare_pre_state
        try process_slots(allocator, &beam_state, block.slot);
        // process block and modify the pre state to post state
        try process_block(allocator, &beam_state, block);

        // extract the post state root
        try ssz.hashTreeRoot(types.BeamState, beam_state, &state_root, allocator);
        block.state_root = state_root;

        // generate the signed beam block and add to block list
        var signature: [48]u8 = undefined;
        _ = try std.fmt.hexToBytes(signature[0..], utils.ZERO_HASH_48HEX);
        const signed_block = types.SignedBeamBlock{
            .message = block,
            .signature = signature,
        };
        try blockList.append(signed_block);
        // now we are ready for next round as the beam_state is not this blocks post state
        prev_block = block;
    }

    return MockChainData{
        .genesis_config = genesis_config,
        .genesis_state = genesis_state,
        .blocks = blockList.items,
    };
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "mock chain util" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
        .genesis_time = 1234,
    };

    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const mock_chain = try genMockChain(allocator, 3, test_config);
    try std.testing.expect(mock_chain.blocks.len == 3);

    // starting beam state
    var beam_state = mock_chain.genesis_state;
    // block 0 is genesis so we have to apply block 1 onwards
    for (1..mock_chain.blocks.len) |i| {
        // this is a signed block
        const block = mock_chain.blocks[i];
        try apply_transition(allocator, &beam_state, block);
    }

    // check the post state root to be equal to block2's stateroot
    // this is reduant though because apply_transition already checks this for each block's state root
    var post_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, beam_state, &post_state_root, allocator);
    try std.testing.expect(std.mem.eql(u8, &post_state_root, &mock_chain.blocks[mock_chain.blocks.len - 1].message.state_root));
    std.debug.print("final post state root: {s}\n", .{std.fmt.fmtSliceHexLower(&post_state_root)});
}

test "genesis and state transition" {
    // 1. setup genesis config
    const test_config = types.GenesisSpec{
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

    var expected_block1_state_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_block1_state_root[0..], "f77aaa703c400ccaffa8e674316713b044fcc3d94ec5764b00ce7edc138e7c95");
    try std.testing.expect(std.mem.eql(u8, &expected_block1_state_root, &block1_state_root));

    // 7. (optional for current test) calc final block1 root which could be used in signing the beam block
    var block1_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamBlock, block1, &block1_root, std.testing.allocator);

    var expected_block1_root: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected_block1_root[0..], "5b0c264e75ce2fae8ec3c2e0c1debb81e023e62df737469be61acdb37b7ff9a3");
    try std.testing.expect(std.mem.eql(u8, &block1_root, &expected_block1_root));

    std.debug.print("post test_genesis: {any}, block1: {any} block1stateroot: {s} block1 root: {s}\n", .{ test_genesis, block1, std.fmt.fmtSliceHexLower(&block1_state_root), std.fmt.fmtSliceHexLower(&block1_root) });

    // 8. form a signed beam block
    // TODO: real signatures once integrated
    var signature: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(signature[0..], utils.ZERO_HASH_48HEX);

    const signed_block1 = types.SignedBeamBlock{
        .message = block1,
        .signature = signature,
    };

    // 9. run state transition
    // TODO: the previous process block should have been run on cloned state so we have the original pre
    // state here to run the state transition. for now regen same genesis state
    var state = try utils.genGenesisState(std.testing.allocator, test_config);
    try apply_transition(std.testing.allocator, &state, signed_block1);
    var post_state_root: [32]u8 = undefined;
    try ssz.hashTreeRoot(types.BeamState, state, &post_state_root, std.testing.allocator);

    try std.testing.expect(std.mem.eql(u8, &post_state_root, &expected_block1_state_root));
    std.debug.print("post state transition: {any}, signed_block1: {any} post_state_root: {s}\n", .{ test_genesis, signed_block1, std.fmt.fmtSliceHexLower(&post_state_root) });
}
