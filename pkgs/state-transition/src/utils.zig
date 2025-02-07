const types = @import("zeam-types");
const ssz = @import("ssz");

// zig will change it into utf8 32 bytes zero
const ZERO_HASH = "0000000000000000000000000000000000";

pub fn blockToHeader(block: types.BeamBlock) types.BeamBlockHeader {
    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .state_root = block.state_root,
        .body_root = ssz.hash_tree_root(block.body),
    };
    return header;
}

pub fn blockToLatestBlockHeader(block: types.BeamBlock) types.BeamBlockHeader {
    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        // zero hash the stateroot for purposes of state's latest block header
        .state_root = ZERO_HASH,
        .body_root = ssz.hash_tree_root(block.body),
    };
    return header;
}
