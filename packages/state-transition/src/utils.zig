const types = @import("zeam-types");
const ssz = @import("ssz");

pub fn blockToHeader(block: types.BeamBlock) types.BeamBlockHeader {
    const header = types.BeamBlockHeader{
        .slot = block.slot,
        .proposer_index = block.proposer_index,
        .state_root = block.state_root,
        .body_root = ssz.hash_tree_root(block.body),
    };
    return header;
}
