const types = @import("types")
const state_transition = @import("state-transition")


const StateTransitionOpts = struct{
    zk_vm: ZKVM_TYPES,
}

pub fn execute_transition(state: types.BeamState, block: types.SignedBeamBlock, opts: StateTransitionOpts) types.BeamSTFProof {
    return types.BeamSTFProof{};
}

pub fn verify_transition(stf_proof: types.BeamSTFProof, state_root: types.Bytes32, block_root: types.Bytes32, opts: StateTransitionOpts) !void{

}
