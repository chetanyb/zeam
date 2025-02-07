const types = @import("types")
const state_transition = @import("state-transition")


const StateTransitionOpts = struct{
    zk_vm: ZKVM_TYPES,
}

pub fn execute_transition(state: types.BeamState, block: types.SignedBeamBlock, opts: StateTransitionOpts) types.BeamSTFProof {
    return types.BeamSTFProof{};
}