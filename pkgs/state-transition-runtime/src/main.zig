const std = @import("std");
const Allocator = std.mem.Allocator;

const ssz = @import("ssz");
const types = @import("zeam-types");
const state_transition = @import("zeam-state-transition");

const Inputs = struct {
    state_root: []const u8,
    block_root: []const u8,
};

const Witnesses = struct {
    state: []const u8,
    block: []const u8,
};

// implements risv5 runtime that runs in zkvm on provided inputs and witnesses to execute
// and prove the state transition as imported from `pkgs/state-transition`
pub fn main() noreturn {
    // access inputs and witnesses from zkvm
    const inputs = Inputs{
        .state_root = &[_]u8{},
        .block_root = &[_]u8{},
    };
    _ = inputs;
    const witnesses = Witnesses{
        .state = &[_]u8{},
        .block = &[_]u8{},
    };
    _ = witnesses;

    // TODO: construct state and block from witnesses and validate stateroot and block root
    // use the ssz deserialized state and block to apply state transition

    const state = types.BeamState{};
    const block = types.SignedBeamBlock{};

    // get some allocator
    // apply the state transition to modify the state
    state_transition.apply_transition(allocator, &state, block);

    // verify the block.state_root is ssz hash tree root of state
    // this completes our zkvm proving
}

test "ssz import" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };
    var list = std.ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try ssz.serialize(u16, data, &list);
    try std.testing.expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}
