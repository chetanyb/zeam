const std = @import("std");
const types = @import("types");

pub const ProtoNode = struct {
    slot: types.Slot,
    blockRoot: types.RootHex,
    parentRoot: types.RootHex,
    stateRoot: types.RootHex,
    targetRoot: types.targetRoot,
    timeliness: bool,

    parent: ?usize,
    weight: ?usize,
    bestChild: ?usize,
    bestDescendant: ?usize,
};

pub const ProtoArray = struct {
    nodes: []ProtoNode,
    indices: std.StringHashMap(usize),

    const Self = @This();
    pub fn init() !Self {}

    pub fn onBlock(block: ProtoNode, currentSlot: types.Slot) !void {
        _ = block;
        _ = currentSlot;
        return ForkChoiceError.NotImplemented;
    }
};

const OnBlockOpts = struct {
    currentSlot: types.Slot,
};

pub const ForkChoice = struct {
    blockTree: ProtoArray,

    const Self = @This();
    pub fn init() !Self {}
    pub fn onBlock(block: types.BeaconBlock, state: types.BeaconState, opts: OnBlockOpts) !void {
        _ = block;
        _ = state;
        _ = opts;

        return ForkChoiceError.NotImplemented;
    }
};

const ForkChoiceError = error{NotImplemented};
