// figure out a way to dynamically load these constants based on env
const std = @import("std");
const mainnetPreset = @import("./presets/mainnet.zig");
const minimalPreset = @import("./presets/minimal.zig");
const types = @import("./types.zig");
const PresetConfig = types.PresetConfig;

pub const Preset = enum {
    mainnet,
    minimal,
};

const presets = .{
    .mainnet = mainnetPreset.preset,
    .minimal = minimalPreset.preset,
};

// Default to mainnet if no preset is specified
pub const activePreset = Preset.mainnet;
const activePresetValues = @field(presets, @tagName(activePreset));

pub const SECONDS_PER_SLOT = activePresetValues.SECONDS_PER_SLOT;

// SSZ capacity constants
pub const HISTORICAL_ROOTS_LIMIT = activePresetValues.HISTORICAL_ROOTS_LIMIT;
pub const VALIDATOR_REGISTRY_LIMIT = activePresetValues.VALIDATOR_REGISTRY_LIMIT;
pub const MAX_REQUEST_BLOCKS = activePresetValues.MAX_REQUEST_BLOCKS;

// Function to get preset values dynamically
pub fn getPresetValues(preset_type: Preset) PresetConfig {
    return switch (preset_type) {
        .mainnet => presets.mainnet,
        .minimal => presets.minimal,
    };
}

test "test preset loading" {
    try std.testing.expect(SECONDS_PER_SLOT == mainnetPreset.preset.SECONDS_PER_SLOT);
}

test "test preset values" {
    const mainnet_values = getPresetValues(.mainnet);
    const minimal_values = getPresetValues(.minimal);

    // Test that different presets have different values
    try std.testing.expect(mainnet_values.SECONDS_PER_SLOT == 4);
    try std.testing.expect(minimal_values.SECONDS_PER_SLOT == 6);

    // Test that minimal has smaller limits
    try std.testing.expect(minimal_values.HISTORICAL_ROOTS_LIMIT < mainnet_values.HISTORICAL_ROOTS_LIMIT);
    try std.testing.expect(minimal_values.VALIDATOR_REGISTRY_LIMIT < mainnet_values.VALIDATOR_REGISTRY_LIMIT);
    try std.testing.expect(minimal_values.MAX_REQUEST_BLOCKS < mainnet_values.MAX_REQUEST_BLOCKS);
}
