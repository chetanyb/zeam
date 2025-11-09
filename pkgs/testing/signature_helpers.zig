const std = @import("std");
const xmss = @import("@zeam/xmss");
const types = @import("@zeam/types");
const ssz = @import("ssz");
const Allocator = std.mem.Allocator;

pub const TestKeyManager = struct {
    keys: []xmss.KeyPair,
    allocator: Allocator,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        num_validators: usize,
        max_slot: usize,
    ) !Self {
        const keys = try allocator.alloc(xmss.KeyPair, num_validators);
        errdefer allocator.free(keys);

        const num_active_epochs = max_slot + 1;

        for (keys, 0..) |*key, i| {
            const seed = try std.fmt.allocPrint(allocator, "test_validator_{d}", .{i});
            defer allocator.free(seed);

            key.* = try xmss.KeyPair.generate(
                allocator,
                seed,
                0,
                num_active_epochs,
            );
        }

        return Self{
            .keys = keys,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.keys) |*key| {
            key.deinit();
        }
        self.allocator.free(self.keys);
    }

    pub fn signAttestation(
        self: *const Self,
        attestation: *const types.Attestation,
        allocator: Allocator,
    ) !types.Bytes4000 {
        const validator_index: usize = @intCast(attestation.validator_id);

        const keypair = &self.keys[validator_index];

        var message: [32]u8 = undefined;
        try ssz.hashTreeRoot(types.Attestation, attestation.*, &message, allocator);

        const epoch: u32 = @intCast(attestation.data.slot);
        var signature = try keypair.sign(&message, epoch);
        defer signature.deinit();

        var sig_buffer: types.Bytes4000 = undefined;
        const bytes_written = try signature.toBytes(&sig_buffer);

        if (bytes_written < types.SIGSIZE) {
            @memset(sig_buffer[bytes_written..], 0);
        }

        return sig_buffer;
    }

    pub fn getPublicKeyBytes(
        self: *const Self,
        validator_index: usize,
        buffer: []u8,
    ) !usize {
        const keypair = &self.keys[validator_index];
        return try keypair.pubkeyToBytes(buffer);
    }
};
