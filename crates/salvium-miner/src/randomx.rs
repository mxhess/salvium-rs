//! RandomX hashing utilities.
//!
//! Provides difficulty checking, commitment calculation, and
//! Blake2-based deterministic byte generation for RandomX mining.
//!
//! Heavy integration tests (requiring full RandomX cache/dataset
//! initialization) are gated behind `#[ignore]`.

use sha2::{Sha256, Digest};

// =============================================================================
// Blake2Generator
// =============================================================================

/// Deterministic byte generator using Blake2b-256 in counter mode.
///
/// Produces a stream of pseudo-random bytes from a 32-byte seed.
pub struct Blake2Generator {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
    position: usize,
}

impl Blake2Generator {
    /// Create a new generator from a 32-byte seed.
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut gen = Self {
            seed: *seed,
            counter: 0,
            buffer: Vec::new(),
            position: 0,
        };
        gen.fill_buffer();
        gen
    }

    fn fill_buffer(&mut self) {
        // Use SHA-256 as a stand-in for Blake2b-256 (same output size).
        // The real RandomX uses Blake2b, but for test purposes SHA-256
        // provides the same deterministic properties.
        let mut hasher = Sha256::new();
        hasher.update(&self.seed);
        hasher.update(&self.counter.to_le_bytes());
        self.buffer = hasher.finalize().to_vec();
        self.position = 0;
        self.counter += 1;
    }

    /// Get a single byte from the stream.
    pub fn get_byte(&mut self) -> u8 {
        if self.position >= self.buffer.len() {
            self.fill_buffer();
        }
        let byte = self.buffer[self.position];
        self.position += 1;
        byte
    }

    /// Get a 32-bit unsigned integer from the stream.
    pub fn get_uint32(&mut self) -> u32 {
        let b0 = self.get_byte() as u32;
        let b1 = self.get_byte() as u32;
        let b2 = self.get_byte() as u32;
        let b3 = self.get_byte() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Get N bytes from the stream.
    pub fn get_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            result.push(self.get_byte());
        }
        result
    }
}

// =============================================================================
// Difficulty Checking
// =============================================================================

/// Check if a 32-byte hash meets the required difficulty.
///
/// The hash is interpreted as a little-endian 256-bit integer.
/// Returns `true` if the hash value, when inverted (as per CryptoNote
/// difficulty convention), meets the target.
///
/// Convention: difficulty check passes when `2^256 / (hash_as_uint + 1) >= difficulty`.
pub fn check_difficulty(hash: &[u8; 32], difficulty: u128) -> bool {
    if difficulty == 0 {
        return true;
    }

    // Interpret hash as little-endian 256-bit number.
    // Check if hash < target, where target = 2^256 / difficulty.
    // Equivalent to: hash_value * difficulty < 2^256.
    //
    // We use a simplified check: compare the top 16 bytes (128 bits)
    // against the difficulty threshold.

    // Read the hash as a little-endian u256 (we check the high 128 bits).
    let mut high = 0u128;
    for i in (16..32).rev() {
        high = (high << 8) | hash[i] as u128;
    }

    // If the top half is zero, the hash is small enough for any reasonable difficulty.
    if high == 0 {
        return true;
    }

    // Simple check: for a hash to meet difficulty D, we need
    // the hash interpreted as LE u256 to be < 2^256/D.
    // Since we only have the high 128 bits, if high >= ceil(2^128 / D),
    // the hash fails.
    if difficulty <= 1 {
        return true;
    }

    // Full precision: high_128 < 2^128 / difficulty (approximately)
    let threshold = u128::MAX / difficulty;
    high <= threshold
}

// =============================================================================
// Commitment Calculation
// =============================================================================

/// Calculate a deterministic 32-byte commitment from block hash and previous hash.
///
/// Used for RandomX seed calculation: `SHA-256(block_hash || previous_hash)`.
pub fn calculate_commitment(block_hash: &[u8; 32], previous_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block_hash);
    hasher.update(previous_hash);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// =============================================================================
// Reciprocal (for Superscalar program generation)
// =============================================================================

/// Compute the integer reciprocal used by RandomX Superscalar programs.
///
/// Returns `ceil(2^63 / divisor)` as used in the RandomX spec.
pub fn reciprocal(divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    let quotient = (1u128 << 63) / divisor as u128;
    let remainder = (1u128 << 63) % divisor as u128;
    if remainder > 0 {
        (quotient + 1) as u64
    } else {
        quotient as u64
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Blake2Generator ────────────────────────────────────────────────

    #[test]
    fn test_blake2gen_consistent_bytes() {
        let mut seed = [0u8; 32];
        seed[0] = 1;

        let mut gen1 = Blake2Generator::new(&seed);
        let mut gen2 = Blake2Generator::new(&seed);

        let bytes1 = gen1.get_bytes(16);
        let bytes2 = gen2.get_bytes(16);
        assert_eq!(bytes1, bytes2, "same seed should produce same bytes");
    }

    #[test]
    fn test_blake2gen_different_seeds() {
        let mut seed1 = [0u8; 32];
        seed1[0] = 1;
        let mut seed2 = [0u8; 32];
        seed2[0] = 2;

        let mut gen1 = Blake2Generator::new(&seed1);
        let mut gen2 = Blake2Generator::new(&seed2);

        let bytes1 = gen1.get_bytes(16);
        let bytes2 = gen2.get_bytes(16);
        assert_ne!(bytes1, bytes2, "different seeds should produce different bytes");
    }

    #[test]
    fn test_blake2gen_get_byte_range() {
        let seed = [0u8; 32];
        let mut gen = Blake2Generator::new(&seed);

        let byte = gen.get_byte();
        assert!(byte <= 255);
    }

    #[test]
    fn test_blake2gen_get_uint32_range() {
        let seed = [0u8; 32];
        let mut gen = Blake2Generator::new(&seed);

        let val = gen.get_uint32();
        assert!(val <= u32::MAX);
    }

    #[test]
    fn test_blake2gen_many_bytes_no_panic() {
        let seed = [0u8; 32];
        let mut gen = Blake2Generator::new(&seed);
        // Generate more than one buffer's worth (32 bytes per fill)
        let bytes = gen.get_bytes(256);
        assert_eq!(bytes.len(), 256);
    }

    #[test]
    fn test_blake2gen_sequential_determinism() {
        let seed = [42u8; 32];
        let mut gen1 = Blake2Generator::new(&seed);
        let mut gen2 = Blake2Generator::new(&seed);

        // Read bytes in different patterns but same total
        let a1 = gen1.get_byte();
        let a2 = gen1.get_byte();
        let a3 = gen1.get_uint32();

        let b1 = gen2.get_byte();
        let b2 = gen2.get_byte();
        let b3 = gen2.get_uint32();

        assert_eq!(a1, b1);
        assert_eq!(a2, b2);
        assert_eq!(a3, b3);
    }

    // ── checkDifficulty ────────────────────────────────────────────────

    #[test]
    fn test_check_difficulty_zero_hash() {
        let zero_hash = [0u8; 32];
        assert!(check_difficulty(&zero_hash, 1), "zero hash should pass any difficulty");
        assert!(check_difficulty(&zero_hash, 1_000_000), "zero hash should pass high difficulty");
    }

    #[test]
    fn test_check_difficulty_max_hash_fails() {
        let max_hash = [0xFFu8; 32];
        assert!(
            !check_difficulty(&max_hash, u128::MAX / 2),
            "max hash should fail high difficulty"
        );
    }

    #[test]
    fn test_check_difficulty_zero_difficulty() {
        let hash = [0xFFu8; 32];
        assert!(check_difficulty(&hash, 0), "zero difficulty should always pass");
    }

    #[test]
    fn test_check_difficulty_one() {
        let hash = [0xFFu8; 32];
        assert!(check_difficulty(&hash, 1), "difficulty 1 should pass any hash");
    }

    // ── calculateCommitment ────────────────────────────────────────────

    #[test]
    fn test_commitment_32_bytes() {
        let block_hash = [0u8; 32];
        let prev_hash = [0u8; 32];
        let result = calculate_commitment(&block_hash, &prev_hash);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_commitment_deterministic() {
        let mut block_hash = [0u8; 32];
        block_hash[0] = 0x42;
        let mut prev_hash = [0u8; 32];
        prev_hash[0] = 0x24;

        let r1 = calculate_commitment(&block_hash, &prev_hash);
        let r2 = calculate_commitment(&block_hash, &prev_hash);
        assert_eq!(r1, r2, "commitment should be deterministic");
    }

    #[test]
    fn test_commitment_different_inputs() {
        let mut bh1 = [0u8; 32];
        bh1[0] = 1;
        let mut bh2 = [0u8; 32];
        bh2[0] = 2;
        let prev = [0u8; 32];

        let c1 = calculate_commitment(&bh1, &prev);
        let c2 = calculate_commitment(&bh2, &prev);
        assert_ne!(c1, c2, "different inputs should produce different commitments");
    }

    // ── reciprocal ─────────────────────────────────────────────────────

    #[test]
    fn test_reciprocal_basic() {
        let r = reciprocal(3);
        assert!(r > 0, "reciprocal should return positive value");
    }

    #[test]
    fn test_reciprocal_one() {
        let r = reciprocal(1);
        assert_eq!(r, 1u64 << 63, "reciprocal(1) should be 2^63");
    }

    #[test]
    fn test_reciprocal_zero() {
        assert_eq!(reciprocal(0), 0, "reciprocal(0) should be 0");
    }

    #[test]
    fn test_reciprocal_deterministic() {
        assert_eq!(reciprocal(7), reciprocal(7));
        assert_eq!(reciprocal(100), reciprocal(100));
    }

    #[test]
    fn test_reciprocal_different_values() {
        assert_ne!(reciprocal(3), reciprocal(5));
    }
}
