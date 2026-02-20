//! GhostRider mining engine implementing the HashAlgorithm trait.
//!
//! Wraps the vendored GhostRider C library. The full GhostRider algorithm
//! chains 15 SPH-512 core hashes interleaved with 3 CryptoNight memory-hard
//! rounds across a 3-part pipeline.

use crate::ffi;
use salvium_miner::mining::HashAlgorithm;
use std::ffi::c_void;

/// GhostRider hasher — holds a per-thread CryptoNight context (2MB scratchpad).
pub struct GhostRiderEngine {
    ctx: *mut c_void,
}

// Safety: the context is a self-contained scratchpad with no shared state.
// Each engine is used by exactly one mining thread.
unsafe impl Send for GhostRiderEngine {}

impl GhostRiderEngine {
    pub fn new() -> Self {
        let ctx = unsafe { ffi::ghostrider_alloc_ctx() };
        assert!(!ctx.is_null(), "failed to allocate GhostRider context");
        Self { ctx }
    }
}

impl Drop for GhostRiderEngine {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { ffi::ghostrider_free_ctx(self.ctx) };
            self.ctx = std::ptr::null_mut();
        }
    }
}

impl HashAlgorithm for GhostRiderEngine {
    fn name(&self) -> &str {
        "GhostRider"
    }

    fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        let ret = unsafe {
            ffi::ghostrider_hash(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                self.ctx,
            )
        };
        if ret != 0 {
            return [0u8; 32];
        }
        output
    }

    fn needs_reinit_on_seed_change(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sph_hash(algo: i32, input: &[u8]) -> [u8; 64] {
        let mut output = [0u8; 64];
        let ret = unsafe {
            ffi::ghostrider_sph_hash(algo, input.as_ptr(), input.len(), output.as_mut_ptr())
        };
        assert_eq!(ret, 0, "sph_hash({}) failed", algo);
        output
    }

    #[test]
    fn test_ghostrider_hash_produces_nonzero_output() {
        let mut engine = GhostRiderEngine::new();
        // Input must be >= 43 bytes for CN V1 requirement
        let input = b"test input for ghostrider hash verification!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        let hash = engine.hash(input);
        assert!(!hash.iter().all(|&b| b == 0), "hash should not be all zeros");
    }

    #[test]
    fn test_ghostrider_hash_is_deterministic() {
        let mut engine = GhostRiderEngine::new();
        let input = b"deterministic test input for ghostrider that is long enough bytes";
        let hash1 = engine.hash(input);
        let hash2 = engine.hash(input);
        assert_eq!(hash1, hash2, "same input must produce same hash");
    }

    #[test]
    fn test_ghostrider_hash_different_inputs() {
        let mut engine = GhostRiderEngine::new();
        let hash1 = engine.hash(b"input A for ghostrider that is long enough for cn v1 hash");
        let hash2 = engine.hash(b"input B for ghostrider that is long enough for cn v1 hash");
        assert_ne!(hash1, hash2, "different inputs should produce different hashes");
    }

    #[test]
    fn test_ghostrider_hash_trait_name() {
        let engine = GhostRiderEngine::new();
        assert_eq!(engine.name(), "GhostRider");
        assert!(!engine.needs_reinit_on_seed_change());
    }

    #[test]
    fn test_ghostrider_rejects_short_input() {
        let mut engine = GhostRiderEngine::new();
        // Input less than 43 bytes should fail (return zeros)
        let hash = engine.hash(b"too short");
        assert!(hash.iter().all(|&b| b == 0), "short input should return zeros");
    }

    // ── SPH individual hash function verification ─────────────────────
    // Each test verifies the SPH-512 hash of "abc" against published
    // reference values from the original algorithm specs.

    #[test]
    fn test_sph_blake512_abc() {
        let hash = sph_hash(0, b"abc");
        let expected = "14266c7c704a3b58fb421ee69fd005fcc6eeff742136be67435df995b7c986e7cbde4dbde135e7689c354d2bc5b8d260536c554b4f84c118e61efc576fed7cd3";
        assert_eq!(hex::encode(hash), expected, "BLAKE-512(\"abc\") mismatch");
    }

    #[test]
    fn test_sph_bmw512_abc() {
        let hash = sph_hash(1, b"abc");
        let expected = "8f37bef264289f61f3d713944d394a7ac1dd95d3fe5787b5d325a310bc9cd18783852bfee12fbdeaab3ad9a67f2b654e348714aed3acf7d7548e95591af68046";
        assert_eq!(hex::encode(hash), expected, "BMW-512(\"abc\") mismatch");
    }

    #[test]
    fn test_sph_keccak512_abc() {
        let hash = sph_hash(4, b"abc");
        let expected = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96";
        assert_eq!(hex::encode(hash), expected, "Keccak-512(\"abc\") mismatch");
    }

    #[test]
    fn test_sph_skein512_abc() {
        let hash = sph_hash(5, b"abc");
        let expected = "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f93893ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75";
        assert_eq!(hex::encode(hash), expected, "Skein-512(\"abc\") mismatch");
    }

    #[test]
    fn test_sph_whirlpool_abc() {
        let hash = sph_hash(14, b"abc");
        let expected = "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5";
        assert_eq!(hex::encode(hash), expected, "Whirlpool(\"abc\") mismatch");
    }

    #[test]
    fn test_sph_all_15_hashes_unique() {
        let input = b"GhostRider test vector";
        let mut hashes = Vec::new();
        for algo in 0..15 {
            let hash = sph_hash(algo, input);
            assert!(!hash.iter().all(|&b| b == 0), "algo {} returned all zeros", algo);
            hashes.push(hex::encode(hash));
        }
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 15, "all 15 SPH hashes should be distinct");
    }

    #[test]
    fn test_sph_deterministic() {
        let input = b"determinism check";
        for algo in 0..15 {
            let h1 = sph_hash(algo, input);
            let h2 = sph_hash(algo, input);
            assert_eq!(h1, h2, "algo {} not deterministic", algo);
        }
    }

    // ── XMRig reference test vectors ─────────────────────────────────
    // XMRig verifies GhostRider via XOR-differential: for 8 slots (i=0..7):
    //   blob1: 80 zero-bytes with [0]=i, [4]=0x10, [5]=0x02
    //   blob2: 80 zero-bytes with [0]=i, [4]=0x43, [5]=0x05
    //   expected: hash(blob1) XOR hash(blob2) == test_output_gr[i*32..(i+1)*32]
    //
    // Source: XMRig CpuWorker.cpp verify() + CryptoNight_test.h test_output_gr

    #[rustfmt::skip]
    const TEST_OUTPUT_GR: [u8; 256] = [
        0x42, 0x17, 0x0C, 0xC1, 0x85, 0xE6, 0x76, 0x3C, 0xC7, 0xCB, 0x27, 0xC4, 0x17, 0x39, 0x2D, 0xE2,
        0x29, 0x6B, 0x40, 0x66, 0x85, 0xA4, 0xE3, 0xD3, 0x8C, 0xE9, 0xA5, 0x8F, 0x10, 0xFC, 0x81, 0xE4,
        0x90, 0x56, 0xF2, 0x9E, 0x00, 0xD0, 0xF8, 0xA1, 0x88, 0x82, 0x86, 0xC0, 0x86, 0x04, 0x6B, 0x0E,
        0x9A, 0xDB, 0xDB, 0xFD, 0x23, 0x16, 0x77, 0x94, 0xFE, 0x58, 0x93, 0x05, 0x10, 0x3F, 0x27, 0x75,
        0x51, 0x44, 0xF3, 0x5F, 0xE2, 0xF9, 0x61, 0xBE, 0xC0, 0x30, 0xB5, 0x8E, 0xB1, 0x1B, 0xA1, 0xF7,
        0x06, 0x4E, 0xF1, 0x6A, 0xFD, 0xA5, 0x44, 0x8E, 0x64, 0x47, 0x8C, 0x67, 0x51, 0xE2, 0x5C, 0x55,
        0x3E, 0x39, 0xA6, 0xA5, 0xF7, 0xB8, 0xD0, 0x5E, 0xE2, 0xBF, 0x92, 0x44, 0xD9, 0xAA, 0x76, 0x22,
        0xE3, 0x3E, 0x15, 0x96, 0xD8, 0x6A, 0x78, 0x2D, 0xA9, 0x77, 0x24, 0x1A, 0x4B, 0xE7, 0x5A, 0x2E,
        0x89, 0x77, 0xAE, 0x92, 0xE4, 0xA4, 0x2D, 0xAF, 0x0B, 0x27, 0x09, 0xB2, 0x5F, 0x95, 0x61, 0xA9,
        0xA8, 0xBE, 0x5D, 0x39, 0xBE, 0x41, 0x5F, 0x9C, 0x67, 0x28, 0x48, 0x4F, 0xAE, 0x2A, 0x50, 0x2B,
        0xB8, 0xC7, 0x42, 0x73, 0x51, 0x60, 0x59, 0xD8, 0x9C, 0xBA, 0x22, 0x2F, 0x8E, 0x34, 0xDE, 0xC8,
        0x1B, 0xAE, 0x9E, 0xBD, 0xF7, 0xE8, 0xFD, 0x8A, 0x97, 0xBE, 0xF0, 0x47, 0xAC, 0x27, 0xDD, 0x28,
        0xC9, 0x28, 0xA8, 0x7B, 0x2A, 0xB8, 0x90, 0x3E, 0xCA, 0xB4, 0x78, 0x44, 0xCE, 0xCD, 0x91, 0xEC,
        0xC2, 0x5A, 0x17, 0x59, 0x7C, 0x14, 0xF8, 0x95, 0x28, 0x14, 0xC3, 0xAD, 0xC4, 0xE1, 0x13, 0x5A,
        0xC4, 0xA7, 0xC7, 0x77, 0xAD, 0xF8, 0x09, 0x61, 0x16, 0xBB, 0xAA, 0x7E, 0xAB, 0xC3, 0x00, 0x25,
        0xBA, 0xA8, 0x97, 0xC7, 0x7D, 0x38, 0x46, 0x0E, 0x59, 0xAC, 0xCB, 0xAE, 0xFE, 0x3C, 0x6F, 0x01,
    ];

    #[test]
    fn test_ghostrider_xmrig_vector_slot0() {
        let mut engine = GhostRiderEngine::new();

        // blob1: 80 zero-bytes with [0]=0, [4]=0x10, [5]=0x02
        let mut blob1 = [0u8; 80];
        blob1[4] = 0x10;
        blob1[5] = 0x02;
        let hash1 = engine.hash(&blob1);

        // blob2: 80 zero-bytes with [0]=0, [4]=0x43, [5]=0x05
        let mut blob2 = [0u8; 80];
        blob2[4] = 0x43;
        blob2[5] = 0x05;
        let hash2 = engine.hash(&blob2);

        // XOR should match test_output_gr[0..32]
        let xor: Vec<u8> = hash1.iter().zip(hash2.iter()).map(|(a, b)| a ^ b).collect();
        let expected = &TEST_OUTPUT_GR[0..32];
        assert_eq!(
            &xor[..], expected,
            "GhostRider XOR-differential mismatch for slot 0\n  got:    {}\n  expect: {}",
            hex::encode(&xor), hex::encode(expected)
        );
    }

    #[test]
    fn test_ghostrider_xmrig_vectors_all_8_slots() {
        let mut engine = GhostRiderEngine::new();

        for i in 0u8..8 {
            let mut blob1 = [0u8; 80];
            blob1[0] = i;
            blob1[4] = 0x10;
            blob1[5] = 0x02;
            let hash1 = engine.hash(&blob1);

            let mut blob2 = [0u8; 80];
            blob2[0] = i;
            blob2[4] = 0x43;
            blob2[5] = 0x05;
            let hash2 = engine.hash(&blob2);

            let xor: Vec<u8> = hash1.iter().zip(hash2.iter()).map(|(a, b)| a ^ b).collect();
            let expected = &TEST_OUTPUT_GR[(i as usize) * 32..(i as usize + 1) * 32];
            assert_eq!(
                &xor[..], expected,
                "GhostRider XOR-differential mismatch for slot {}\n  got:    {}\n  expect: {}",
                i, hex::encode(&xor), hex::encode(expected)
            );
        }
    }

    // ── Mining loop integration test ──────────────────────────────────

    #[test]
    fn test_ghostrider_mining_loop_smoke() {
        use salvium_miner::mining::MiningLoop;
        use salvium_miner::miner::MiningJob;
        use std::sync::atomic::Ordering;

        let mining_loop = MiningLoop::new(1, |_| {
            Ok(Box::new(GhostRiderEngine::new()))
        }).expect("failed to create mining loop");

        let mut hashing_blob = vec![0u8; 76];
        hashing_blob[0] = 10;
        hashing_blob[1] = 10;
        hashing_blob[2] = 1;

        mining_loop.send_job(MiningJob {
            job_id: 1,
            hashing_blob,
            template_blob: vec![0u8; 200],
            difficulty: 1,
            height: 100,
            nonce_offset: None,
            target: None,
        });

        // CryptoNight is much slower; give it more time
        std::thread::sleep(std::time::Duration::from_secs(5));

        let hashes = mining_loop.hash_count.load(Ordering::Relaxed);
        eprintln!("GhostRider hashes in 5s: {}", hashes);
        assert!(hashes > 0, "should have computed at least some hashes");

        let block = mining_loop.try_recv_block();
        assert!(block.is_some(), "should have found a block with difficulty=1");

        let block = block.unwrap();
        assert!(!block.hash.iter().all(|&b| b == 0), "found block hash should be non-zero");

        mining_loop.stop();
    }
}
