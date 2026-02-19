//! CryptoNote tree hash (Merkle root) computation.
//!
//! Used to compute the root hash of transaction hashes in a block.
//! This is NOT a standard binary Merkle tree — it uses the CryptoNote
//! algorithm from crypto/tree-hash.c.
//!
//! Reference: salvium/src/crypto/tree-hash.c, mining.js treeHash()

use tiny_keccak::{Hasher, Keccak};

/// Keccak-256 of 64 bytes (two concatenated 32-byte hashes).
fn cn_fast_hash(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut output);
    output
}

/// Hash a pair of 32-byte values.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(a);
    combined[32..].copy_from_slice(b);
    cn_fast_hash(&combined)
}

/// Compute the CryptoNote tree hash (Merkle root) of transaction hashes.
///
/// Algorithm:
/// - 0 hashes → zero hash
/// - 1 hash → identity
/// - 2 hashes → hash(h0 || h1)
/// - N ≥ 3 → CryptoNote power-of-2 tree algorithm
///
/// Reference: crypto/tree-hash.c `tree_hash()`
pub fn tree_hash(hashes: &[[u8; 32]]) -> [u8; 32] {
    let count = hashes.len();

    if count == 0 {
        return [0u8; 32];
    }

    if count == 1 {
        return hashes[0];
    }

    if count == 2 {
        return hash_pair(&hashes[0], &hashes[1]);
    }

    // Find cnt = largest power of 2 ≤ count
    let mut cnt = 1usize;
    while cnt * 2 <= count {
        cnt *= 2;
    }

    // Initialize intermediate hashes
    let mut ints = vec![[0u8; 32]; cnt];

    // Copy hashes that don't need initial hashing
    let start_idx = 2 * cnt - count;
    ints[..start_idx].copy_from_slice(&hashes[..start_idx]);

    // Hash remaining pairs into intermediate array
    let mut i = start_idx;
    let mut j = start_idx;
    while j < cnt {
        ints[j] = hash_pair(&hashes[i], &hashes[i + 1]);
        i += 2;
        j += 1;
    }

    // Reduce tree until we have 2 elements
    while cnt > 2 {
        cnt >>= 1;
        let mut i = 0;
        let mut j = 0;
        while j < cnt {
            let a = ints[i];
            let b = ints[i + 1];
            ints[j] = hash_pair(&a, &b);
            i += 2;
            j += 1;
        }
    }

    // Final hash of 2 remaining elements
    hash_pair(&ints[0], &ints[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_hash_empty() {
        assert_eq!(tree_hash(&[]), [0u8; 32]);
    }

    #[test]
    fn test_tree_hash_single() {
        let h = [0xABu8; 32];
        assert_eq!(tree_hash(&[h]), h);
    }

    #[test]
    fn test_tree_hash_two() {
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        let result = tree_hash(&[h1, h2]);
        assert_eq!(result, hash_pair(&h1, &h2));
    }

    #[test]
    fn test_tree_hash_three() {
        // count=3, cnt=2, start_idx=1
        // ints[0] = hashes[0]
        // ints[1] = hash(hashes[1], hashes[2])
        // result = hash(ints[0], ints[1])
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        let h3 = [0x03u8; 32];

        let result = tree_hash(&[h1, h2, h3]);
        let expected = hash_pair(&h1, &hash_pair(&h2, &h3));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_tree_hash_four() {
        // count=4, cnt=4, start_idx=4 (2*4-4=4)
        // No copies, all pairs hashed:
        // ints[0..4] all filled by pairing, but start_idx=4 means i=4..j=4 loop doesn't run
        // Wait, let me re-check: start_idx = 2*cnt - count = 2*4-4 = 4
        // So we copy hashes[0..4] to ints[0..4]... but cnt=4 so ints has 4 slots
        // Then i=4, j=4, while j<4 doesn't run
        // Then reduce: cnt=2, hash pairs (0,1) and (2,3)
        // Then cnt=1 < 2 so loop ends... wait cnt>2 is false when cnt=2
        // So final = hash(ints[0], ints[1]) where ints[0]=hash(h0,h1), ints[1]=hash(h2,h3)
        // But the copy loop copies all 4 hashes, then reduce once
        // Actually: cnt=4, start_idx=4. Copy loop: 0..4 copies hashes[0..4] to ints[0..4]
        // Pair loop: i=4, j=4, while j<4 → doesn't execute
        // Reduce: cnt=4>2, cnt=2: hash pairs: ints[0]=hash(h0,h1), ints[1]=hash(h2,h3)
        // cnt=2, not >2, stop. Final = hash(ints[0], ints[1])
        let h = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let result = tree_hash(&h);
        let left = hash_pair(&h[0], &h[1]);
        let right = hash_pair(&h[2], &h[3]);
        let expected = hash_pair(&left, &right);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_tree_hash_five() {
        // count=5, cnt=4, start_idx=3
        // ints[0..3] = hashes[0..3]
        // ints[3] = hash(hashes[3], hashes[4])
        // Reduce: cnt=2: ints[0]=hash(ints[0],ints[1]), ints[1]=hash(ints[2],ints[3])
        // Final = hash(ints[0], ints[1])
        let h: Vec<[u8; 32]> = (0..5).map(|i| [i as u8 + 1; 32]).collect();
        let result = tree_hash(&h);

        let h3h4 = hash_pair(&h[3], &h[4]);
        let left = hash_pair(&h[0], &h[1]);
        let right = hash_pair(&h[2], &h3h4);
        let expected = hash_pair(&left, &right);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_tree_hash_deterministic() {
        let hashes: Vec<[u8; 32]> = (0..7).map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h
        }).collect();

        let r1 = tree_hash(&hashes);
        let r2 = tree_hash(&hashes);
        assert_eq!(r1, r2, "tree_hash must be deterministic");
        assert_ne!(r1, [0u8; 32], "result should not be zero");
    }
}
