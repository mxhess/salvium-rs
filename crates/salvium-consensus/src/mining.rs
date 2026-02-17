//! Mining utilities: block template handling, nonce manipulation, difficulty
//! formatting, hashrate statistics.
//!
//! The actual PoW hash (RandomX) is external — this module provides the
//! infrastructure around it.
//!
//! Reference: salvium/src/cryptonote_basic/miner.cpp, difficulty.cpp, mining.js


// =============================================================================
// Constants
// =============================================================================

/// Maximum extra nonce size in bytes.
pub const MAX_EXTRA_NONCE_SIZE: usize = 255;

/// Nonce size in bytes (32-bit).
pub const NONCE_SIZE: usize = 4;

// =============================================================================
// Block Template
// =============================================================================

/// Parsed block template from daemon RPC `get_block_template`.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Full 128-bit difficulty.
    pub difficulty: u128,
    /// Block height.
    pub height: u64,
    /// Reserved space offset for extra nonce.
    pub reserved_offset: usize,
    /// Expected block reward in atomic units.
    pub expected_reward: u64,
    /// Previous block hash (hex string).
    pub prev_hash: String,
    /// RandomX seed height.
    pub seed_height: u64,
    /// RandomX seed hash (hex string).
    pub seed_hash: String,
    /// Next RandomX seed hash (hex string).
    pub next_seed_hash: String,
    /// Raw block template blob (bytes).
    pub blocktemplate_blob: Vec<u8>,
    /// Block hashing blob (bytes).
    pub blockhashing_blob: Vec<u8>,
}

/// Parse difficulty from RPC response fields.
///
/// Handles 64-bit, 128-bit hex, and split top64/low64 formats.
pub fn parse_difficulty(
    difficulty: u64,
    wide_difficulty: Option<&str>,
    difficulty_top64: Option<u64>,
) -> u128 {
    // Prefer wide_difficulty (most accurate)
    if let Some(wide) = wide_difficulty {
        let hex = wide.strip_prefix("0x").unwrap_or(wide);
        if let Ok(val) = u128::from_str_radix(hex, 16) {
            return val;
        }
    }

    // Combine top64 + low64
    if let Some(top) = difficulty_top64 {
        return ((top as u128) << 64) | (difficulty as u128);
    }

    // Just 64-bit
    difficulty as u128
}

// =============================================================================
// Nonce Manipulation
// =============================================================================

/// Set the 32-bit nonce at `offset` in a blob (little-endian).
pub fn set_nonce(blob: &mut [u8], nonce: u32, offset: usize) {
    blob[offset] = (nonce & 0xFF) as u8;
    blob[offset + 1] = ((nonce >> 8) & 0xFF) as u8;
    blob[offset + 2] = ((nonce >> 16) & 0xFF) as u8;
    blob[offset + 3] = ((nonce >> 24) & 0xFF) as u8;
}

/// Get the 32-bit nonce from `offset` in a blob (little-endian).
pub fn get_nonce(blob: &[u8], offset: usize) -> u32 {
    blob[offset] as u32
        | ((blob[offset + 1] as u32) << 8)
        | ((blob[offset + 2] as u32) << 16)
        | ((blob[offset + 3] as u32) << 24)
}

/// Set extra nonce data in block template at reserved offset.
pub fn set_extra_nonce(
    blob: &mut [u8],
    extra_nonce: &[u8],
    reserved_offset: usize,
) -> Result<(), &'static str> {
    if extra_nonce.len() > MAX_EXTRA_NONCE_SIZE {
        return Err("extra nonce too large");
    }
    blob[reserved_offset..reserved_offset + extra_nonce.len()]
        .copy_from_slice(extra_nonce);
    Ok(())
}

/// Find the nonce offset in a block template blob.
///
/// Nonce follows: major_version(varint) + minor_version(varint) +
/// timestamp(varint) + prev_id(32 bytes).
pub fn find_nonce_offset(blob: &[u8]) -> usize {
    let mut offset = 0;

    // Skip major_version (varint)
    while blob[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1;

    // Skip minor_version (varint)
    while blob[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1;

    // Skip timestamp (varint)
    while blob[offset] & 0x80 != 0 {
        offset += 1;
    }
    offset += 1;

    // Skip prev_id (32 bytes)
    offset += 32;

    offset
}

/// Format a mined block for submission via `submit_block` RPC.
///
/// Sets the winning nonce and returns the hex-encoded block blob.
pub fn format_block_for_submission(
    blocktemplate_blob: &[u8],
    nonce: u32,
    nonce_offset: usize,
) -> String {
    let mut blob = blocktemplate_blob.to_vec();
    set_nonce(&mut blob, nonce, nonce_offset);
    hex::encode(&blob)
}

// =============================================================================
// Difficulty Formatting
// =============================================================================

/// Format difficulty to human-readable string with SI suffix.
pub fn format_difficulty(difficulty: u128) -> String {
    let num = difficulty as f64;
    if num >= 1e15 {
        format!("{:.2} P", num / 1e15)
    } else if num >= 1e12 {
        format!("{:.2} T", num / 1e12)
    } else if num >= 1e9 {
        format!("{:.2} G", num / 1e9)
    } else if num >= 1e6 {
        format!("{:.2} M", num / 1e6)
    } else if num >= 1e3 {
        format!("{:.2} K", num / 1e3)
    } else {
        difficulty.to_string()
    }
}

/// Calculate difficulty target (2^256 / difficulty).
pub fn difficulty_to_target(difficulty: u128) -> Option<[u8; 32]> {
    if difficulty == 0 {
        return None;
    }
    // target = (2^256 - 1) / difficulty (approximation using u256-like math)
    // For practical purposes, this is used for display only
    // The actual check is done by check_hash() in salvium-types
    None // TODO: implement when u256 is needed
}

// =============================================================================
// Mining Statistics
// =============================================================================

/// Calculate hashrate from hash count and elapsed time.
pub fn calculate_hashrate(hashes: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    hashes as f64 / seconds
}

/// Format hashrate to human-readable string.
pub fn format_hashrate(hashrate: f64) -> String {
    if hashrate >= 1e12 {
        format!("{:.2} TH/s", hashrate / 1e12)
    } else if hashrate >= 1e9 {
        format!("{:.2} GH/s", hashrate / 1e9)
    } else if hashrate >= 1e6 {
        format!("{:.2} MH/s", hashrate / 1e6)
    } else if hashrate >= 1e3 {
        format!("{:.2} KH/s", hashrate / 1e3)
    } else {
        format!("{:.2} H/s", hashrate)
    }
}

/// Estimate time to find a block given hashrate and difficulty.
///
/// Returns seconds (f64::INFINITY if hashrate is 0).
pub fn estimate_block_time(hashrate: f64, difficulty: u128) -> f64 {
    if hashrate <= 0.0 {
        return f64::INFINITY;
    }
    difficulty as f64 / hashrate
}

/// Format a duration in seconds to human-readable string.
pub fn format_duration(seconds: f64) -> String {
    if !seconds.is_finite() {
        return "inf".to_string();
    }

    let total = seconds as u64;
    let days = total / 86400;
    let hours = (total % 86400) / 3600;
    let minutes = (total % 3600) / 60;
    let secs = total % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{}s", secs));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_difficulty_64bit() {
        assert_eq!(parse_difficulty(12345, None, None), 12345u128);
    }

    #[test]
    fn test_parse_difficulty_wide() {
        assert_eq!(
            parse_difficulty(0, Some("0xff"), None),
            255u128
        );
        assert_eq!(
            parse_difficulty(0, Some("100"), None),
            256u128
        );
    }

    #[test]
    fn test_parse_difficulty_top64() {
        assert_eq!(
            parse_difficulty(1, None, Some(1)),
            (1u128 << 64) | 1
        );
    }

    #[test]
    fn test_nonce_roundtrip() {
        let mut blob = vec![0u8; 64];
        let offset = 39;
        set_nonce(&mut blob, 0xDEADBEEF, offset);
        assert_eq!(get_nonce(&blob, offset), 0xDEADBEEF);
    }

    #[test]
    fn test_nonce_zero() {
        let mut blob = vec![0xFFu8; 64];
        let offset = 10;
        set_nonce(&mut blob, 0, offset);
        assert_eq!(get_nonce(&blob, offset), 0);
    }

    #[test]
    fn test_find_nonce_offset() {
        // major_version=1(1 byte), minor_version=1(1 byte),
        // timestamp=100(1 byte), prev_id=32 bytes → offset=35
        let mut blob = vec![0u8; 100];
        blob[0] = 1; // major version (no continuation)
        blob[1] = 1; // minor version (no continuation)
        blob[2] = 100; // timestamp (no continuation)
        let offset = find_nonce_offset(&blob);
        assert_eq!(offset, 35); // 1+1+1+32
    }

    #[test]
    fn test_find_nonce_offset_multivarint() {
        // major_version uses 2-byte varint: [0x80, 0x01] = 128
        let mut blob = vec![0u8; 100];
        blob[0] = 0x80; // continuation bit set
        blob[1] = 0x01; // second byte, no continuation
        blob[2] = 1; // minor version
        blob[3] = 1; // timestamp
        let offset = find_nonce_offset(&blob);
        assert_eq!(offset, 36); // 2+1+1+32
    }

    #[test]
    fn test_extra_nonce() {
        let mut blob = vec![0u8; 100];
        let nonce_data = [0xAA, 0xBB, 0xCC];
        set_extra_nonce(&mut blob, &nonce_data, 50).unwrap();
        assert_eq!(&blob[50..53], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_format_difficulty() {
        assert_eq!(format_difficulty(500), "500");
        assert_eq!(format_difficulty(1_500_000), "1.50 M");
        assert_eq!(format_difficulty(2_500_000_000), "2.50 G");
    }

    #[test]
    fn test_hashrate() {
        assert_eq!(calculate_hashrate(1000, 10.0), 100.0);
        assert_eq!(calculate_hashrate(0, 0.0), 0.0);
    }

    #[test]
    fn test_format_hashrate() {
        assert_eq!(format_hashrate(100.0), "100.00 H/s");
        assert_eq!(format_hashrate(1500.0), "1.50 KH/s");
        assert_eq!(format_hashrate(2_500_000.0), "2.50 MH/s");
    }

    #[test]
    fn test_estimate_block_time() {
        assert_eq!(estimate_block_time(100.0, 1000), 10.0);
        assert!(estimate_block_time(0.0, 1000).is_infinite());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0.0), "0s");
        assert_eq!(format_duration(65.0), "1m 5s");
        assert_eq!(format_duration(3661.0), "1h 1m 1s");
        assert_eq!(format_duration(90061.0), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_block_for_submission() {
        let blob = vec![0u8; 64];
        let hex = format_block_for_submission(&blob, 42, 39);
        let bytes = hex::decode(&hex).unwrap();
        assert_eq!(get_nonce(&bytes, 39), 42);
    }
}
