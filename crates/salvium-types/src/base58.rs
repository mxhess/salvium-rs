//! CryptoNote Base58 encoding/decoding.
//!
//! This is NOT the same as Bitcoin's Base58Check. CryptoNote uses a block-based
//! encoding where data is split into 8-byte blocks, each encoding to exactly
//! 11 Base58 characters. Partial blocks use a size mapping table.
//!
//! Reference: salvium/src/common/base58.cpp

use crate::constants::CHECKSUM_SIZE;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data);
    keccak.finalize(&mut output);
    output.to_vec()
}

/// Base58 alphabet (CryptoNote variant — same as Bitcoin).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Full block size: 8 bytes of data.
const FULL_BLOCK_SIZE: usize = 8;

/// Full encoded block size: 11 Base58 characters.
const FULL_ENCODED_BLOCK_SIZE: usize = 11;

/// Encoded block sizes for partial blocks (index = byte count, value = char count).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// Reverse lookup: encoded char count → decoded byte count. -1 = invalid.
const DECODED_BLOCK_SIZES: [i8; 12] = [0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8];

#[derive(Debug, Error)]
pub enum Base58Error {
    #[error("invalid character '{0}' at position {1}")]
    InvalidCharacter(char, usize),

    #[error("invalid encoded length {0} (last block size {1} is invalid)")]
    InvalidLength(usize, usize),

    #[error("numeric overflow in block {0}")]
    Overflow(usize),

    #[error("address too short ({0} bytes, need >4)")]
    AddressTooShort(usize),

    #[error("checksum mismatch")]
    ChecksumMismatch,

    #[error("varint incomplete or too long")]
    VarintError,
}

/// Build reverse alphabet lookup table at compile time.
const fn build_reverse_alphabet() -> [u8; 128] {
    let mut table = [0xFFu8; 128];
    let mut i = 0;
    while i < 58 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

static REVERSE_ALPHABET: [u8; 128] = build_reverse_alphabet();

/// Encode a single block of bytes to Base58.
fn encode_block(block: &[u8]) -> String {
    let encoded_size = ENCODED_BLOCK_SIZES[block.length_checked()];
    let mut result = vec![ALPHABET[0]; encoded_size];

    let mut num = uint8_be_to_u64(block);
    let mut i = encoded_size;

    while num > 0 {
        i -= 1;
        result[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }

    // SAFETY: all bytes are valid ASCII from ALPHABET
    unsafe { String::from_utf8_unchecked(result) }
}

/// Decode a single Base58 block to bytes.
fn decode_block(block: &[u8], block_index: usize) -> Result<Vec<u8>, Base58Error> {
    if block.len() >= DECODED_BLOCK_SIZES.len() {
        return Err(Base58Error::InvalidLength(0, block.len()));
    }

    let decoded_size = DECODED_BLOCK_SIZES[block.len()];
    if decoded_size < 0 {
        return Err(Base58Error::InvalidLength(0, block.len()));
    }
    let decoded_size = decoded_size as usize;

    if decoded_size == 0 {
        return Ok(Vec::new());
    }

    let mut num: u64 = 0;
    for (i, &ch) in block.iter().enumerate() {
        if ch >= 128 {
            return Err(Base58Error::InvalidCharacter(ch as char, i));
        }
        let digit = REVERSE_ALPHABET[ch as usize];
        if digit == 0xFF {
            return Err(Base58Error::InvalidCharacter(ch as char, i));
        }
        num = num * 58 + digit as u64;
    }

    // Check for overflow on partial blocks
    if decoded_size < FULL_BLOCK_SIZE && num >= (1u64 << (8 * decoded_size)) {
        return Err(Base58Error::Overflow(block_index));
    }

    Ok(u64_to_uint8_be(num, decoded_size))
}

/// Convert up to 8 bytes (big-endian) to u64.
fn uint8_be_to_u64(data: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &byte in data {
        result = (result << 8) | byte as u64;
    }
    result
}

/// Convert u64 to big-endian bytes of given size.
fn u64_to_uint8_be(mut num: u64, size: usize) -> Vec<u8> {
    let mut result = vec![0u8; size];
    for i in (0..size).rev() {
        result[i] = (num & 0xFF) as u8;
        num >>= 8;
    }
    result
}

/// Helper trait to get block length, avoiding confusion with slice methods.
trait BlockLen {
    fn length_checked(&self) -> usize;
}

impl BlockLen for [u8] {
    fn length_checked(&self) -> usize {
        self.len()
    }
}

/// Encode binary data to CryptoNote Base58.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let full_block_count = data.len() / FULL_BLOCK_SIZE;
    let last_block_size = data.len() % FULL_BLOCK_SIZE;

    let mut result = String::with_capacity(
        full_block_count * FULL_ENCODED_BLOCK_SIZE
            + if last_block_size > 0 { ENCODED_BLOCK_SIZES[last_block_size] } else { 0 },
    );

    for i in 0..full_block_count {
        let start = i * FULL_BLOCK_SIZE;
        let block = &data[start..start + FULL_BLOCK_SIZE];
        result.push_str(&encode_block(block));
    }

    if last_block_size > 0 {
        let block = &data[full_block_count * FULL_BLOCK_SIZE..];
        result.push_str(&encode_block(block));
    }

    result
}

/// Decode CryptoNote Base58 string to binary data.
pub fn decode(encoded: &str) -> Result<Vec<u8>, Base58Error> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = encoded.as_bytes();
    let full_block_count = bytes.len() / FULL_ENCODED_BLOCK_SIZE;
    let last_block_size = bytes.len() % FULL_ENCODED_BLOCK_SIZE;

    if last_block_size > 0 {
        let decoded_size = if last_block_size < DECODED_BLOCK_SIZES.len() {
            DECODED_BLOCK_SIZES[last_block_size]
        } else {
            -1
        };
        if decoded_size < 0 {
            return Err(Base58Error::InvalidLength(encoded.len(), last_block_size));
        }
    }

    let mut result = Vec::new();

    for i in 0..full_block_count {
        let start = i * FULL_ENCODED_BLOCK_SIZE;
        let block = &bytes[start..start + FULL_ENCODED_BLOCK_SIZE];
        result.extend_from_slice(&decode_block(block, i)?);
    }

    if last_block_size > 0 {
        let block = &bytes[full_block_count * FULL_ENCODED_BLOCK_SIZE..];
        result.extend_from_slice(&decode_block(block, full_block_count)?);
    }

    Ok(result)
}

/// Encode a varint (variable-length integer, LEB128 unsigned).
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            break;
        }
    }
    bytes
}

/// Decode a varint from the start of data. Returns (value, bytes_read).
pub fn decode_varint(data: &[u8]) -> Result<(u64, usize), Base58Error> {
    if data.is_empty() {
        return Err(Base58Error::VarintError);
    }

    let mut value: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &byte) in data.iter().enumerate().take(10) {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }

    Err(Base58Error::VarintError)
}

/// Encode an address with varint tag/prefix and Keccak-256 checksum.
pub fn encode_address(tag: u64, data: &[u8]) -> String {
    let tag_bytes = encode_varint(tag);
    let mut combined = Vec::with_capacity(tag_bytes.len() + data.len());
    combined.extend_from_slice(&tag_bytes);
    combined.extend_from_slice(data);

    // Checksum: first 4 bytes of Keccak-256
    let hash = keccak256(&combined);
    let checksum = &hash[..CHECKSUM_SIZE];

    let mut with_checksum = Vec::with_capacity(combined.len() + CHECKSUM_SIZE);
    with_checksum.extend_from_slice(&combined);
    with_checksum.extend_from_slice(checksum);

    encode(&with_checksum)
}

/// Decode an address, verifying checksum and extracting tag and data.
pub fn decode_address(address: &str) -> Result<(u64, Vec<u8>), Base58Error> {
    let decoded = decode(address)?;
    if decoded.len() <= CHECKSUM_SIZE {
        return Err(Base58Error::AddressTooShort(decoded.len()));
    }

    let payload = &decoded[..decoded.len() - CHECKSUM_SIZE];
    let checksum = &decoded[decoded.len() - CHECKSUM_SIZE..];

    // Verify checksum
    let hash = keccak256(payload);
    if &hash[..CHECKSUM_SIZE] != checksum {
        return Err(Base58Error::ChecksumMismatch);
    }

    // Decode varint tag
    let (tag, bytes_read) = decode_varint(payload)?;
    let data = payload[bytes_read..].to_vec();

    Ok((tag, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 16384, 0x3ef318, 0xf343eb318] {
            let encoded = encode_varint(val);
            let (decoded, bytes_read) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
            assert_eq!(bytes_read, encoded.len());
        }
    }

    #[test]
    fn test_base58_roundtrip() {
        let data = vec![0u8; 32];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);

        let data = (0..69u8).collect::<Vec<_>>();
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58_empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_address_roundtrip() {
        // Use a known mainnet standard prefix
        let tag = 0x3ef318u64;
        let data = vec![0xAB; 64]; // 2 × 32-byte keys
        let encoded = encode_address(tag, &data);
        let (decoded_tag, decoded_data) = decode_address(&encoded).unwrap();
        assert_eq!(decoded_tag, tag);
        assert_eq!(decoded_data, data);
    }

    #[test]
    fn test_checksum_mismatch() {
        let tag = 0x3ef318u64;
        let data = vec![0xAB; 64];
        let mut encoded = encode_address(tag, &data);
        // Corrupt last character
        let bytes = unsafe { encoded.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'1' { b'2' } else { b'1' };
        assert!(decode_address(&encoded).is_err());
    }
}
