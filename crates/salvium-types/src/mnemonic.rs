//! Mnemonic seed encoding/decoding for Salvium.
//!
//! 25 words = 24 data words + 1 checksum word.
//! Each group of 3 words encodes 4 bytes (32 bits) using a modified base-1626
//! encoding with wrapping for error detection.
//!
//! Supports 12 languages.

use crate::wordlists::{self, WordList, ALL_LANGUAGES};
use thiserror::Error;

/// Word list size (same for all languages).
const WORD_LIST_SIZE: u32 = 1626;

#[derive(Debug, Error)]
pub enum MnemonicError {
    #[error("expected 25 words, got {0}")]
    WrongWordCount(usize),

    #[error("unknown word \"{word}\" at position {position}")]
    UnknownWord { word: String, position: usize },

    #[error("checksum mismatch: expected \"{expected}\", got \"{actual}\"")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("invalid word encoding at position {0}")]
    InvalidEncoding(usize),

    #[error("seed must be 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    #[error("unknown language: {0}")]
    UnknownLanguage(String),

    #[error("could not detect language")]
    LanguageDetectionFailed,
}

/// Result of decoding a mnemonic.
pub struct MnemonicResult {
    pub seed: [u8; 32],
    pub language: &'static WordList,
}

/// CRC32 (same polynomial as zlib/PNG).
fn crc32(data: &str) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in data.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Find a word in a word list. Returns the index or None.
fn find_word(word_list: &WordList, word: &str) -> Option<usize> {
    word_list.words.iter().position(|&w| w == word)
}

/// Detect language from a mnemonic phrase.
pub fn detect_language(mnemonic: &str) -> Result<&'static WordList, MnemonicError> {
    let lowered = mnemonic.to_lowercase();
    let words: Vec<&str> = lowered.split_whitespace().collect();
    if words.is_empty() {
        return Err(MnemonicError::LanguageDetectionFailed);
    }

    // Find all languages containing the first word
    let mut candidates: Vec<(&'static WordList, usize)> = Vec::new();
    for lang in ALL_LANGUAGES {
        if find_word(lang, words[0]).is_some() {
            candidates.push((lang, 1));
        }
    }

    if candidates.is_empty() {
        return Err(MnemonicError::UnknownWord {
            word: words[0].to_string(),
            position: 0,
        });
    }

    if candidates.len() == 1 {
        return Ok(candidates[0].0);
    }

    // Multiple candidates — check more words to disambiguate
    let check_count = words.len().min(5);
    for word in &words[1..check_count] {
        for candidate in &mut candidates {
            if find_word(candidate.0, word).is_some() {
                candidate.1 += 1;
            }
        }
    }

    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(candidates[0].0)
}

/// Get a language by name.
pub fn get_language(name: &str) -> Option<&'static WordList> {
    let normalized = name.to_lowercase();
    ALL_LANGUAGES.iter().find(|l| l.english_name == normalized).copied()
}

/// Decode a 25-word mnemonic to a 256-bit seed.
pub fn mnemonic_to_seed(
    mnemonic: &str,
    language: Option<&str>,
) -> Result<MnemonicResult, MnemonicError> {
    let words: Vec<String> = mnemonic
        .to_lowercase()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    if words.len() != 25 {
        return Err(MnemonicError::WrongWordCount(words.len()));
    }

    // Resolve language
    let word_list = match language {
        Some("auto") | None => detect_language(mnemonic)?,
        Some(name) => get_language(name)
            .ok_or_else(|| MnemonicError::UnknownLanguage(name.to_string()))?,
    };

    // Convert words to indices
    let mut indices = Vec::with_capacity(25);
    for (i, word) in words.iter().enumerate() {
        let idx = find_word(word_list, word).ok_or_else(|| MnemonicError::UnknownWord {
            word: word.clone(),
            position: i + 1,
        })?;
        indices.push(idx as u32);
    }

    // Verify checksum
    let prefix_len = word_list.prefix_length;
    let checksum_data: String = words[..24]
        .iter()
        .map(|w| &w[..w.len().min(prefix_len)])
        .collect::<Vec<_>>()
        .join("");
    let checksum_index = (crc32(&checksum_data) % 24) as usize;

    let expected_prefix = &words[checksum_index][..words[checksum_index].len().min(prefix_len)];
    let actual_prefix = &words[24][..words[24].len().min(prefix_len)];

    if expected_prefix != actual_prefix {
        return Err(MnemonicError::ChecksumMismatch {
            expected: words[checksum_index].clone(),
            actual: words[24].clone(),
        });
    }

    // Decode 24 words to 256-bit seed
    let n = WORD_LIST_SIZE;
    let mut seed = [0u8; 32];

    for i in 0..8 {
        let w1 = indices[i * 3];
        let w2 = indices[i * 3 + 1];
        let w3 = indices[i * 3 + 2];

        let val = w1
            + n * (((n - w1) + w2) % n)
            + n * n * (((n - w2) + w3) % n);

        // Verify encoding
        if val % n != w1 {
            return Err(MnemonicError::InvalidEncoding(i * 3 + 1));
        }

        // Store as 4 little-endian bytes
        seed[i * 4] = (val & 0xFF) as u8;
        seed[i * 4 + 1] = ((val >> 8) & 0xFF) as u8;
        seed[i * 4 + 2] = ((val >> 16) & 0xFF) as u8;
        seed[i * 4 + 3] = ((val >> 24) & 0xFF) as u8;
    }

    Ok(MnemonicResult {
        seed,
        language: word_list,
    })
}

/// Encode a 256-bit seed to a 25-word mnemonic.
pub fn seed_to_mnemonic(
    seed: &[u8; 32],
    language: Option<&str>,
) -> Result<String, MnemonicError> {
    let word_list = match language {
        Some(name) => get_language(name)
            .ok_or_else(|| MnemonicError::UnknownLanguage(name.to_string()))?,
        None => wordlists::english(),
    };

    let n = WORD_LIST_SIZE;
    let mut words = Vec::with_capacity(25);

    for i in 0..8 {
        let val = seed[i * 4] as u32
            | ((seed[i * 4 + 1] as u32) << 8)
            | ((seed[i * 4 + 2] as u32) << 16)
            | ((seed[i * 4 + 3] as u32) << 24);

        let w1 = val % n;
        let w2 = (val / n + w1) % n;
        let w3 = (val / n / n + w2) % n;

        words.push(word_list.words[w1 as usize]);
        words.push(word_list.words[w2 as usize]);
        words.push(word_list.words[w3 as usize]);
    }

    // Calculate checksum word
    let prefix_len = word_list.prefix_length;
    let checksum_data: String = words
        .iter()
        .map(|w| &w[..w.len().min(prefix_len)])
        .collect::<Vec<_>>()
        .join("");
    let checksum_index = (crc32(&checksum_data) % 24) as usize;
    words.push(words[checksum_index]);

    Ok(words.join(" "))
}

/// Validate a mnemonic without returning the seed.
pub fn validate_mnemonic(
    mnemonic: &str,
    language: Option<&str>,
) -> Result<&'static WordList, MnemonicError> {
    let result = mnemonic_to_seed(mnemonic, language)?;
    Ok(result.language)
}

/// Get all available language names.
pub fn available_languages() -> Vec<&'static str> {
    ALL_LANGUAGES.iter().map(|l| l.english_name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        // Known CRC32 values
        assert_eq!(crc32(""), 0);
        assert_ne!(crc32("hello"), 0);
    }

    #[test]
    fn test_seed_mnemonic_roundtrip() {
        let seed = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ];

        let mnemonic = seed_to_mnemonic(&seed, Some("english")).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 25, "mnemonic should have 25 words");

        let result = mnemonic_to_seed(&mnemonic, Some("english")).unwrap();
        assert_eq!(result.seed, seed, "roundtrip should preserve seed");
    }

    #[test]
    fn test_wrong_word_count() {
        let result = mnemonic_to_seed("one two three", Some("english"));
        assert!(matches!(result, Err(MnemonicError::WrongWordCount(3))));
    }

    #[test]
    fn test_available_languages() {
        let langs = available_languages();
        assert_eq!(langs.len(), 12);
        assert!(langs.contains(&"english"));
    }
}
