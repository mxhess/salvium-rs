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
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Return the first `n` characters of a UTF-8 string (or the whole string if shorter).
fn utf8_prefix(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((byte_pos, _)) => &s[..byte_pos],
        None => s,
    }
}

/// Find a word in a word list (case-insensitive, Unicode-aware). Returns the index or None.
fn find_word(word_list: &WordList, word: &str) -> Option<usize> {
    let lower = word.to_lowercase();
    word_list.words.iter().position(|&w| w.to_lowercase() == lower)
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
        return Err(MnemonicError::UnknownWord { word: words[0].to_string(), position: 0 });
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
    let words: Vec<String> =
        mnemonic.to_lowercase().split_whitespace().map(|s| s.to_string()).collect();

    if words.len() != 25 {
        return Err(MnemonicError::WrongWordCount(words.len()));
    }

    // Resolve language
    let word_list = match language {
        Some("auto") | None => detect_language(mnemonic)?,
        Some(name) => {
            get_language(name).ok_or_else(|| MnemonicError::UnknownLanguage(name.to_string()))?
        }
    };

    // Convert words to indices
    let mut indices = Vec::with_capacity(25);
    for (i, word) in words.iter().enumerate() {
        let idx = find_word(word_list, word)
            .ok_or_else(|| MnemonicError::UnknownWord { word: word.clone(), position: i + 1 })?;
        indices.push(idx as u32);
    }

    // Use canonical wordlist entries for checksum (preserves original case,
    // e.g. German nouns are capitalized: "Augapfel" not "augapfel").
    let canonical: Vec<&str> = indices.iter().map(|&i| word_list.words[i as usize]).collect();

    // Verify checksum
    let prefix_len = word_list.prefix_length;
    let checksum_data: String =
        canonical[..24].iter().map(|w| utf8_prefix(w, prefix_len)).collect::<Vec<_>>().join("");
    let checksum_index = (crc32(&checksum_data) % 24) as usize;

    let expected_prefix = utf8_prefix(canonical[checksum_index], prefix_len);
    let actual_prefix = utf8_prefix(canonical[24], prefix_len);

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

        let val = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);

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

    Ok(MnemonicResult { seed, language: word_list })
}

/// Encode a 256-bit seed to a 25-word mnemonic.
pub fn seed_to_mnemonic(seed: &[u8; 32], language: Option<&str>) -> Result<String, MnemonicError> {
    let word_list = match language {
        Some(name) => {
            get_language(name).ok_or_else(|| MnemonicError::UnknownLanguage(name.to_string()))?
        }
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
    let checksum_data: String =
        words.iter().map(|w| utf8_prefix(w, prefix_len)).collect::<Vec<_>>().join("");
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
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];

        let mnemonic = seed_to_mnemonic(&seed, Some("english")).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 25, "mnemonic should have 25 words");

        let result = mnemonic_to_seed(&mnemonic, Some("english")).unwrap();
        assert_eq!(result.seed, seed, "roundtrip should preserve seed");
    }

    #[test]
    fn test_german_roundtrip() {
        let seed = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];

        // Encode as German (mixed-case wordlist)
        let mnemonic = seed_to_mnemonic(&seed, Some("german")).unwrap();

        // Decode with explicit language
        let result = mnemonic_to_seed(&mnemonic, Some("german")).unwrap();
        assert_eq!(result.seed, seed, "German roundtrip should preserve seed");

        // Decode with auto-detection
        let result2 = mnemonic_to_seed(&mnemonic, None).unwrap();
        assert_eq!(result2.seed, seed, "German auto-detect roundtrip should preserve seed");

        // Decode with user-lowercased input (the actual bug scenario)
        let lowered = mnemonic.to_lowercase();
        let result3 = mnemonic_to_seed(&lowered, None).unwrap();
        assert_eq!(result3.seed, seed, "lowercase German input should still decode correctly");
    }

    #[test]
    fn test_all_languages_roundtrip() {
        let seed = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        ];

        for lang in available_languages() {
            let mnemonic =
                seed_to_mnemonic(&seed, Some(lang)).unwrap_or_else(|e| panic!("{lang}: {e}"));

            // Original-case roundtrip
            let result = mnemonic_to_seed(&mnemonic, Some(lang))
                .unwrap_or_else(|e| panic!("{lang} decode: {e}"));
            assert_eq!(result.seed, seed, "{lang}: roundtrip failed");

            // Lowercased input (user may type all lowercase)
            let lowered = mnemonic.to_lowercase();
            let result2 = mnemonic_to_seed(&lowered, Some(lang))
                .unwrap_or_else(|e| panic!("{lang} lowercase decode: {e}"));
            assert_eq!(result2.seed, seed, "{lang}: lowercase roundtrip failed");

            // Auto-detect from lowercased input
            let result3 = mnemonic_to_seed(&lowered, None)
                .unwrap_or_else(|e| panic!("{lang} auto-detect: {e}"));
            assert_eq!(result3.seed, seed, "{lang}: auto-detect roundtrip failed");
        }
    }

    #[test]
    fn test_wrong_word_count() {
        let result = mnemonic_to_seed("one two three", Some("english"));
        assert!(matches!(result, Err(MnemonicError::WrongWordCount(3))));
    }

    /// Cross-implementation test using the exact German seed from the C++ test suite
    /// (`tests/unit_tests/mnemonics.cpp` — `case_tolerance` test).
    /// Verifies that mixed-case, all-lowercase, and auto-detected decoding all
    /// produce the same seed bytes.
    #[test]
    fn test_cpp_german_case_tolerance() {
        // Exact seed from C++ test: mixed case with umlaut (Grünalge)
        let seed_mixed = "Neubau umarmen Abart umarmen Turban feilen Brett Bargeld \
            Episode Milchkuh Substanz Jahr Armband Maibaum Tand Grünalge Tabak \
            erziehen Federboa Lobrede Tenor Leuchter Curry Diskurs Tenor";

        // Decode mixed-case (as originally generated)
        let result1 = mnemonic_to_seed(seed_mixed, None).expect("mixed-case German decode");
        assert_eq!(result1.language.english_name, "german");

        // All-lowercase (what C++ boost::algorithm::to_lower produces)
        let seed_lower = seed_mixed.to_lowercase();
        let result2 = mnemonic_to_seed(&seed_lower, None).expect("lowercase German decode");
        assert_eq!(result2.language.english_name, "german");

        // Both must produce identical seed bytes
        assert_eq!(result1.seed, result2.seed, "case should not affect seed derivation");

        // Re-encode from the derived seed and verify roundtrip
        let re_encoded = seed_to_mnemonic(&result1.seed, Some("german")).unwrap();
        let result3 = mnemonic_to_seed(&re_encoded, Some("german")).unwrap();
        assert_eq!(result3.seed, result1.seed, "re-encoded German roundtrip failed");
    }

    #[test]
    fn test_available_languages() {
        let langs = available_languages();
        assert_eq!(langs.len(), 12);
        assert!(langs.contains(&"english"));
    }
}
