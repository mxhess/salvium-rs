//! Account and subaddress management.
//!
//! Each account has a major index and a set of subaddresses (minor indices).
//! Subaddress maps are generated in batch from salvium-crypto for both
//! CryptoNote (legacy) and CARROT protocols.

use crate::keys::WalletKeys;

/// A wallet account with pre-computed subaddress maps.
#[derive(Debug, Clone)]
pub struct Account {
    /// Account major index (0 = primary).
    pub index: u32,
    /// Human-readable label.
    pub label: String,
    /// Number of subaddresses generated (minor indices 0..count).
    pub subaddress_count: u32,
}

/// CryptoNote + CARROT subaddress lookup maps.
///
/// Each entry is `(spend_public_key, major_index, minor_index)`.
/// Used by the scanner to detect owned outputs sent to subaddresses.
#[derive(Debug, Clone)]
pub struct SubaddressMaps {
    pub cn: Vec<([u8; 32], u32, u32)>,
    pub carrot: Vec<([u8; 32], u32, u32)>,
}

impl SubaddressMaps {
    /// Generate subaddress maps for all accounts.
    ///
    /// * `num_accounts` — number of accounts (major indices 0..num_accounts).
    /// * `minor_per_account` — subaddresses per account (minor indices 0..minor_per_account).
    pub fn generate(
        keys: &WalletKeys,
        num_accounts: u32,
        minor_per_account: u32,
    ) -> Self {
        let major_count = num_accounts.saturating_sub(1);
        let minor_count = minor_per_account.saturating_sub(1);

        let cn_raw = salvium_crypto::subaddress::cn_subaddress_map_batch(
            &keys.cn.spend_public_key,
            &keys.cn.view_secret_key,
            major_count,
            minor_count,
        );
        let cn = parse_subaddress_map(&cn_raw);

        let carrot = if !keys.carrot.is_empty() {
            let carrot_raw = salvium_crypto::subaddress::carrot_subaddress_map_batch(
                &keys.carrot.account_spend_pubkey,
                &keys.carrot.account_view_pubkey,
                &keys.carrot.generate_address_secret,
                major_count,
                minor_count,
            );
            parse_subaddress_map(&carrot_raw)
        } else {
            vec![]
        };

        Self { cn, carrot }
    }

    /// Number of CN subaddress entries.
    pub fn cn_count(&self) -> usize {
        self.cn.len()
    }

    /// Number of CARROT subaddress entries.
    pub fn carrot_count(&self) -> usize {
        self.carrot.len()
    }

    /// Look up a CN subaddress by spend public key.
    pub fn cn_lookup(&self, spend_pubkey: &[u8; 32]) -> Option<(u32, u32)> {
        self.cn
            .iter()
            .find(|(pk, _, _)| pk == spend_pubkey)
            .map(|(_, major, minor)| (*major, *minor))
    }

    /// Look up a CARROT subaddress by spend public key.
    pub fn carrot_lookup(&self, spend_pubkey: &[u8; 32]) -> Option<(u32, u32)> {
        self.carrot
            .iter()
            .find(|(pk, _, _)| pk == spend_pubkey)
            .map(|(_, major, minor)| (*major, *minor))
    }
}

/// Parse the flat binary subaddress map from salvium-crypto batch functions.
///
/// Format: `[count: u32 LE] [entry_0: 40 bytes] [entry_1: 40 bytes] ...`
/// Each entry: `[spend_pubkey: 32 bytes] [major: u32 LE] [minor: u32 LE]`
pub fn parse_subaddress_map(data: &[u8]) -> Vec<([u8; 32], u32, u32)> {
    if data.len() < 4 {
        return vec![];
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 4 + i * 40;
        if offset + 40 > data.len() {
            break;
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&data[offset..offset + 32]);
        let major = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().unwrap());
        let minor = u32::from_le_bytes(data[offset + 36..offset + 40].try_into().unwrap());
        result.push((pubkey, major, minor));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_map() {
        assert!(parse_subaddress_map(&[]).is_empty());
        assert!(parse_subaddress_map(&[0, 0, 0, 0]).is_empty());
    }

    #[test]
    fn test_parse_single_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        data.extend_from_slice(&[0xAA; 32]); // pubkey
        data.extend_from_slice(&5u32.to_le_bytes()); // major = 5
        data.extend_from_slice(&10u32.to_le_bytes()); // minor = 10

        let result = parse_subaddress_map(&data);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, [0xAA; 32]);
        assert_eq!(result[0].1, 5);
        assert_eq!(result[0].2, 10);
    }

    #[test]
    fn test_parse_multiple_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        for i in 0..3u32 {
            data.extend_from_slice(&[i as u8; 32]);
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&i.to_le_bytes());
        }

        let result = parse_subaddress_map(&data);
        assert_eq!(result.len(), 3);
        assert_eq!(result[2].2, 2);
    }

    #[test]
    fn test_parse_truncated_data() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // claims 2 entries
        data.extend_from_slice(&[0xBB; 32]); // but only partial first entry
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        // Second entry missing — should parse only the first.
        let result = parse_subaddress_map(&data);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_subaddress_maps_generate() {
        let keys = WalletKeys::from_seed([42u8; 32], salvium_types::constants::Network::Testnet);
        let maps = SubaddressMaps::generate(&keys, 1, 5);

        // Account 0 with 5 subaddresses → 5 entries (0,0)..(0,4)
        assert!(maps.cn_count() >= 5);
        assert!(maps.carrot_count() >= 5);
    }

    #[test]
    fn test_subaddress_lookup() {
        let keys = WalletKeys::from_seed([42u8; 32], salvium_types::constants::Network::Testnet);
        let maps = SubaddressMaps::generate(&keys, 1, 3);

        // The first entry (0,0) should be the main address spend pubkey.
        if let Some(entry) = maps.cn.first() {
            let found = maps.cn_lookup(&entry.0);
            assert!(found.is_some());
            assert_eq!(found.unwrap(), (entry.1, entry.2));
        }

        // Random key should not be found.
        assert!(maps.cn_lookup(&[0xFF; 32]).is_none());
    }
}
