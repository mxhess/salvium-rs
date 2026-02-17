//! Wallet key management.
//!
//! Derives CryptoNote (legacy) and CARROT key hierarchies from a 32-byte seed.
//! Supports full wallets, view-only wallets (CN and CARROT), and watch-only.

use crate::error::WalletError;
use salvium_types::address::{create_address_raw, AddressError};
use salvium_types::constants::{AddressFormat, AddressType, Network};
use serde::{Deserialize, Serialize};

/// Wallet capability level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletType {
    /// Full wallet: can scan and spend.
    Full,
    /// View-only: can scan outputs but cannot spend.
    ViewOnly,
    /// Watch-only: public keys only, no scanning.
    Watch,
}

/// CryptoNote (legacy) key set.
#[derive(Debug, Clone)]
pub struct CnKeys {
    pub spend_secret_key: Option<[u8; 32]>,
    pub spend_public_key: [u8; 32],
    pub view_secret_key: [u8; 32],
    pub view_public_key: [u8; 32],
}

/// CARROT key hierarchy (9 keys derived from master secret).
#[derive(Debug, Clone)]
pub struct CarrotKeys {
    pub master_secret: Option<[u8; 32]>,
    pub prove_spend_key: Option<[u8; 32]>,
    pub view_balance_secret: [u8; 32],
    pub generate_image_key: [u8; 32],
    pub view_incoming_key: [u8; 32],
    pub generate_address_secret: [u8; 32],
    pub account_spend_pubkey: [u8; 32],
    pub primary_address_view_pubkey: [u8; 32],
    pub account_view_pubkey: [u8; 32],
}

/// Complete wallet key set: CryptoNote + CARROT + network.
pub struct WalletKeys {
    pub wallet_type: WalletType,
    pub seed: Option<[u8; 32]>,
    pub cn: CnKeys,
    pub carrot: CarrotKeys,
    pub network: Network,
}

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v[..32]);
    arr
}

impl WalletKeys {
    /// Create a full wallet from a 32-byte seed.
    ///
    /// Derives both CryptoNote and CARROT key hierarchies.
    pub fn from_seed(seed: [u8; 32], network: Network) -> Self {
        // CryptoNote key derivation:
        //   spend_secret = sc_reduce32(seed)
        //   spend_public = spend_secret * G
        //   view_secret  = sc_reduce32(keccak256(spend_secret))
        //   view_public  = view_secret * G
        let spend_secret_key = to_32(&salvium_crypto::sc_reduce32(&seed));
        let spend_public_key = to_32(&salvium_crypto::scalar_mult_base(&spend_secret_key));
        let view_secret_key = to_32(&salvium_crypto::sc_reduce32(
            &salvium_crypto::keccak256(&spend_secret_key),
        ));
        let view_public_key = to_32(&salvium_crypto::scalar_mult_base(&view_secret_key));

        // CARROT key hierarchy (9 keys from 32-byte master secret = seed).
        let carrot_raw = salvium_crypto::carrot_keys::derive_carrot_keys(&seed);
        let carrot = parse_carrot_full(&carrot_raw);

        Self {
            wallet_type: WalletType::Full,
            seed: Some(seed),
            cn: CnKeys {
                spend_secret_key: Some(spend_secret_key),
                spend_public_key,
                view_secret_key,
                view_public_key,
            },
            carrot,
            network,
        }
    }

    /// Create a full wallet from a 25-word mnemonic.
    pub fn from_mnemonic(words: &str, network: Network) -> Result<Self, WalletError> {
        let result = salvium_types::mnemonic::mnemonic_to_seed(words, None)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        Ok(Self::from_seed(result.seed, network))
    }

    /// Create a CryptoNote-only view-only wallet.
    pub fn view_only(
        view_secret_key: [u8; 32],
        spend_public_key: [u8; 32],
        network: Network,
    ) -> Self {
        let view_public_key = to_32(&salvium_crypto::scalar_mult_base(&view_secret_key));

        Self {
            wallet_type: WalletType::ViewOnly,
            seed: None,
            cn: CnKeys {
                spend_secret_key: None,
                spend_public_key,
                view_secret_key,
                view_public_key,
            },
            carrot: CarrotKeys::empty(),
            network,
        }
    }

    /// Create a view-only wallet with both CN and CARROT scanning capability.
    pub fn view_only_carrot(
        view_secret_key: [u8; 32],
        spend_public_key: [u8; 32],
        view_balance_secret: [u8; 32],
        account_spend_pubkey: [u8; 32],
        network: Network,
    ) -> Self {
        let view_public_key = to_32(&salvium_crypto::scalar_mult_base(&view_secret_key));

        let carrot_raw = salvium_crypto::carrot_keys::derive_carrot_view_only_keys(
            &view_balance_secret,
            &account_spend_pubkey,
        );
        let carrot = parse_carrot_view_only(&carrot_raw);

        Self {
            wallet_type: WalletType::ViewOnly,
            seed: None,
            cn: CnKeys {
                spend_secret_key: None,
                spend_public_key,
                view_secret_key,
                view_public_key,
            },
            carrot,
            network,
        }
    }

    /// Generate a random seed for a new wallet.
    pub fn random_seed() -> [u8; 32] {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    /// Convert the seed back to a 25-word mnemonic (English).
    pub fn to_mnemonic(&self) -> Option<Result<String, WalletError>> {
        self.seed.map(|seed| {
            salvium_types::mnemonic::seed_to_mnemonic(&seed, Some("english"))
                .map_err(|e| WalletError::Other(e.to_string()))
        })
    }

    /// Get the primary CryptoNote (legacy) address.
    pub fn cn_address(&self) -> Result<String, AddressError> {
        create_address_raw(
            self.network,
            AddressFormat::Legacy,
            AddressType::Standard,
            &self.cn.spend_public_key,
            &self.cn.view_public_key,
            None,
        )
    }

    /// Get the primary CARROT address.
    pub fn carrot_address(&self) -> Result<String, AddressError> {
        create_address_raw(
            self.network,
            AddressFormat::Carrot,
            AddressType::Standard,
            &self.carrot.account_spend_pubkey,
            &self.carrot.account_view_pubkey,
            None,
        )
    }

    pub fn can_spend(&self) -> bool {
        self.wallet_type == WalletType::Full
    }

    pub fn can_view(&self) -> bool {
        self.wallet_type != WalletType::Watch
    }
}

impl CarrotKeys {
    /// Empty CARROT keys (for CN-only view wallets).
    pub fn empty() -> Self {
        Self {
            master_secret: None,
            prove_spend_key: None,
            view_balance_secret: [0u8; 32],
            generate_image_key: [0u8; 32],
            view_incoming_key: [0u8; 32],
            generate_address_secret: [0u8; 32],
            account_spend_pubkey: [0u8; 32],
            primary_address_view_pubkey: [0u8; 32],
            account_view_pubkey: [0u8; 32],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.account_spend_pubkey == [0u8; 32]
    }
}

/// Parse full CARROT key derivation output (288 bytes = 9 × 32).
///
/// Layout: masterSecret | proveSpendKey | viewBalanceSecret | generateImageKey
///       | viewIncomingKey | generateAddressSecret | accountSpendPubkey
///       | primaryAddressViewPubkey | accountViewPubkey
fn parse_carrot_full(raw: &[u8; 288]) -> CarrotKeys {
    let get = |i: usize| -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        arr
    };

    CarrotKeys {
        master_secret: Some(get(0)),
        prove_spend_key: Some(get(1)),
        view_balance_secret: get(2),
        generate_image_key: get(3),
        view_incoming_key: get(4),
        generate_address_secret: get(5),
        account_spend_pubkey: get(6),
        primary_address_view_pubkey: get(7),
        account_view_pubkey: get(8),
    }
}

/// Parse CARROT view-only key derivation output (224 bytes = 7 × 32).
///
/// Layout: viewBalanceSecret | viewIncomingKey | generateImageKey
///       | generateAddressSecret | accountSpendPubkey
///       | primaryAddressViewPubkey | accountViewPubkey
fn parse_carrot_view_only(raw: &[u8; 224]) -> CarrotKeys {
    let get = |i: usize| -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        arr
    };

    CarrotKeys {
        master_secret: None,
        prove_spend_key: None,
        view_balance_secret: get(0),
        view_incoming_key: get(1),
        generate_image_key: get(2),
        generate_address_secret: get(3),
        account_spend_pubkey: get(4),
        primary_address_view_pubkey: get(5),
        account_view_pubkey: get(6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_key_derivation() {
        let seed = [42u8; 32];
        let keys1 = WalletKeys::from_seed(seed, Network::Mainnet);
        let keys2 = WalletKeys::from_seed(seed, Network::Mainnet);

        assert_eq!(keys1.cn.spend_public_key, keys2.cn.spend_public_key);
        assert_eq!(keys1.cn.view_public_key, keys2.cn.view_public_key);
        assert_eq!(
            keys1.carrot.account_spend_pubkey,
            keys2.carrot.account_spend_pubkey
        );
    }

    #[test]
    fn test_key_lengths() {
        let seed = [1u8; 32];
        let keys = WalletKeys::from_seed(seed, Network::Mainnet);

        assert!(keys.cn.spend_secret_key.is_some());
        assert!(keys.carrot.master_secret.is_some());
        assert!(keys.can_spend());
        assert!(keys.can_view());
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let keys1 = WalletKeys::from_seed([1u8; 32], Network::Mainnet);
        let keys2 = WalletKeys::from_seed([2u8; 32], Network::Mainnet);

        assert_ne!(keys1.cn.spend_public_key, keys2.cn.spend_public_key);
        assert_ne!(keys1.cn.view_public_key, keys2.cn.view_public_key);
    }

    #[test]
    fn test_cn_and_carrot_keys_differ() {
        let keys = WalletKeys::from_seed([7u8; 32], Network::Mainnet);

        // CN spend public and CARROT account spend pubkey should differ
        // (different derivation paths).
        assert_ne!(
            keys.cn.spend_public_key,
            keys.carrot.account_spend_pubkey
        );
    }

    #[test]
    fn test_view_only_wallet() {
        let full = WalletKeys::from_seed([10u8; 32], Network::Testnet);
        let view = WalletKeys::view_only(
            full.cn.view_secret_key,
            full.cn.spend_public_key,
            Network::Testnet,
        );

        assert_eq!(view.wallet_type, WalletType::ViewOnly);
        assert!(!view.can_spend());
        assert!(view.can_view());
        assert_eq!(view.cn.view_public_key, full.cn.view_public_key);
        assert_eq!(view.cn.spend_public_key, full.cn.spend_public_key);
        assert!(view.cn.spend_secret_key.is_none());
    }

    #[test]
    fn test_carrot_keys_not_empty_for_full() {
        let keys = WalletKeys::from_seed([5u8; 32], Network::Mainnet);
        assert!(!keys.carrot.is_empty());
    }

    #[test]
    fn test_cn_address_generation() {
        let keys = WalletKeys::from_seed([99u8; 32], Network::Testnet);
        let addr = keys.cn_address().expect("should generate CN address");
        assert!(addr.len() > 90);
    }

    #[test]
    fn test_carrot_address_generation() {
        let keys = WalletKeys::from_seed([99u8; 32], Network::Testnet);
        let addr = keys.carrot_address().expect("should generate CARROT address");
        assert!(addr.len() > 90);
    }

    #[test]
    fn test_random_seed() {
        let s1 = WalletKeys::random_seed();
        let s2 = WalletKeys::random_seed();
        assert_ne!(s1, s2);
    }
}
