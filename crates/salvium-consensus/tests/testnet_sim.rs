//! Testnet simulation integration tests.
//!
//! Tests miner transaction creation, genesis block coinbase,
//! block reward with premine, and protocol TX creation.

use salvium_types::consensus::{
    block_reward, PREMINE_AMOUNT, MONEY_SUPPLY,
    EMISSION_SPEED_FACTOR_PER_MINUTE, DIFFICULTY_TARGET_V2,
    hf_version_for_height, MINED_MONEY_UNLOCK_WINDOW,
};
use salvium_types::constants::{TxType, Network, HfVersion};
use salvium_consensus::validation::{
    validate_tx_type_and_version, validate_miner_tx_structure,
    validate_miner_tx_reward, validate_output_count,
};

/// Simulated miner transaction output.
struct MinerTxOutput {
    amount: u64,
    tx_type: TxType,
}

/// Create a miner transaction for a given height.
/// After genesis, 20% of the block reward goes to stake deduction.
fn create_miner_transaction(
    height: u64,
    median_weight: u64,
    already_generated_coins: u64,
    network: Network,
) -> Option<MinerTxOutput> {
    let hf = hf_version_for_height(height, network);
    let reward = block_reward(median_weight, 0, already_generated_coins, hf)?;

    // Genesis block: full premine, no stake deduction
    if already_generated_coins == 0 {
        return Some(MinerTxOutput {
            amount: reward,
            tx_type: TxType::Miner,
        });
    }

    // Post-genesis: 20% stake deduction
    let stake_deduction = reward / 5;
    let miner_reward = reward - stake_deduction;

    Some(MinerTxOutput {
        amount: miner_reward,
        tx_type: TxType::Miner,
    })
}

/// Create an empty protocol transaction (for stake returns, yield, etc.)
fn create_protocol_transaction(_height: u64, amount: u64) -> MinerTxOutput {
    MinerTxOutput {
        amount,
        tx_type: TxType::Protocol,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_genesis_block_coinbase() {
    let tx = create_miner_transaction(0, 0, 0, Network::Testnet).unwrap();
    assert_eq!(tx.amount, PREMINE_AMOUNT);
    assert_eq!(tx.tx_type, TxType::Miner);
}

#[test]
fn test_post_genesis_stake_deduction() {
    // After genesis, miner gets 80% of reward
    let hf = hf_version_for_height(1, Network::Testnet);
    let tx = create_miner_transaction(1, 300_000, PREMINE_AMOUNT, Network::Testnet).unwrap();
    let full_reward = block_reward(300_000, 0, PREMINE_AMOUNT, hf).unwrap();
    let expected = full_reward - full_reward / 5;
    assert_eq!(tx.amount, expected);
}

#[test]
fn test_block_reward_decreases() {
    // Block reward should decrease as more coins are generated
    let hf = hf_version_for_height(1, Network::Testnet);
    let r1 = block_reward(300_000, 0, PREMINE_AMOUNT, hf).unwrap();
    let r2 = block_reward(300_000, 0, PREMINE_AMOUNT + r1 * 1000, hf).unwrap();
    assert!(r2 < r1);
}

#[test]
fn test_protocol_transaction_creation() {
    let tx = create_protocol_transaction(100, 50_000_000);
    assert_eq!(tx.amount, 50_000_000);
    assert_eq!(tx.tx_type, TxType::Protocol);
}

#[test]
fn test_miner_tx_validation_at_genesis() {
    let result = validate_miner_tx_structure(0, 0, 2, TxType::Miner, 1);
    assert!(result.is_ok());
}

#[test]
fn test_miner_tx_reward_validation() {
    let hf = hf_version_for_height(1, Network::Testnet);
    let reward = block_reward(300_000, 0, PREMINE_AMOUNT, hf).unwrap();
    // Miner gets 80%, which must be <= base_reward + fees
    let miner_amount = reward - reward / 5;
    assert!(validate_miner_tx_reward(miner_amount, reward, 0).is_ok());
}

#[test]
fn test_coinbase_maturity() {
    // Coinbase outputs need MINED_MONEY_UNLOCK_WINDOW (60) confirmations
    assert_eq!(MINED_MONEY_UNLOCK_WINDOW, 60);
}

#[test]
fn test_simulate_chain_growth() {
    // Simulate 10 blocks of chain growth
    let mut generated = 0u64;
    let mut rewards = Vec::new();

    for height in 0..10 {
        let hf = hf_version_for_height(height, Network::Testnet);
        let reward = block_reward(300_000, 0, generated, hf).unwrap();
        rewards.push(reward);
        generated += reward;
    }

    // Genesis should be the premine
    assert_eq!(rewards[0], PREMINE_AMOUNT);
    // Subsequent rewards should be much smaller
    assert!(rewards[1] < PREMINE_AMOUNT / 10);
    // Total generated should not exceed money supply
    assert!(generated < MONEY_SUPPLY);
}
