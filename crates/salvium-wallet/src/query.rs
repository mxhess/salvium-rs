//! Query presets and factory functions for wallet output/transaction filtering.
//!
//! Provides commonly-used query configurations for outputs and transactions.

use salvium_crypto::storage::{OutputQuery, TxQuery};

// ─── Output Query Presets ───────────────────────────────────────────────────

/// Query for unspent, unfrozen outputs.
pub fn unspent_outputs() -> OutputQuery {
    OutputQuery {
        is_spent: Some(false),
        is_frozen: Some(false),
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

/// Query for spent outputs.
pub fn spent_outputs() -> OutputQuery {
    OutputQuery {
        is_spent: Some(true),
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

/// Query for staking outputs (tx_type = 6).
pub fn staking_outputs() -> OutputQuery {
    OutputQuery {
        is_spent: Some(false),
        is_frozen: None,
        asset_type: None,
        tx_type: Some(6),
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

/// Query for yield/return outputs (tx_type = 7).
pub fn yield_outputs() -> OutputQuery {
    OutputQuery {
        is_spent: Some(false),
        is_frozen: None,
        asset_type: None,
        tx_type: Some(7),
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

/// Query for outputs of a specific asset type.
pub fn outputs_by_asset(asset_type: &str) -> OutputQuery {
    OutputQuery {
        is_spent: None,
        is_frozen: None,
        asset_type: Some(asset_type.to_string()),
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

/// Query for outputs in an amount range.
pub fn outputs_in_range(min: u64, max: u64) -> OutputQuery {
    OutputQuery {
        is_spent: None,
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: None,
        subaddress_index: None,
        min_amount: Some(min.to_string()),
        max_amount: Some(max.to_string()),
    }
}

/// Query for outputs by account.
pub fn outputs_by_account(account_index: i64) -> OutputQuery {
    OutputQuery {
        is_spent: Some(false),
        is_frozen: None,
        asset_type: None,
        tx_type: None,
        account_index: Some(account_index),
        subaddress_index: None,
        min_amount: None,
        max_amount: None,
    }
}

// ─── Transaction Query Presets ──────────────────────────────────────────────

/// Query for incoming transactions.
pub fn incoming_txs() -> TxQuery {
    TxQuery {
        is_incoming: Some(true),
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for outgoing transactions.
pub fn outgoing_txs() -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: Some(true),
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for pending (in-pool) transactions.
pub fn pending_txs() -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: Some(true),
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for confirmed transactions.
pub fn confirmed_txs() -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: Some(true),
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for staking transactions (tx_type = 6).
pub fn staking_txs() -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: Some(6),
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for yield/return transactions (tx_type = 7).
pub fn yield_txs() -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: Some(7),
        min_height: None,
        max_height: None,
        tx_hash: None,
    }
}

/// Query for transactions in a height range.
pub fn txs_in_height_range(min: i64, max: i64) -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: Some(min),
        max_height: Some(max),
        tx_hash: None,
    }
}

/// Query for a specific transaction by hash.
pub fn tx_by_hash(hash: &str) -> TxQuery {
    TxQuery {
        is_incoming: None,
        is_outgoing: None,
        is_confirmed: None,
        in_pool: None,
        tx_type: None,
        min_height: None,
        max_height: None,
        tx_hash: Some(hash.to_string()),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Output Query Preset Tests ───────────────────────────────────────

    #[test]
    fn test_unspent_outputs_preset() {
        let q = unspent_outputs();
        assert_eq!(q.is_spent, Some(false));
        assert_eq!(q.is_frozen, Some(false));
        assert!(q.asset_type.is_none());
        assert!(q.tx_type.is_none());
        assert!(q.account_index.is_none());
        assert!(q.subaddress_index.is_none());
        assert!(q.min_amount.is_none());
        assert!(q.max_amount.is_none());
    }

    #[test]
    fn test_spent_outputs_preset() {
        let q = spent_outputs();
        assert_eq!(q.is_spent, Some(true));
        assert!(q.is_frozen.is_none());
        assert!(q.asset_type.is_none());
        assert!(q.tx_type.is_none());
        assert!(q.account_index.is_none());
        assert!(q.subaddress_index.is_none());
        assert!(q.min_amount.is_none());
        assert!(q.max_amount.is_none());
    }

    #[test]
    fn test_staking_outputs_preset() {
        let q = staking_outputs();
        assert_eq!(q.is_spent, Some(false));
        assert_eq!(q.tx_type, Some(6));
        assert!(q.is_frozen.is_none());
        assert!(q.asset_type.is_none());
    }

    #[test]
    fn test_yield_outputs_preset() {
        let q = yield_outputs();
        assert_eq!(q.is_spent, Some(false));
        assert_eq!(q.tx_type, Some(7));
        assert!(q.is_frozen.is_none());
        assert!(q.asset_type.is_none());
    }

    #[test]
    fn test_outputs_by_asset() {
        let q = outputs_by_asset("SAL");
        assert_eq!(q.asset_type, Some("SAL".to_string()));
        assert!(q.is_spent.is_none());
        assert!(q.is_frozen.is_none());
        assert!(q.tx_type.is_none());

        let q2 = outputs_by_asset("USD");
        assert_eq!(q2.asset_type, Some("USD".to_string()));
    }

    #[test]
    fn test_outputs_in_range() {
        let q = outputs_in_range(1000, 50000);
        assert_eq!(q.min_amount, Some("1000".to_string()));
        assert_eq!(q.max_amount, Some("50000".to_string()));
        assert!(q.is_spent.is_none());
        assert!(q.asset_type.is_none());
        assert!(q.tx_type.is_none());
    }

    #[test]
    fn test_outputs_by_account() {
        let q = outputs_by_account(2);
        assert_eq!(q.account_index, Some(2));
        assert_eq!(q.is_spent, Some(false));
        assert!(q.is_frozen.is_none());
        assert!(q.subaddress_index.is_none());
    }

    // ── Transaction Query Preset Tests ──────────────────────────────────

    #[test]
    fn test_incoming_txs_preset() {
        let q = incoming_txs();
        assert_eq!(q.is_incoming, Some(true));
        assert!(q.is_outgoing.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.in_pool.is_none());
        assert!(q.tx_type.is_none());
        assert!(q.min_height.is_none());
        assert!(q.max_height.is_none());
        assert!(q.tx_hash.is_none());
    }

    #[test]
    fn test_outgoing_txs_preset() {
        let q = outgoing_txs();
        assert_eq!(q.is_outgoing, Some(true));
        assert!(q.is_incoming.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.in_pool.is_none());
    }

    #[test]
    fn test_pending_txs_preset() {
        let q = pending_txs();
        assert_eq!(q.in_pool, Some(true));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.tx_type.is_none());
    }

    #[test]
    fn test_confirmed_txs_preset() {
        let q = confirmed_txs();
        assert_eq!(q.is_confirmed, Some(true));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.in_pool.is_none());
    }

    #[test]
    fn test_staking_txs_preset() {
        let q = staking_txs();
        assert_eq!(q.tx_type, Some(6));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.in_pool.is_none());
    }

    #[test]
    fn test_yield_txs_preset() {
        let q = yield_txs();
        assert_eq!(q.tx_type, Some(7));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.in_pool.is_none());
    }

    #[test]
    fn test_txs_in_height_range() {
        let q = txs_in_height_range(100, 500);
        assert_eq!(q.min_height, Some(100));
        assert_eq!(q.max_height, Some(500));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.tx_type.is_none());
        assert!(q.tx_hash.is_none());
    }

    #[test]
    fn test_tx_by_hash() {
        let q = tx_by_hash("abc123def456");
        assert_eq!(q.tx_hash, Some("abc123def456".to_string()));
        assert!(q.is_incoming.is_none());
        assert!(q.is_outgoing.is_none());
        assert!(q.is_confirmed.is_none());
        assert!(q.in_pool.is_none());
        assert!(q.tx_type.is_none());
        assert!(q.min_height.is_none());
        assert!(q.max_height.is_none());
    }
}
