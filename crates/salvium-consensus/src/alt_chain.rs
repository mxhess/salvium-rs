//! Alternative chain management and reorganisation handling.
//!
//! Tracks blocks that do not extend the current main-chain tip, organises
//! them into alternative chains, and provides the data structures needed
//! to evaluate and execute chain switches (reorgs).
//!
//! Reference: salvium/src/cryptonote_core/blockchain.cpp,
//!            test/blockchain.test.js

use std::collections::{HashMap, HashSet};

// =============================================================================
// Constants
// =============================================================================

/// Alt blocks whose height is more than this many blocks behind the main-chain
/// tip are pruned to keep memory bounded.
const ALT_BLOCK_PRUNE_DEPTH: u64 = 720;

// =============================================================================
// BlockExtendedInfo
// =============================================================================

/// Extended block information used for alt-chain tracking.
///
/// Stores the fields required to evaluate cumulative difficulty along an
/// alternative chain without needing the full block body.
#[derive(Debug, Clone, Default)]
pub struct BlockExtendedInfo {
    /// Block hash.
    pub hash: String,
    /// Hash of the previous block.
    pub prev_hash: String,
    /// Height of this block.
    pub height: u64,
    /// Block timestamp.
    pub timestamp: u64,
    /// Per-block difficulty.
    pub difficulty: u128,
    /// Cumulative difficulty up to and including this block.
    pub cumulative_difficulty: u128,
    /// Serialised block weight (bytes).
    pub weight: u64,
}

// =============================================================================
// BlockVerificationContext
// =============================================================================

/// Result of processing a new block through `handle_block`.
///
/// Exactly one of the boolean flags will be `true` after a call unless the
/// block is silently ignored.
#[derive(Debug, Clone, Default)]
pub struct BlockVerificationContext {
    /// Block was accepted and extends the main chain tip.
    pub added_to_main_chain: bool,
    /// Block was accepted and stored as an alternative-chain block.
    pub added_to_alt_chain: bool,
    /// Block was rejected because it or its parent is invalid/orphaned.
    pub marked_as_orphaned: bool,
    /// Block hash was already present on the main or alt chain.
    pub already_exists: bool,
}

// =============================================================================
// ReorgEvent
// =============================================================================

/// Describes a chain reorganisation that has occurred.
#[derive(Debug, Clone)]
pub struct ReorgEvent {
    /// Height at which the two chains diverged.
    pub split_height: u64,
    /// Main-chain height before the reorg.
    pub old_height: u64,
    /// Main-chain height after the reorg.
    pub new_height: u64,
    /// Number of blocks disconnected (rolled back) from the old chain.
    pub blocks_disconnected: u64,
    /// Number of blocks connected from the alternative chain.
    pub blocks_connected: u64,
}

// =============================================================================
// AlternativeChainManager
// =============================================================================

/// Manages alternative chains and handles reorganisations.
///
/// Maintains a set of blocks that did not extend the current main-chain tip
/// but whose parents are known (either on the main chain or on an existing
/// alternative chain). Blocks with unknown parents are classified as orphans.
pub struct AlternativeChainManager {
    /// Known block hashes on the main chain, mapping hash to height.
    main_chain_hashes: HashMap<String, u64>,
    /// Alternative blocks keyed by their hash.
    alt_blocks: HashMap<String, BlockExtendedInfo>,
    /// Set of block hashes known to be invalid.
    invalid_blocks: HashSet<String>,
    /// Current main-chain height (number of blocks).
    main_chain_height: u64,
    /// Cumulative difficulty at the main-chain tip.
    main_chain_cum_diff: u128,
}

impl AlternativeChainManager {
    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// Create an empty manager with no chain data.
    pub fn new() -> Self {
        Self {
            main_chain_hashes: HashMap::new(),
            alt_blocks: HashMap::new(),
            invalid_blocks: HashSet::new(),
            main_chain_height: 0,
            main_chain_cum_diff: 0,
        }
    }

    /// Initialise (or re-initialise) the manager from main-chain data.
    ///
    /// `hashes` is a slice of `(hash, height)` pairs representing every block
    /// on the current main chain. `height` is the current tip height, and
    /// `cum_diff` is the cumulative difficulty at that tip.
    pub fn set_main_chain(
        &mut self,
        hashes: &[(String, u64)],
        height: u64,
        cum_diff: u128,
    ) {
        self.main_chain_hashes.clear();
        for (h, ht) in hashes {
            self.main_chain_hashes.insert(h.clone(), *ht);
        }
        self.main_chain_height = height;
        self.main_chain_cum_diff = cum_diff;
    }

    // -------------------------------------------------------------------------
    // Block processing
    // -------------------------------------------------------------------------

    /// Process a new block and determine where it belongs.
    ///
    /// # Returns
    ///
    /// A `BlockVerificationContext` describing what happened:
    /// - `added_to_main_chain` -- the block extends the current tip.
    /// - `added_to_alt_chain`  -- the block forks from a known point and was
    ///   stored for potential future reorg evaluation.
    /// - `marked_as_orphaned`  -- the block or its parent is unknown/invalid.
    /// - `already_exists`      -- the block hash is already tracked.
    pub fn handle_block(
        &mut self,
        hash: &str,
        prev_hash: &str,
        timestamp: u64,
        difficulty: u128,
        weight: u64,
    ) -> BlockVerificationContext {
        let mut bvc = BlockVerificationContext::default();

        // --- Known-invalid? ---------------------------------------------------
        if self.invalid_blocks.contains(hash) {
            bvc.marked_as_orphaned = true;
            return bvc;
        }

        // --- Duplicate? -------------------------------------------------------
        if self.main_chain_hashes.contains_key(hash) || self.alt_blocks.contains_key(hash) {
            bvc.already_exists = true;
            return bvc;
        }

        // --- Parent invalid? --------------------------------------------------
        if self.invalid_blocks.contains(prev_hash) {
            self.invalid_blocks.insert(hash.to_string());
            bvc.marked_as_orphaned = true;
            return bvc;
        }

        // --- Extends main-chain tip? ------------------------------------------
        // The tip is identified as the block whose height equals
        // `main_chain_height - 1` (0-indexed), but the simplest check is
        // whether `prev_hash` maps to `main_chain_height - 1` in our hash map
        // (the most recent entry added).
        if let Some(&parent_height) = self.main_chain_hashes.get(prev_hash) {
            if parent_height == self.main_chain_height.saturating_sub(1) {
                // Extends tip.
                let new_height = self.main_chain_height; // 0-indexed: next slot
                self.main_chain_cum_diff += difficulty;
                self.main_chain_height = new_height + 1;
                self.main_chain_hashes
                    .insert(hash.to_string(), new_height);
                bvc.added_to_main_chain = true;

                // Prune stale alt blocks while we are here.
                self.prune_alt_blocks();

                return bvc;
            }

            // Parent is on main chain but is not the tip -- fork.
            let parent_cum_diff = self.cum_diff_at_main_height(parent_height);
            let bei = BlockExtendedInfo {
                hash: hash.to_string(),
                prev_hash: prev_hash.to_string(),
                height: parent_height + 1,
                timestamp,
                difficulty,
                cumulative_difficulty: parent_cum_diff + difficulty,
                weight,
            };
            self.alt_blocks.insert(hash.to_string(), bei);
            bvc.added_to_alt_chain = true;
            return bvc;
        }

        // --- Parent on an existing alt chain? ---------------------------------
        if let Some(parent_bei) = self.alt_blocks.get(prev_hash).cloned() {
            let bei = BlockExtendedInfo {
                hash: hash.to_string(),
                prev_hash: prev_hash.to_string(),
                height: parent_bei.height + 1,
                timestamp,
                difficulty,
                cumulative_difficulty: parent_bei.cumulative_difficulty + difficulty,
                weight,
            };
            self.alt_blocks.insert(hash.to_string(), bei);
            bvc.added_to_alt_chain = true;
            return bvc;
        }

        // --- Orphan -----------------------------------------------------------
        bvc.marked_as_orphaned = true;
        bvc
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// Returns `true` when `hash` is present on either the main chain or any
    /// tracked alternative chain.
    pub fn is_known_block(&self, hash: &str) -> bool {
        self.main_chain_hashes.contains_key(hash) || self.alt_blocks.contains_key(hash)
    }

    /// Number of blocks currently stored on alternative chains.
    pub fn get_alt_block_count(&self) -> usize {
        self.alt_blocks.len()
    }

    /// Current main-chain height as known by the manager.
    pub fn main_chain_height(&self) -> u64 {
        self.main_chain_height
    }

    /// Current main-chain cumulative difficulty.
    pub fn main_chain_cum_diff(&self) -> u128 {
        self.main_chain_cum_diff
    }

    // -------------------------------------------------------------------------
    // Flush / invalidation
    // -------------------------------------------------------------------------

    /// Remove all tracked alternative blocks.
    pub fn flush_alt_blocks(&mut self) {
        self.alt_blocks.clear();
    }

    /// Clear the set of known-invalid block hashes.
    pub fn flush_invalid_blocks(&mut self) {
        self.invalid_blocks.clear();
    }

    /// Mark a block hash as invalid so that it (and any future children) will
    /// be rejected.
    pub fn add_invalid_block(&mut self, hash: &str) {
        self.invalid_blocks.insert(hash.to_string());
    }

    /// Returns `true` if the given hash has been marked invalid.
    pub fn is_invalid_block(&self, hash: &str) -> bool {
        self.invalid_blocks.contains(hash)
    }

    /// Number of hashes in the invalid-block set.
    pub fn invalid_block_count(&self) -> usize {
        self.invalid_blocks.len()
    }

    // -------------------------------------------------------------------------
    // Alt-chain building
    // -------------------------------------------------------------------------

    /// Walk backwards from `hash` through the alt-block map until a main-chain
    /// block is reached.
    ///
    /// # Returns
    ///
    /// `(alt_chain, split_height)` where `alt_chain` contains the
    /// `BlockExtendedInfo` entries in *ascending* height order (oldest first),
    /// and `split_height` is the height on the main chain where the fork
    /// occurred.
    ///
    /// If `hash` itself is on the main chain, `alt_chain` will be empty and
    /// `split_height` will be the height of that hash.
    pub fn build_alt_chain(&self, hash: &str) -> (Vec<BlockExtendedInfo>, u64) {
        // If the hash is directly on the main chain, return immediately.
        if let Some(&h) = self.main_chain_hashes.get(hash) {
            return (Vec::new(), h);
        }

        let mut chain: Vec<BlockExtendedInfo> = Vec::new();
        let mut current = hash.to_string();

        loop {
            if let Some(bei) = self.alt_blocks.get(&current) {
                chain.push(bei.clone());
                let parent = &bei.prev_hash;
                // Check if parent is on the main chain.
                if let Some(&parent_height) = self.main_chain_hashes.get(parent.as_str()) {
                    // We've reached the split point. Reverse so oldest is first.
                    chain.reverse();
                    return (chain, parent_height);
                }
                current = parent.clone();
            } else {
                // Should not happen for a well-formed alt chain; treat the
                // current hash as the split at height 0.
                chain.reverse();
                return (chain, 0);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Rollback helpers
    // -------------------------------------------------------------------------

    /// Store a set of blocks that were disconnected during a failed chain
    /// switch, effectively re-applying them to the main chain tracking.
    ///
    /// `popped_blocks` should be in the order they were removed (tip first),
    /// and `restore_height` is the height the chain was rolled back to before
    /// the switch attempt.
    pub fn rollback_chain_switching(
        &mut self,
        popped_blocks: &[BlockExtendedInfo],
        restore_height: u64,
    ) {
        // Re-apply the popped blocks in reverse order (lowest height first).
        let mut height = restore_height;
        let mut cum_diff = self.cum_diff_at_main_height(height.saturating_sub(1));

        // The popped blocks arrive tip-first; iterate in reverse to go from
        // lowest height to highest.
        for bei in popped_blocks.iter().rev() {
            cum_diff += bei.difficulty;
            self.main_chain_hashes.insert(bei.hash.clone(), height);
            height += 1;
        }

        self.main_chain_height = height;
        self.main_chain_cum_diff = cum_diff;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Estimate cumulative difficulty at a given main-chain height.
    ///
    /// We use a simple linear interpolation from the tip since we do not
    /// store per-height cumulative difficulty in this manager. When `height`
    /// equals `main_chain_height - 1` this returns `main_chain_cum_diff`.
    fn cum_diff_at_main_height(&self, height: u64) -> u128 {
        if self.main_chain_height == 0 {
            return 0;
        }
        // Average difficulty per block.
        let avg = self.main_chain_cum_diff / self.main_chain_height as u128;
        avg * (height + 1) as u128
    }

    /// Remove alt blocks whose height is more than `ALT_BLOCK_PRUNE_DEPTH`
    /// behind the current main-chain tip.
    fn prune_alt_blocks(&mut self) {
        if self.main_chain_height <= ALT_BLOCK_PRUNE_DEPTH {
            return;
        }
        let cutoff = self.main_chain_height - ALT_BLOCK_PRUNE_DEPTH;
        self.alt_blocks.retain(|_, bei| bei.height >= cutoff);
    }
}

impl Default for AlternativeChainManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --------------------------------------------------------------

    /// Build a main-chain manager with `n` blocks, each having difficulty 100
    /// and weight 300_000.
    fn build_main_chain(n: u64) -> (AlternativeChainManager, Vec<String>) {
        let mut acm = AlternativeChainManager::new();
        let mut hashes = Vec::new();
        let mut pairs: Vec<(String, u64)> = Vec::new();
        for i in 0..n {
            let h = format!("main_{:04}", i);
            hashes.push(h.clone());
            pairs.push((h, i));
        }
        let cum_diff = n as u128 * 100;
        acm.set_main_chain(&pairs, n, cum_diff);
        (acm, hashes)
    }

    // ---- BlockExtendedInfo --------------------------------------------------

    #[test]
    fn block_extended_info_default() {
        let bei = BlockExtendedInfo::default();
        assert!(bei.hash.is_empty());
        assert!(bei.prev_hash.is_empty());
        assert_eq!(bei.height, 0);
        assert_eq!(bei.timestamp, 0);
        assert_eq!(bei.difficulty, 0);
        assert_eq!(bei.cumulative_difficulty, 0);
        assert_eq!(bei.weight, 0);
    }

    #[test]
    fn block_extended_info_with_data() {
        let bei = BlockExtendedInfo {
            hash: "abc".into(),
            prev_hash: "def".into(),
            height: 10,
            timestamp: 1234,
            difficulty: 500,
            cumulative_difficulty: 1000,
            weight: 300_000,
        };
        assert_eq!(bei.hash, "abc");
        assert_eq!(bei.height, 10);
        assert_eq!(bei.cumulative_difficulty, 1000);
    }

    // ---- BlockVerificationContext --------------------------------------------

    #[test]
    fn block_verification_context_defaults() {
        let bvc = BlockVerificationContext::default();
        assert!(!bvc.added_to_main_chain);
        assert!(!bvc.added_to_alt_chain);
        assert!(!bvc.marked_as_orphaned);
        assert!(!bvc.already_exists);
    }

    // ---- Main chain: extending tip ------------------------------------------

    #[test]
    fn block_extending_main_chain_tip() {
        let (mut acm, hashes) = build_main_chain(5);
        assert_eq!(acm.main_chain_height(), 5);

        let bvc = acm.handle_block("new_block_hash", &hashes[4], 1600, 100, 300_000);

        assert!(bvc.added_to_main_chain);
        assert!(!bvc.added_to_alt_chain);
        assert_eq!(acm.main_chain_height(), 6);
    }

    // ---- Main chain: duplicate detection ------------------------------------

    #[test]
    fn duplicate_block_detected() {
        let (mut acm, hashes) = build_main_chain(5);

        let bvc = acm.handle_block(&hashes[2], "irrelevant", 0, 0, 0);
        assert!(bvc.already_exists);
    }

    // ---- Main chain: unknown parent → orphaned ------------------------------

    #[test]
    fn unknown_parent_is_orphaned() {
        let (mut acm, _hashes) = build_main_chain(5);

        let bvc = acm.handle_block("orphan_hash", "unknown_parent", 1600, 100, 300_000);
        assert!(bvc.marked_as_orphaned);
    }

    // ---- Main chain: invalid parent → child marked invalid ------------------

    #[test]
    fn invalid_parent_marks_child_invalid() {
        let (mut acm, _hashes) = build_main_chain(5);

        acm.add_invalid_block("bad_parent");
        let bvc = acm.handle_block("child_of_bad", "bad_parent", 1600, 100, 300_000);

        assert!(bvc.marked_as_orphaned);
        assert!(acm.is_invalid_block("child_of_bad"));
    }

    // ---- Main chain: known invalid block rejected ---------------------------

    #[test]
    fn known_invalid_block_rejected() {
        let (mut acm, _hashes) = build_main_chain(5);

        acm.add_invalid_block("known_bad");
        let bvc = acm.handle_block("known_bad", "some_parent", 0, 0, 0);
        assert!(bvc.marked_as_orphaned);
    }

    // ---- Alt chain: fork from main chain ------------------------------------

    #[test]
    fn block_forking_from_main_chain_added_to_alt() {
        let (mut acm, hashes) = build_main_chain(10);

        // Fork at height 7 -- parent is main_0007 which is at height 7 but not
        // the tip (height 9), so this creates an alt block.
        let bvc = acm.handle_block("alt_1", &hashes[7], 2000, 50, 300_000);

        assert!(bvc.added_to_alt_chain);
        assert_eq!(acm.get_alt_block_count(), 1);
    }

    // ---- Alt chain: extension stored ----------------------------------------

    #[test]
    fn alt_chain_extension_stored() {
        let (mut acm, hashes) = build_main_chain(10);

        // Fork at height 7.
        acm.handle_block("alt_1", &hashes[7], 2000, 50, 300_000);

        // Extend the alt chain.
        let bvc = acm.handle_block("alt_2", "alt_1", 2120, 50, 300_000);

        assert!(bvc.added_to_alt_chain);
        assert_eq!(acm.get_alt_block_count(), 2);
    }

    // ---- Utility: is_known_block --------------------------------------------

    #[test]
    fn is_known_block_checks_main_and_alt() {
        let (mut acm, hashes) = build_main_chain(5);

        assert!(acm.is_known_block(&hashes[0]));
        assert!(!acm.is_known_block("unknown"));

        // Add an alt block, then check it.
        acm.handle_block("alt_known", &hashes[3], 2000, 50, 300_000);
        assert!(acm.is_known_block("alt_known"));
    }

    // ---- Utility: get_alt_block_count ---------------------------------------

    #[test]
    fn get_alt_block_count_returns_correct_count() {
        let (mut acm, hashes) = build_main_chain(5);

        assert_eq!(acm.get_alt_block_count(), 0);

        acm.handle_block("alt_count", &hashes[3], 2000, 50, 300_000);
        assert_eq!(acm.get_alt_block_count(), 1);
    }

    // ---- Utility: flush_alt_blocks ------------------------------------------

    #[test]
    fn flush_alt_blocks_clears_all() {
        let (mut acm, hashes) = build_main_chain(5);

        acm.handle_block("alt_flush", &hashes[3], 2000, 50, 300_000);
        assert_eq!(acm.get_alt_block_count(), 1);

        acm.flush_alt_blocks();
        assert_eq!(acm.get_alt_block_count(), 0);
    }

    // ---- Utility: flush_invalid_blocks --------------------------------------

    #[test]
    fn flush_invalid_blocks_clears_set() {
        let (mut acm, _hashes) = build_main_chain(5);

        acm.add_invalid_block("bad1");
        acm.add_invalid_block("bad2");
        assert_eq!(acm.invalid_block_count(), 2);

        acm.flush_invalid_blocks();
        assert_eq!(acm.invalid_block_count(), 0);
    }

    // ---- build_alt_chain: from alt blocks -----------------------------------

    #[test]
    fn build_alt_chain_from_alt_blocks() {
        let (mut acm, hashes) = build_main_chain(10);

        // Add 3 alt blocks forking from height 6.
        acm.handle_block("chain_a1", &hashes[6], 2000, 50, 300_000);
        acm.handle_block("chain_a2", "chain_a1", 2120, 50, 300_000);
        acm.handle_block("chain_a3", "chain_a2", 2240, 50, 300_000);

        let (alt_chain, split_height) = acm.build_alt_chain("chain_a3");

        // Walking back: chain_a3 → chain_a2 → chain_a1 → hashes[6] (main).
        assert_eq!(alt_chain.len(), 3);
        assert_eq!(split_height, 6);
        // Verify ordering: oldest first.
        assert_eq!(alt_chain[0].hash, "chain_a1");
        assert_eq!(alt_chain[1].hash, "chain_a2");
        assert_eq!(alt_chain[2].hash, "chain_a3");
    }

    // ---- build_alt_chain: direct from main chain ----------------------------

    #[test]
    fn build_alt_chain_direct_from_main() {
        let (acm, hashes) = build_main_chain(5);

        let (alt_chain, split_height) = acm.build_alt_chain(&hashes[3]);
        assert!(alt_chain.is_empty());
        assert_eq!(split_height, 3);
    }

    // ---- Pruning: old alt blocks removed ------------------------------------

    #[test]
    fn old_alt_blocks_are_pruned() {
        let (mut acm, hashes) = build_main_chain(5);

        // Add an alt block forking from height 1.
        acm.handle_block("old_alt", &hashes[1], 1500, 50, 300_000);
        assert_eq!(acm.get_alt_block_count(), 1);

        // Forcibly set its height to 0 so it will be considered ancient.
        acm.alt_blocks.get_mut("old_alt").unwrap().height = 0;

        // Advance the main chain well past the prune depth by adding many
        // blocks through handle_block so pruning triggers.
        let mut prev = hashes[4].clone();
        for i in 0..800u64 {
            let h = format!("prune_{:04}", i);
            // Each call extends the tip, incrementing main_chain_height and
            // triggering prune_alt_blocks().
            acm.handle_block(&h, &prev, 2000 + i * 120, 100, 300_000);
            prev = h;
        }

        // The ancient alt block should have been pruned.
        assert!(!acm.alt_blocks.contains_key("old_alt"));
    }

    // ---- Rollback mechanics -------------------------------------------------

    #[test]
    fn rollback_chain_switching_restores_blocks() {
        let (mut acm, _hashes) = build_main_chain(5);

        // Simulate popping the top 2 blocks (heights 3 and 4, 0-indexed).
        let popped = vec![
            BlockExtendedInfo {
                hash: "main_0004".into(),
                prev_hash: "main_0003".into(),
                height: 4,
                timestamp: 1480,
                difficulty: 100,
                cumulative_difficulty: 500,
                weight: 300_000,
            },
            BlockExtendedInfo {
                hash: "main_0003".into(),
                prev_hash: "main_0002".into(),
                height: 3,
                timestamp: 1360,
                difficulty: 100,
                cumulative_difficulty: 400,
                weight: 300_000,
            },
        ];

        // Remove the two blocks from the manager's main chain tracking.
        acm.main_chain_hashes.remove("main_0003");
        acm.main_chain_hashes.remove("main_0004");
        acm.main_chain_height = 3;
        // Recalculate cum_diff for height 3 (blocks 0..3 → 300).
        acm.main_chain_cum_diff = 300;

        // Now rollback_chain_switching should re-apply them.
        acm.rollback_chain_switching(&popped, 3);

        assert_eq!(acm.main_chain_height(), 5);
        assert!(acm.is_known_block("main_0003"));
        assert!(acm.is_known_block("main_0004"));
    }

    // ---- ReorgEvent structure -----------------------------------------------

    #[test]
    fn reorg_event_structure() {
        let event = ReorgEvent {
            split_height: 50,
            old_height: 100,
            new_height: 105,
            blocks_disconnected: 50,
            blocks_connected: 55,
        };

        assert_eq!(event.split_height, 50);
        assert_eq!(event.old_height, 100);
        assert_eq!(event.new_height, 105);
        assert_eq!(event.blocks_disconnected, 50);
        assert_eq!(event.blocks_connected, 55);
    }
}
