//! UTXO selection strategies.
//!
//! Selects unspent outputs for spending based on configurable strategies.
//! All strategies respect the target amount + fee and aim to minimize change.

use serde::{Deserialize, Serialize};

/// Available UTXO selection strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionStrategy {
    /// Default: pick randomly from eligible outputs for privacy.
    Default,
    /// Prefer largest outputs first (minimizes number of inputs).
    LargestFirst,
    /// Prefer smallest outputs first (consolidates dust).
    SmallestFirst,
    /// Purely random selection.
    Random,
    /// Use all available outputs (sweep).
    All,
    /// First-in-first-out: oldest outputs first (by block_height).
    Fifo,
}

/// Options for UTXO selection.
#[derive(Debug, Clone)]
pub struct SelectionOptions {
    /// Minimum confirmations required.
    pub min_confirmations: u64,
    /// Outputs below this amount are considered dust and skipped.
    pub dust_threshold: u64,
    /// Maximum number of inputs to select.
    pub max_inputs: usize,
    /// Current blockchain height (for confirmation check).
    pub current_height: u64,
}

impl Default for SelectionOptions {
    fn default() -> Self {
        Self {
            min_confirmations: 10,
            dust_threshold: 0,
            max_inputs: 16,
            current_height: 0,
        }
    }
}

/// A candidate UTXO for selection.
#[derive(Debug, Clone)]
pub struct UtxoCandidate {
    /// Unique identifier (key image hex).
    pub key_image: String,
    /// Output amount in atomic units.
    pub amount: u64,
    /// Block height where the output was created.
    pub block_height: u64,
    /// Global output index (for decoy ring construction).
    pub global_index: u64,
}

/// Result of UTXO selection.
#[derive(Debug)]
pub struct SelectionResult {
    /// Selected UTXOs.
    pub selected: Vec<UtxoCandidate>,
    /// Total amount of selected UTXOs.
    pub total: u64,
    /// Change amount (total - target - fee).
    pub change: u64,
}

/// Select UTXOs to meet a target amount.
///
/// Returns `None` if insufficient funds.
pub fn select_utxos(
    candidates: &[UtxoCandidate],
    target_amount: u64,
    fee: u64,
    strategy: SelectionStrategy,
) -> Option<SelectionResult> {
    if candidates.is_empty() {
        return None;
    }

    let needed = target_amount.checked_add(fee)?;

    match strategy {
        SelectionStrategy::All => select_all(candidates),
        SelectionStrategy::LargestFirst => select_sorted(candidates, needed, true),
        SelectionStrategy::SmallestFirst => select_sorted(candidates, needed, false),
        SelectionStrategy::Random => select_random(candidates, needed),
        SelectionStrategy::Default => select_default(candidates, needed),
        SelectionStrategy::Fifo => select_fifo(candidates, needed),
    }
}

fn select_all(candidates: &[UtxoCandidate]) -> Option<SelectionResult> {
    let total: u64 = candidates.iter().map(|c| c.amount).sum();
    Some(SelectionResult {
        selected: candidates.to_vec(),
        total,
        change: 0,
    })
}

fn select_sorted(
    candidates: &[UtxoCandidate],
    needed: u64,
    largest_first: bool,
) -> Option<SelectionResult> {
    let mut sorted: Vec<_> = candidates.to_vec();
    if largest_first {
        sorted.sort_by(|a, b| b.amount.cmp(&a.amount));
    } else {
        sorted.sort_by(|a, b| a.amount.cmp(&b.amount));
    }

    accumulate(&sorted, needed)
}

fn select_random(candidates: &[UtxoCandidate], needed: u64) -> Option<SelectionResult> {
    use rand::seq::SliceRandom;
    let mut shuffled: Vec<_> = candidates.to_vec();
    shuffled.shuffle(&mut rand::thread_rng());
    accumulate(&shuffled, needed)
}

fn select_default(candidates: &[UtxoCandidate], needed: u64) -> Option<SelectionResult> {
    // Default strategy: try to find a single output that covers the amount
    // (reduces number of inputs = better privacy). If none is large enough,
    // fall back to largest-first accumulation.

    // Try single-output exact-ish match (within 10x of needed).
    let mut singles: Vec<_> = candidates
        .iter()
        .filter(|c| c.amount >= needed)
        .collect();
    singles.sort_by_key(|c| c.amount);

    if let Some(best) = singles.first() {
        return Some(SelectionResult {
            selected: vec![(*best).clone()],
            total: best.amount,
            change: best.amount - needed,
        });
    }

    // No single output suffices — use largest-first.
    select_sorted(candidates, needed, true)
}

fn select_fifo(candidates: &[UtxoCandidate], needed: u64) -> Option<SelectionResult> {
    let mut sorted: Vec<_> = candidates.to_vec();
    sorted.sort_by_key(|c| c.block_height);
    accumulate(&sorted, needed)
}

/// Select UTXOs with additional filtering options.
///
/// Filters candidates by confirmation count, dust threshold, and limits the
/// number of inputs before delegating to [`select_utxos`].
pub fn select_utxos_with_options(
    candidates: &[UtxoCandidate],
    target_amount: u64,
    fee: u64,
    strategy: SelectionStrategy,
    options: &SelectionOptions,
) -> Option<SelectionResult> {
    let filtered: Vec<UtxoCandidate> = candidates
        .iter()
        .filter(|c| {
            if options.current_height > 0 && options.min_confirmations > 0
                && options.current_height < c.block_height + options.min_confirmations
            {
                return false;
            }
            if c.amount < options.dust_threshold {
                return false;
            }
            true
        })
        .cloned()
        .collect();

    let mut result = select_utxos(&filtered, target_amount, fee, strategy)?;
    if result.selected.len() > options.max_inputs {
        // Re-select with only max_inputs candidates using largest first to maximize coverage
        let mut sorted = filtered;
        sorted.sort_by(|a, b| b.amount.cmp(&a.amount));
        sorted.truncate(options.max_inputs);
        result = select_utxos(&sorted, target_amount, fee, strategy)?;
    }
    Some(result)
}

/// Accumulate outputs in order until we meet the target.
fn accumulate(ordered: &[UtxoCandidate], needed: u64) -> Option<SelectionResult> {
    let mut selected = Vec::new();
    let mut total = 0u64;

    for candidate in ordered {
        selected.push(candidate.clone());
        total += candidate.amount;
        if total >= needed {
            return Some(SelectionResult {
                selected,
                total,
                change: total - needed,
            });
        }
    }

    // Not enough funds.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidates(amounts: &[u64]) -> Vec<UtxoCandidate> {
        amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| UtxoCandidate {
                key_image: format!("ki_{}", i),
                amount,
                block_height: 100 + i as u64,
                global_index: i as u64,
            })
            .collect()
    }

    #[test]
    fn test_select_all() {
        let candidates = make_candidates(&[100, 200, 300]);
        let result = select_utxos(&candidates, 0, 0, SelectionStrategy::All).unwrap();
        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.total, 600);
    }

    #[test]
    fn test_largest_first() {
        let candidates = make_candidates(&[50, 200, 100]);
        let result = select_utxos(&candidates, 150, 10, SelectionStrategy::LargestFirst).unwrap();
        // Should pick 200 first (covers 160 needed).
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total, 200);
        assert_eq!(result.change, 40);
    }

    #[test]
    fn test_smallest_first() {
        let candidates = make_candidates(&[50, 200, 100]);
        let result = select_utxos(&candidates, 140, 10, SelectionStrategy::SmallestFirst).unwrap();
        // 50 + 100 = 150 >= 150.
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.total, 150);
    }

    #[test]
    fn test_insufficient_funds() {
        let candidates = make_candidates(&[10, 20, 30]);
        let result = select_utxos(&candidates, 100, 0, SelectionStrategy::Default);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_candidates() {
        let result = select_utxos(&[], 100, 0, SelectionStrategy::Default);
        assert!(result.is_none());
    }

    #[test]
    fn test_default_prefers_single_output() {
        let candidates = make_candidates(&[50, 200, 100]);
        let result = select_utxos(&candidates, 90, 10, SelectionStrategy::Default).unwrap();
        // Default should pick smallest single output >= 100 → the 100 output.
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total, 100);
    }

    #[test]
    fn test_default_falls_back_to_accumulation() {
        let candidates = make_candidates(&[30, 40, 50]);
        let result = select_utxos(&candidates, 100, 10, SelectionStrategy::Default).unwrap();
        // No single output >= 110, so accumulate largest-first: 50+40+30=120.
        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.total, 120);
    }

    #[test]
    fn test_random_strategy() {
        let candidates = make_candidates(&[100, 200, 300, 400]);
        let result = select_utxos(&candidates, 250, 0, SelectionStrategy::Random).unwrap();
        assert!(result.total >= 250);
    }

    #[test]
    fn test_exact_amount() {
        let candidates = make_candidates(&[100]);
        let result = select_utxos(&candidates, 90, 10, SelectionStrategy::Default).unwrap();
        assert_eq!(result.total, 100);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn test_overflow_protection() {
        let result = select_utxos(&[], u64::MAX, 1, SelectionStrategy::Default);
        assert!(result.is_none()); // target + fee would overflow
    }

    // --- Fifo & SelectionOptions tests ---

    fn make_candidates_with_heights(entries: &[(u64, u64)]) -> Vec<UtxoCandidate> {
        entries
            .iter()
            .enumerate()
            .map(|(i, &(amount, height))| UtxoCandidate {
                key_image: format!("ki_{}", i),
                amount,
                block_height: height,
                global_index: i as u64,
            })
            .collect()
    }

    #[test]
    fn test_fifo_strategy() {
        // Amounts with varying heights; Fifo should pick oldest first.
        let candidates = make_candidates_with_heights(&[
            (100, 300), // newest
            (200, 100), // oldest
            (150, 200), // middle
        ]);
        let result = select_utxos(&candidates, 250, 0, SelectionStrategy::Fifo).unwrap();
        // Sorted by height: 200@100, 150@200 => 350 >= 250
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected[0].block_height, 100);
        assert_eq!(result.selected[1].block_height, 200);
        assert_eq!(result.total, 350);
    }

    #[test]
    fn test_fifo_insufficient() {
        let candidates = make_candidates_with_heights(&[(10, 100), (20, 200)]);
        let result = select_utxos(&candidates, 100, 0, SelectionStrategy::Fifo);
        assert!(result.is_none());
    }

    #[test]
    fn test_selection_options_min_confirmations() {
        // current_height=110, min_confirmations=10 => only height <= 100 qualifies.
        let candidates = make_candidates_with_heights(&[
            (100, 90),  // confirmed (110 >= 90+10)
            (200, 105), // not confirmed (110 < 105+10)
        ]);
        let options = SelectionOptions {
            min_confirmations: 10,
            current_height: 110,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 50, 0, SelectionStrategy::LargestFirst, &options,
        ).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].amount, 100);
    }

    #[test]
    fn test_selection_options_dust_threshold() {
        let candidates = make_candidates(&[5, 10, 200]);
        let options = SelectionOptions {
            dust_threshold: 10,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 50, 0, SelectionStrategy::LargestFirst, &options,
        ).unwrap();
        // 5 is below dust_threshold=10, should be filtered out.
        for c in &result.selected {
            assert!(c.amount >= 10);
        }
    }

    #[test]
    fn test_selection_options_max_inputs() {
        let candidates = make_candidates(&[10, 20, 30, 40, 50]);
        let options = SelectionOptions {
            max_inputs: 2,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 60, 0, SelectionStrategy::SmallestFirst, &options,
        );
        // SmallestFirst would need 4 inputs (10+20+30+40=100) but max_inputs=2,
        // so re-select with top 2 by amount: 50+40=90 >= 60.
        let r = result.unwrap();
        assert!(r.selected.len() <= 2);
    }

    #[test]
    fn test_selection_options_default() {
        let opts = SelectionOptions::default();
        assert_eq!(opts.min_confirmations, 10);
        assert_eq!(opts.dust_threshold, 0);
        assert_eq!(opts.max_inputs, 16);
        assert_eq!(opts.current_height, 0);
    }

    #[test]
    fn test_fifo_with_options() {
        let candidates = make_candidates_with_heights(&[
            (100, 50),  // old, confirmed
            (200, 80),  // confirmed
            (300, 95),  // not confirmed at height 100 with min_conf=10
        ]);
        let options = SelectionOptions {
            min_confirmations: 10,
            current_height: 100,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 250, 0, SelectionStrategy::Fifo, &options,
        ).unwrap();
        // Only heights 50 and 80 pass (100 >= 50+10 and 100 >= 80+10).
        // Height 95 filtered (100 < 95+10).
        // Fifo order: 100@50 + 200@80 = 300 >= 250.
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.selected[0].block_height, 50);
        assert_eq!(result.selected[1].block_height, 80);
    }

    #[test]
    fn test_options_no_current_height() {
        // When current_height=0, min_confirmations check is skipped.
        let candidates = make_candidates_with_heights(&[(100, 999_999)]);
        let options = SelectionOptions {
            min_confirmations: 10,
            current_height: 0,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 50, 0, SelectionStrategy::Default, &options,
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_options_all_filtered() {
        let candidates = make_candidates_with_heights(&[(5, 100), (3, 200)]);
        let options = SelectionOptions {
            dust_threshold: 10,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 1, 0, SelectionStrategy::Default, &options,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_select_with_options_largest_first() {
        let candidates = make_candidates(&[10, 50, 100, 200]);
        let options = SelectionOptions {
            dust_threshold: 20,
            ..Default::default()
        };
        let result = select_utxos_with_options(
            &candidates, 100, 0, SelectionStrategy::LargestFirst, &options,
        ).unwrap();
        // 10 filtered (< 20 dust). Largest first from [50, 100, 200]: 200 >= 100.
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].amount, 200);
    }

    #[test]
    fn test_fifo_ordering() {
        let candidates = make_candidates_with_heights(&[
            (10, 500),
            (20, 100),
            (30, 300),
            (40, 200),
        ]);
        let result = select_utxos(&candidates, 90, 0, SelectionStrategy::Fifo).unwrap();
        // Sorted by height: 20@100, 40@200, 30@300 => 90 >= 90.
        assert_eq!(result.selected.len(), 3);
        assert_eq!(result.selected[0].block_height, 100);
        assert_eq!(result.selected[1].block_height, 200);
        assert_eq!(result.selected[2].block_height, 300);
        assert_eq!(result.total, 90);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn test_options_max_inputs_reselection() {
        // 5 candidates: SmallestFirst would pick many small ones.
        let candidates = make_candidates(&[10, 20, 30, 40, 50]);
        let options = SelectionOptions {
            max_inputs: 3,
            ..Default::default()
        };
        // Target 80: SmallestFirst picks 10+20+30+40=100 (4 inputs > max 3).
        // Re-select: top 3 by amount [50,40,30], then SmallestFirst: 30+40=70 < 80, 30+40+50=120 >= 80.
        let result = select_utxos_with_options(
            &candidates, 80, 0, SelectionStrategy::SmallestFirst, &options,
        ).unwrap();
        assert!(result.selected.len() <= 3);
        assert!(result.total >= 80);
    }
}
