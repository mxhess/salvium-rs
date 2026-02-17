//! Decoy (ring member) selection using a gamma distribution.
//!
//! Implements the decoy selection algorithm from Miller et al., which uses a
//! gamma distribution to model real-world spending patterns and select
//! plausible decoy outputs for ring signatures.

use crate::TxError;
use rand::Rng;

/// Default ring size (16 = 15 decoys + 1 real).
pub const DEFAULT_RING_SIZE: usize = 16;

/// Number of recent blocks whose coinbase outputs are excluded (not yet spendable).
const SPENDABLE_AGE: usize = 10;

/// Gamma distribution shape parameter (Miller et al.).
const GAMMA_SHAPE: f64 = 19.28;

/// Gamma distribution scale parameter (1 / 1.61).
const GAMMA_SCALE: f64 = 1.0 / 1.61;

/// Recent spend window in seconds.
const RECENT_SPEND_WINDOW: f64 = 1800.0;

/// Average time between blocks in seconds.
const DIFFICULTY_TARGET: f64 = 120.0;

/// Selects decoy ring members from the global output distribution.
pub struct DecoySelector {
    /// Cumulative output counts per block (from daemon `get_output_distribution`).
    rct_offsets: Vec<u64>,
    /// Number of usable outputs (excluding recent locked ones).
    num_usable: u64,
    /// Average seconds per output.
    average_output_time: f64,
}

impl DecoySelector {
    /// Create a new decoy selector from the output distribution.
    ///
    /// `rct_offsets` is the cumulative RCT output count array from the daemon.
    /// Each entry represents the total number of RCT outputs at that block height.
    pub fn new(rct_offsets: Vec<u64>) -> Result<Self, TxError> {
        if rct_offsets.len() < SPENDABLE_AGE + 1 {
            return Err(TxError::DecoySelection(
                "insufficient output distribution data".into(),
            ));
        }

        let usable_len = rct_offsets.len() - SPENDABLE_AGE;
        let num_usable = rct_offsets[usable_len - 1];

        if num_usable == 0 {
            return Err(TxError::DecoySelection("no usable outputs".into()));
        }

        let total_time = (usable_len as f64) * DIFFICULTY_TARGET;
        let average_output_time = total_time / (num_usable as f64);

        Ok(Self {
            rct_offsets,
            num_usable,
            average_output_time,
        })
    }

    /// Pick decoys for one input.
    ///
    /// Returns `ring_size - 1` global output indices (excluding `real_index`),
    /// suitable for building a ring. The caller must insert `real_index` and sort.
    pub fn pick_decoys(
        &self,
        real_index: u64,
        ring_size: usize,
    ) -> Result<Vec<u64>, TxError> {
        let num_decoys = ring_size - 1;
        let mut rng = rand::thread_rng();
        let mut decoys = Vec::with_capacity(num_decoys);
        let mut attempts = 0;
        let max_attempts = num_decoys * 100;

        while decoys.len() < num_decoys {
            attempts += 1;
            if attempts > max_attempts {
                return Err(TxError::DecoySelection(format!(
                    "failed to find {} unique decoys after {} attempts",
                    num_decoys, max_attempts
                )));
            }

            let idx = self.sample_output_index(&mut rng);

            // Skip if it's the real output, a duplicate, or out of range.
            if idx == real_index || idx >= self.num_usable {
                continue;
            }
            if decoys.contains(&idx) {
                continue;
            }

            decoys.push(idx);
        }

        Ok(decoys)
    }

    /// Build a complete sorted ring for one input.
    ///
    /// Returns `(ring_indices, real_position)` where `ring_indices` is sorted
    /// ascending and `real_position` is the index of the real output within it.
    pub fn build_ring(
        &self,
        real_index: u64,
        ring_size: usize,
    ) -> Result<(Vec<u64>, usize), TxError> {
        let mut decoys = self.pick_decoys(real_index, ring_size)?;
        decoys.push(real_index);
        decoys.sort_unstable();
        let real_pos = decoys.iter().position(|&x| x == real_index).unwrap();
        Ok((decoys, real_pos))
    }

    /// Sample a single output index using the gamma distribution.
    fn sample_output_index<R: Rng>(&self, rng: &mut R) -> u64 {
        // Sample from gamma distribution.
        let x = gamma_sample(GAMMA_SHAPE, GAMMA_SCALE, rng);
        let y = x.exp();

        // Convert time to output index.
        let time_offset = if y > RECENT_SPEND_WINDOW {
            y - RECENT_SPEND_WINDOW
        } else {
            rng.gen::<f64>() * RECENT_SPEND_WINDOW
        };

        let output_offset = (time_offset / self.average_output_time) as u64;

        if output_offset >= self.num_usable {
            // Out of range, will be rejected by caller.
            return self.num_usable;
        }

        // Convert from "time ago" to ascending index.
        let idx = self.num_usable - 1 - output_offset;

        // Find which block this output belongs to and pick randomly within.
        self.localize_output(idx)
    }

    /// Given a global output index, find the block it belongs to and return
    /// a random output index within that block's range.
    fn localize_output(&self, target: u64) -> u64 {
        let usable_len = self.rct_offsets.len() - SPENDABLE_AGE;

        // Binary search for the block containing this output index.
        let block = match self.rct_offsets[..usable_len].binary_search(&target) {
            Ok(pos) => pos,
            Err(pos) => {
                if pos == 0 {
                    0
                } else {
                    pos - 1
                }
            }
        };

        let block_start = if block == 0 {
            0
        } else {
            self.rct_offsets[block - 1]
        };
        let block_end = self.rct_offsets[block];

        if block_end <= block_start {
            return target;
        }

        // Pick uniformly within the block.
        let mut rng = rand::thread_rng();
        let offset = rng.gen_range(0..block_end - block_start);
        block_start + offset
    }
}

// ─── Gamma Distribution Sampler (Marsaglia & Tsang) ──────────────────────────

/// Sample from Gamma(shape, scale) using Marsaglia & Tsang's method.
fn gamma_sample<R: Rng>(shape: f64, scale: f64, rng: &mut R) -> f64 {
    if shape < 1.0 {
        // For shape < 1, use the transformation: Gamma(a) = Gamma(a+1) * U^(1/a).
        let g = gamma_sample(shape + 1.0, 1.0, rng);
        let u: f64 = rng.gen();
        return g * u.powf(1.0 / shape) * scale;
    }

    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x = standard_normal(rng);
        let v = 1.0 + c * x;
        if v <= 0.0 {
            continue;
        }

        let v = v * v * v;
        let u: f64 = rng.gen();
        let x2 = x * x;

        // Fast acceptance.
        if u < 1.0 - 0.0331 * x2 * x2 {
            return d * v * scale;
        }

        // Slow acceptance.
        if u.ln() < 0.5 * x2 + d * (1.0 - v + v.ln()) {
            return d * v * scale;
        }
    }
}

/// Standard normal sample using Box-Muller transform.
fn standard_normal<R: Rng>(rng: &mut R) -> f64 {
    let u1: f64 = rng.gen();
    let u2: f64 = rng.gen();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_offsets(num_blocks: usize, outputs_per_block: u64) -> Vec<u64> {
        let mut offsets = Vec::with_capacity(num_blocks);
        for i in 0..num_blocks {
            offsets.push((i as u64 + 1) * outputs_per_block);
        }
        offsets
    }

    #[test]
    fn test_decoy_selector_creation() {
        let offsets = make_offsets(100, 10);
        let sel = DecoySelector::new(offsets).unwrap();
        assert_eq!(sel.num_usable, 90 * 10); // 100 - 10 = 90 usable blocks.
    }

    #[test]
    fn test_insufficient_offsets() {
        let offsets = make_offsets(5, 10);
        assert!(DecoySelector::new(offsets).is_err());
    }

    #[test]
    fn test_pick_decoys_count() {
        let offsets = make_offsets(200, 100);
        let sel = DecoySelector::new(offsets).unwrap();
        let decoys = sel.pick_decoys(500, 16).unwrap();
        assert_eq!(decoys.len(), 15);
    }

    #[test]
    fn test_pick_decoys_no_duplicates() {
        let offsets = make_offsets(200, 100);
        let sel = DecoySelector::new(offsets).unwrap();
        let decoys = sel.pick_decoys(500, 16).unwrap();
        let mut sorted = decoys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), decoys.len(), "should have no duplicates");
    }

    #[test]
    fn test_pick_decoys_excludes_real() {
        let offsets = make_offsets(200, 100);
        let sel = DecoySelector::new(offsets).unwrap();
        let decoys = sel.pick_decoys(500, 16).unwrap();
        assert!(!decoys.contains(&500), "should not include real output");
    }

    #[test]
    fn test_build_ring() {
        let offsets = make_offsets(200, 100);
        let sel = DecoySelector::new(offsets).unwrap();
        let (ring, real_pos) = sel.build_ring(500, 16).unwrap();
        assert_eq!(ring.len(), 16);
        assert_eq!(ring[real_pos], 500);
        // Verify sorted.
        for i in 1..ring.len() {
            assert!(ring[i] > ring[i - 1], "ring should be sorted ascending");
        }
    }

    #[test]
    fn test_gamma_distribution_positive() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let sample = gamma_sample(GAMMA_SHAPE, GAMMA_SCALE, &mut rng);
            assert!(sample > 0.0, "gamma sample should be positive");
        }
    }

    #[test]
    fn test_gamma_shape_less_than_one() {
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let sample = gamma_sample(0.5, 1.0, &mut rng);
            assert!(sample > 0.0);
        }
    }

    #[test]
    fn test_standard_normal_range() {
        let mut rng = rand::thread_rng();
        let mut in_range = 0;
        let n = 1000;
        for _ in 0..n {
            let x = standard_normal(&mut rng);
            if x.abs() < 3.0 {
                in_range += 1;
            }
        }
        // ~99.7% should be within 3 sigma.
        assert!(
            in_range > 950,
            "expected >95% within 3 sigma, got {}",
            in_range
        );
    }
}
