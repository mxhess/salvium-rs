//! Transaction builder.
//!
//! Provides a builder pattern for constructing Salvium transactions.
//! The builder assembles inputs, outputs, fee, and metadata, then produces
//! either an unsigned transaction (for offline signing) or a fully signed
//! transaction (when secret keys are provided).

use crate::carrot::{self, CarrotOutputParams};
use crate::fee::{self, FeePriority};
use crate::types::*;
use crate::TxError;

/// A destination for funds in the transaction.
#[derive(Debug, Clone)]
pub struct Destination {
    /// Recipient's account spend public key.
    pub spend_pubkey: [u8; 32],
    /// Recipient's account view public key.
    pub view_pubkey: [u8; 32],
    /// Amount to send (atomic units).
    pub amount: u64,
    /// Asset type (e.g., "SAL", "SAL1").
    pub asset_type: String,
    /// Payment ID (8 bytes, zeros for none).
    pub payment_id: [u8; 8],
    /// Whether the destination is a subaddress.
    pub is_subaddress: bool,
}

/// A prepared input for spending.
#[derive(Debug, Clone)]
pub struct PreparedInput {
    /// Spend secret key (x component, the ed25519 scalar).
    pub secret_key: [u8; 32],
    /// Spend secret key y component (for TCLSAG/CARROT). None for legacy CLSAG.
    pub secret_key_y: Option<[u8; 32]>,
    /// One-time public key of the output being spent.
    pub public_key: [u8; 32],
    /// Amount of the output being spent (atomic units).
    pub amount: u64,
    /// Commitment blinding factor (mask).
    pub mask: [u8; 32],
    /// Asset type of the output.
    pub asset_type: String,
    /// Global output index.
    pub global_index: u64,
    /// Ring member public keys (sorted ascending by index).
    pub ring: Vec<[u8; 32]>,
    /// Ring member commitments (same order as ring).
    pub ring_commitments: Vec<[u8; 32]>,
    /// Ring member global indices (sorted ascending).
    pub ring_indices: Vec<u64>,
    /// Position of the real output within the ring.
    pub real_index: usize,
}

/// Built (unsigned) transaction ready for signing.
#[derive(Debug)]
pub struct UnsignedTransaction {
    /// The transaction prefix.
    pub prefix: TxPrefix,
    /// Output commitment masks (blinding factors), one per output.
    pub output_masks: Vec<[u8; 32]>,
    /// Output amounts (cleartext), one per output.
    pub output_amounts: Vec<u64>,
    /// Encrypted amounts (8 bytes each, from CARROT construction), one per output.
    pub encrypted_amounts: Vec<[u8; 8]>,
    /// Output commitments (Pedersen commitments), one per output.
    pub output_commitments: Vec<[u8; 32]>,
    /// Prepared inputs (with ring data).
    pub inputs: Vec<PreparedInput>,
    /// RCT type to use.
    pub rct_type: u8,
    /// Transaction fee.
    pub fee: u64,
    /// Ephemeral private key (for CARROT tx extra).
    pub ephemeral_key: Option<[u8; 32]>,
}

/// Builder for constructing Salvium transactions.
pub struct TransactionBuilder {
    inputs: Vec<PreparedInput>,
    destinations: Vec<Destination>,
    change_spend_pubkey: Option<[u8; 32]>,
    change_view_pubkey: Option<[u8; 32]>,
    tx_type: u8,
    fee: Option<u64>,
    priority: FeePriority,
    unlock_time: u64,
    source_asset_type: String,
    destination_asset_type: String,
    amount_burnt: u64,
    amount_slippage_limit: u64,
    rct_type: u8,
}

impl TransactionBuilder {
    /// Create a new transaction builder.
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            destinations: Vec::new(),
            change_spend_pubkey: None,
            change_view_pubkey: None,
            tx_type: tx_type::TRANSFER,
            fee: None,
            priority: FeePriority::Normal,
            unlock_time: 0,
            source_asset_type: "SAL".to_string(),
            destination_asset_type: "SAL".to_string(),
            amount_burnt: 0,
            amount_slippage_limit: 0,
            rct_type: rct_type::SALVIUM_ONE,
        }
    }

    /// Add a prepared input to spend.
    pub fn add_input(mut self, input: PreparedInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add multiple prepared inputs.
    pub fn add_inputs(mut self, inputs: Vec<PreparedInput>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Add a destination (recipient).
    pub fn add_destination(mut self, dest: Destination) -> Self {
        self.destinations.push(dest);
        self
    }

    /// Set the change address keys.
    pub fn set_change_address(mut self, spend_pubkey: [u8; 32], view_pubkey: [u8; 32]) -> Self {
        self.change_spend_pubkey = Some(spend_pubkey);
        self.change_view_pubkey = Some(view_pubkey);
        self
    }

    /// Set the transaction type.
    pub fn set_tx_type(mut self, t: u8) -> Self {
        self.tx_type = t;
        self
    }

    /// Set an explicit fee (overrides automatic estimation).
    pub fn set_fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Set the fee priority level.
    pub fn set_priority(mut self, priority: FeePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set the unlock time.
    pub fn set_unlock_time(mut self, unlock_time: u64) -> Self {
        self.unlock_time = unlock_time;
        self
    }

    /// Set source and destination asset types.
    pub fn set_asset_types(mut self, source: &str, destination: &str) -> Self {
        self.source_asset_type = source.to_string();
        self.destination_asset_type = destination.to_string();
        self
    }

    /// Set the amount to burn (for BURN/CONVERT txs).
    pub fn set_amount_burnt(mut self, amount: u64) -> Self {
        self.amount_burnt = amount;
        self
    }

    /// Set the slippage limit (for CONVERT txs).
    pub fn set_slippage_limit(mut self, limit: u64) -> Self {
        self.amount_slippage_limit = limit;
        self
    }

    /// Set the RCT type (defaults to SALVIUM_ONE).
    pub fn set_rct_type(mut self, t: u8) -> Self {
        self.rct_type = t;
        self
    }

    /// Build an unsigned transaction.
    ///
    /// This computes the fee, creates outputs (including change), builds the
    /// transaction prefix, and returns an `UnsignedTransaction` ready for signing.
    pub fn build(self) -> Result<UnsignedTransaction, TxError> {
        if self.destinations.is_empty() {
            return Err(TxError::NoDestinations);
        }

        if self.inputs.is_empty() {
            return Err(TxError::InsufficientInputs { need: 1, have: 0 });
        }

        // Verify all inputs have consistent ring sizes.
        let ring_size = self.inputs[0].ring.len();
        for (i, input) in self.inputs.iter().enumerate() {
            if input.ring.len() != ring_size {
                return Err(TxError::RingSizeMismatch {
                    expected: ring_size,
                    got: input.ring.len(),
                });
            }
            if input.ring_commitments.len() != ring_size {
                return Err(TxError::RingSizeMismatch {
                    expected: ring_size,
                    got: input.ring_commitments.len(),
                });
            }
            if input.real_index >= ring_size {
                return Err(TxError::Invalid(format!(
                    "input {} real_index {} >= ring_size {}",
                    i, input.real_index, ring_size
                )));
            }
        }

        // Calculate total input amount.
        let total_input: u64 = self.inputs.iter().map(|i| i.amount).sum();

        // Calculate total destination amount.
        let total_dest: u64 = self.destinations.iter().map(|d| d.amount).sum();

        // Estimate fee if not explicitly set.
        let use_tclsag = fee::uses_tclsag(self.rct_type);
        let num_outputs = self.destinations.len() + 1; // +1 for change
        let estimated_fee = self.fee.unwrap_or_else(|| {
            fee::estimate_tx_fee(
                self.inputs.len(),
                num_outputs,
                ring_size,
                use_tclsag,
                output_type::CARROT_V1,
                self.priority,
            )
        });

        // Check sufficient funds.
        let needed = total_dest + estimated_fee + self.amount_burnt;
        if total_input < needed {
            return Err(TxError::InsufficientInputs {
                need: needed,
                have: total_input,
            });
        }

        let change_amount = total_input - total_dest - estimated_fee - self.amount_burnt;

        // Build input context.
        let first_key_image = self.inputs[0]
            .ring
            .get(self.inputs[0].real_index)
            .map(|_| {
                let ki_bytes = salvium_crypto::generate_key_image(
                    &self.inputs[0].public_key,
                    &self.inputs[0].secret_key,
                );
                let mut ki = [0u8; 32];
                ki.copy_from_slice(&ki_bytes[..32]);
                ki
            })
            .unwrap_or([0u8; 32]);
        let input_context = carrot::make_input_context_rct(&first_key_image);

        // Create outputs.
        let mut tx_outputs = Vec::new();
        let mut output_masks = Vec::new();
        let mut output_amounts = Vec::new();
        let mut encrypted_amounts = Vec::new();
        let mut output_commitments = Vec::new();
        let mut ephemeral_key = None;

        if self.rct_type >= rct_type::SALVIUM_ONE {
            // CARROT outputs.
            for dest in &self.destinations {
                let params = CarrotOutputParams {
                    recipient_spend_pubkey: &dest.spend_pubkey,
                    recipient_view_pubkey: &dest.view_pubkey,
                    amount: dest.amount,
                    input_context: &input_context,
                    enote_type: carrot::enote_type::PAYMENT,
                    payment_id: dest.payment_id,
                    is_subaddress: dest.is_subaddress,
                };

                let (carrot_out, d_e) = carrot::create_carrot_output(&params)
                    .map_err(|e| TxError::CarrotOutput(e.to_string()))?;

                if ephemeral_key.is_none() {
                    ephemeral_key = Some(d_e);
                }

                tx_outputs.push(TxOutput::CarrotV1 {
                    amount: 0, // RCT: amount is encrypted
                    key: carrot_out.onetime_address,
                    asset_type: dest.asset_type.clone(),
                    view_tag: carrot_out.view_tag,
                    encrypted_janus_anchor: carrot_out.encrypted_anchor,
                });
                output_masks.push(carrot_out.commitment_mask);
                output_amounts.push(dest.amount);
                encrypted_amounts.push(carrot_out.encrypted_amount);
                output_commitments.push(carrot_out.amount_commitment);
            }

            // Change output (if nonzero).
            if change_amount > 0 {
                if let (Some(change_spend), Some(change_view)) =
                    (self.change_spend_pubkey, self.change_view_pubkey)
                {
                    let params = CarrotOutputParams {
                        recipient_spend_pubkey: &change_spend,
                        recipient_view_pubkey: &change_view,
                        amount: change_amount,
                        input_context: &input_context,
                        enote_type: carrot::enote_type::CHANGE,
                        payment_id: [0u8; 8],
                        is_subaddress: false,
                    };

                    let (carrot_out, _) = carrot::create_carrot_output(&params)
                        .map_err(|e| TxError::CarrotOutput(e.to_string()))?;

                    tx_outputs.push(TxOutput::CarrotV1 {
                        amount: 0,
                        key: carrot_out.onetime_address,
                        asset_type: self.source_asset_type.clone(),
                        view_tag: carrot_out.view_tag,
                        encrypted_janus_anchor: carrot_out.encrypted_anchor,
                    });
                    output_masks.push(carrot_out.commitment_mask);
                    output_amounts.push(change_amount);
                    encrypted_amounts.push(carrot_out.encrypted_amount);
                    output_commitments.push(carrot_out.amount_commitment);
                } else {
                    return Err(TxError::Other("change address required".into()));
                }
            }
        } else {
            // Legacy outputs (placeholder — would use CryptoNote derivation).
            return Err(TxError::Other(
                "legacy (non-CARROT) output construction not implemented".into(),
            ));
        }

        // Sort outputs lexicographically by one-time key.
        let mut output_order: Vec<usize> = (0..tx_outputs.len()).collect();
        output_order.sort_by(|&a, &b| tx_outputs[a].key().cmp(tx_outputs[b].key()));
        let tx_outputs: Vec<_> = output_order.iter().map(|&i| tx_outputs[i].clone()).collect();
        let output_masks: Vec<_> = output_order.iter().map(|&i| output_masks[i]).collect();
        let output_amounts: Vec<_> = output_order.iter().map(|&i| output_amounts[i]).collect();
        let encrypted_amounts: Vec<_> = output_order.iter().map(|&i| encrypted_amounts[i]).collect();
        let output_commitments: Vec<_> = output_order.iter().map(|&i| output_commitments[i]).collect();

        // Build sorted inputs (sort by key image, descending).
        let mut sorted_inputs = self.inputs;
        sorted_inputs.sort_by(|a, b| {
            let ki_a = salvium_crypto::generate_key_image(&a.public_key, &a.secret_key);
            let ki_b = salvium_crypto::generate_key_image(&b.public_key, &b.secret_key);
            ki_b.cmp(&ki_a)
        });

        // Convert to TxInput with relative key offsets.
        let tx_inputs: Vec<TxInput> = sorted_inputs
            .iter()
            .map(|input| {
                let key_image_bytes =
                    salvium_crypto::generate_key_image(&input.public_key, &input.secret_key);
                let mut key_image = [0u8; 32];
                key_image.copy_from_slice(&key_image_bytes[..32]);

                // Convert absolute indices to relative offsets.
                let key_offsets = absolute_to_relative(&input.ring_indices);

                TxInput::Key {
                    amount: 0, // RCT: amount is hidden
                    asset_type: input.asset_type.clone(),
                    key_offsets,
                    key_image,
                }
            })
            .collect();

        // Build tx extra (ephemeral public key).
        let mut extra = Vec::new();
        if let Some(ref d_e) = ephemeral_key {
            // Tag 0x01 = tx public key.
            extra.push(0x01);
            // For CARROT, the "tx pub key" in extra is d_e * B (X25519 base).
            let base_u = [9u8; 32];
            let d_e_pub = salvium_crypto::x25519_scalar_mult(d_e, &base_u);
            extra.extend_from_slice(&d_e_pub[..32]);
        }

        // Version 4 for CARROT transactions (rct_type >= SALVIUM_ONE), version 2 otherwise.
        let version = if self.rct_type >= rct_type::SALVIUM_ONE { 4 } else { 2 };

        // For version >= 3 TRANSFER, populate return_address_list and change_mask.
        let (return_address_list, return_address_change_mask) =
            if self.tx_type == tx_type::TRANSFER && version >= 3 {
                // One 32-byte return address per output.
                // Use the sender's change spend pubkey as the return address for all outputs.
                let sender_key = self.change_spend_pubkey.unwrap_or([0u8; 32]);
                let list: Vec<Vec<u8>> = (0..tx_outputs.len())
                    .map(|_| sender_key.to_vec())
                    .collect();

                // Change mask: one byte per output (0=payment, 1=change).
                // After sorting, we need to determine which output is the change output.
                // The change output has the change address's spend pubkey-derived one-time key.
                // Since we don't track this through sorting, use a heuristic: the last
                // destination in the original build is change, so after sort we mark based on count.
                let num_payment = self.destinations.len();
                let mut mask = vec![0u8; tx_outputs.len()];
                // The change output is at index num_payment in the pre-sort order.
                // After sort, it moved to output_order[num_payment]'s new position.
                // output_order maps new_pos -> old_pos. We need old_pos num_payment -> new_pos.
                for (new_pos, &old_pos) in output_order.iter().enumerate() {
                    if old_pos >= num_payment {
                        mask[new_pos] = 1;
                    }
                }

                (Some(list), Some(mask))
            } else {
                (None, None)
            };

        let prefix = TxPrefix {
            version,
            unlock_time: self.unlock_time,
            inputs: tx_inputs,
            outputs: tx_outputs,
            extra,
            tx_type: self.tx_type,
            amount_burnt: self.amount_burnt,
            return_address: None,
            return_pubkey: None,
            return_address_list,
            return_address_change_mask,
            source_asset_type: self.source_asset_type,
            destination_asset_type: self.destination_asset_type,
            amount_slippage_limit: self.amount_slippage_limit,
        };

        Ok(UnsignedTransaction {
            prefix,
            output_masks,
            output_amounts,
            encrypted_amounts,
            output_commitments,
            inputs: sorted_inputs,
            rct_type: self.rct_type,
            fee: estimated_fee,
            ephemeral_key,
        })
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert absolute ring indices to relative offsets.
///
/// Input: [10, 50, 80, 100] (sorted ascending)
/// Output: [10, 40, 30, 20] (each relative to previous)
fn absolute_to_relative(indices: &[u64]) -> Vec<u64> {
    if indices.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(indices.len());
    result.push(indices[0]);
    for i in 1..indices.len() {
        result.push(indices[i] - indices[i - 1]);
    }
    result
}

/// Convert relative offsets back to absolute indices.
pub fn relative_to_absolute(offsets: &[u64]) -> Vec<u64> {
    let mut result = Vec::with_capacity(offsets.len());
    let mut sum = 0u64;
    for &off in offsets {
        sum += off;
        result.push(sum);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_absolute_to_relative() {
        assert_eq!(absolute_to_relative(&[10, 50, 80, 100]), vec![10, 40, 30, 20]);
        assert_eq!(absolute_to_relative(&[5]), vec![5]);
        assert_eq!(absolute_to_relative(&[]), Vec::<u64>::new());
    }

    #[test]
    fn test_relative_to_absolute() {
        assert_eq!(relative_to_absolute(&[10, 40, 30, 20]), vec![10, 50, 80, 100]);
        assert_eq!(relative_to_absolute(&[5]), vec![5]);
    }

    #[test]
    fn test_roundtrip_offsets() {
        let abs = vec![100, 200, 350, 400, 500];
        let rel = absolute_to_relative(&abs);
        let back = relative_to_absolute(&rel);
        assert_eq!(abs, back);
    }

    #[test]
    fn test_builder_no_destinations() {
        let input = make_test_input(1_000_000_000);
        let result = TransactionBuilder::new().add_input(input).build();
        assert!(matches!(result, Err(TxError::NoDestinations)));
    }

    #[test]
    fn test_builder_no_inputs() {
        let dest = Destination {
            spend_pubkey: [0x11; 32],
            view_pubkey: [0x22; 32],
            amount: 500_000_000,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        };
        let result = TransactionBuilder::new().add_destination(dest).build();
        assert!(matches!(result, Err(TxError::InsufficientInputs { .. })));
    }

    #[test]
    fn test_builder_insufficient_funds() {
        let input = make_test_input(100); // very small
        let dest = Destination {
            spend_pubkey: [0x11; 32],
            view_pubkey: [0x22; 32],
            amount: 1_000_000_000,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        };
        let result = TransactionBuilder::new()
            .add_input(input)
            .add_destination(dest)
            .set_change_address([0x33; 32], [0x44; 32])
            .build();
        assert!(matches!(result, Err(TxError::InsufficientInputs { .. })));
    }

    #[test]
    fn test_builder_ring_size_mismatch() {
        let input1 = make_test_input(1_000_000_000);
        let mut input2 = make_test_input(1_000_000_000);
        input2.ring = vec![[0u8; 32]; 8]; // different ring size
        input2.ring_commitments = vec![[0u8; 32]; 8];
        input2.ring_indices = (0..8).map(|i| i * 10).collect();

        let dest = Destination {
            spend_pubkey: [0x11; 32],
            view_pubkey: [0x22; 32],
            amount: 500_000_000,
            asset_type: "SAL".to_string(),
            payment_id: [0u8; 8],
            is_subaddress: false,
        };

        let result = TransactionBuilder::new()
            .add_input(input1)
            .add_input(input2)
            .add_destination(dest)
            .set_change_address([0x33; 32], [0x44; 32])
            .build();
        assert!(matches!(result, Err(TxError::RingSizeMismatch { .. })));
    }

    #[test]
    fn test_builder_default() {
        let b = TransactionBuilder::default();
        assert_eq!(b.tx_type, tx_type::TRANSFER);
        assert_eq!(b.rct_type, rct_type::SALVIUM_ONE);
    }

    fn make_test_input(amount: u64) -> PreparedInput {
        let ring_size = 16;
        PreparedInput {
            secret_key: [0x01; 32],
            secret_key_y: Some([0x02; 32]),
            public_key: [0x03; 32],
            amount,
            mask: [0x04; 32],
            asset_type: "SAL".to_string(),
            global_index: 500,
            ring: vec![[0x10; 32]; ring_size],
            ring_commitments: vec![[0x20; 32]; ring_size],
            ring_indices: (0..ring_size as u64).map(|i| i * 100).collect(),
            real_index: 5,
        }
    }
}
