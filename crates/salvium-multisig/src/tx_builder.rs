//! Multisig transaction builder.
//!
//! Prepares a `PendingMultisigTx` with CLSAG signing contexts so that
//! multiple signers can produce partial signatures via `signing::partial_sign`.
//!
//! The builder performs the same pre-signing steps as the regular
//! `salvium_tx::sign::sign_transaction` pipeline:
//!   1. Compute pseudo-output masks (random masks, last balances)
//!   2. Generate Bulletproofs+ range proofs
//!   3. Compute the signing message: H(prefix_hash || H(rct_base) || H(bp_components))
//!   4. Set up per-input CLSAG contexts (ring, fake responses, commitment images)

use crate::signing::MultisigClsagContext;
use crate::tx_set::PendingMultisigTx;

// ─── Multisig Input ──────────────────────────────────────────────────────────

/// A prepared input for multisig transaction signing.
#[derive(Debug, Clone)]
pub struct MultisigInput {
    /// Ring member public keys (compressed Ed25519 points).
    pub ring: Vec<[u8; 32]>,
    /// Ring member commitments (compressed Pedersen commitments).
    pub ring_commitments: Vec<[u8; 32]>,
    /// Position of the real output within the ring.
    pub real_index: usize,
    /// Key image: I = x * H_p(P_l), where x is the (combined) secret key.
    pub key_image: [u8; 32],
    /// Amount of the output being spent (atomic units).
    pub amount: u64,
    /// Commitment blinding factor (mask) for this UTXO.
    pub input_mask: [u8; 32],
    /// Whether to use TCLSAG (CARROT/SALVIUM_ONE).
    pub use_tclsag: bool,
    /// Key image for the Y dimension (TCLSAG only).
    pub key_image_y: Option<[u8; 32]>,
}

// ─── Builder ─────────────────────────────────────────────────────────────────

/// Build a `PendingMultisigTx` with fully populated CLSAG signing contexts.
///
/// This function performs the pre-signing pipeline (pseudo-outputs, BP+ proof,
/// message hash, CLSAG context setup) and returns a `PendingMultisigTx` that
/// other signers can use to produce partial signatures.
///
/// # Arguments
/// * `inputs` — per-input ring data and amounts
/// * `output_amounts` — cleartext output amounts
/// * `output_masks` — output commitment blinding factors
/// * `output_commitments` — Pedersen commitments for outputs
/// * `encrypted_amounts` — 8-byte encrypted amounts (for ecdh_info)
/// * `fee` — transaction fee (atomic units)
/// * `rct_type` — RCT type (5=CLSAG, 8=SALVIUM_ZERO, 9=SALVIUM_ONE)
/// * `prefix_hash` — keccak256 of the serialized TX prefix
/// * `tx_blob` — hex-encoded unsigned transaction data
/// * `key_images_hex` — hex-encoded key images for the TX inputs
/// * `destinations` — destination addresses (for display)
/// * `input_key_offsets` — per-input derivation scalar (hex); proposer adds to key share
/// * `input_y_keys` — per-input TCLSAG y key (hex); empty string for CLSAG inputs
#[allow(clippy::too_many_arguments)]
pub fn build_multisig_contexts(
    inputs: &[MultisigInput],
    output_amounts: &[u64],
    output_masks: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    encrypted_amounts: &[[u8; 8]],
    fee: u64,
    rct_type: u8,
    prefix_hash: &[u8; 32],
    tx_blob: &str,
    key_images_hex: &[String],
    destinations: &[String],
    input_key_offsets: &[String],
    input_y_keys: &[String],
) -> Result<PendingMultisigTx, String> {
    if inputs.is_empty() {
        return Err("no inputs".into());
    }
    if output_amounts.len() != output_masks.len() {
        return Err("output_amounts/masks length mismatch".into());
    }

    let num_inputs = inputs.len();

    // 1. Compute pseudo-output masks and commitments.
    let (pseudo_masks, pseudo_outs) = compute_pseudo_outputs(inputs, output_masks)?;

    // 2. Generate Bulletproofs+ range proof.
    let bp_data = generate_bp_data(output_amounts, output_masks)?;

    // 3. Compute the signing message.
    let p_r = ed25519_identity();
    let salvium_data_bytes = if rct_type >= 7 {
        // Compute commitment difference: sum(output_masks) - sum(pseudo_masks)
        let output_mask_sum = sum_scalars(output_masks);
        let pseudo_mask_sum = sum_scalars(&pseudo_masks);
        let commitment_diff = to_32(&salvium_crypto::sc_sub(&output_mask_sum, &pseudo_mask_sum));
        Some(build_salvium_data_bytes(rct_type, Some(&commitment_diff)))
    } else {
        None
    };

    let rct_base_bytes = serialize_rct_base(
        rct_type,
        fee,
        encrypted_amounts,
        output_commitments,
        &p_r,
        salvium_data_bytes.as_deref(),
    );
    let bp_components_bytes = serialize_bp_components(&bp_data);

    let signing_message = salvium_crypto::rct_verify::compute_rct_message(
        prefix_hash,
        &rct_base_bytes,
        &bp_components_bytes,
    );
    let signing_message_hex = hex::encode(signing_message);

    // 4. Build per-input CLSAG signing contexts.
    let mut signing_contexts = Vec::with_capacity(num_inputs);
    let mut z_values_hex = Vec::with_capacity(num_inputs);

    for (i, input) in inputs.iter().enumerate() {
        let n = input.ring.len();
        if input.real_index >= n {
            return Err(format!("input {}: real_index {} >= ring size {}", i, input.real_index, n));
        }

        // Commitment mask for signing: z = input_mask - pseudo_mask (mod L).
        let z = to_32(&salvium_crypto::sc_sub(&input.input_mask, &pseudo_masks[i]));
        z_values_hex.push(hex::encode(z));

        // Commitment image: D = z * H_p(P_l).
        let pk = &input.ring[input.real_index];
        let hp_pk = to_32(&salvium_crypto::hash_to_point(pk));
        let d_full = to_32(&salvium_crypto::scalar_mult_point(&z, &hp_pk));

        // D/8 = inv(8) * D.
        let inv8 = to_32(&salvium_crypto::inv_eight_scalar());
        let d8 = to_32(&salvium_crypto::scalar_mult_point(&inv8, &d_full));

        // Random fake responses for non-real positions.
        let mut fake_responses = Vec::with_capacity(n);
        for j in 0..n {
            if j == input.real_index {
                fake_responses.push("00".repeat(32));
            } else {
                fake_responses.push(hex::encode(random_scalar()));
            }
        }

        let ctx = MultisigClsagContext {
            ring: input.ring.iter().map(hex::encode).collect(),
            commitments: input.ring_commitments.iter().map(hex::encode).collect(),
            key_image: hex::encode(input.key_image),
            pseudo_output_commitment: hex::encode(pseudo_outs[i]),
            message: signing_message_hex.clone(),
            real_index: input.real_index,
            use_tclsag: input.use_tclsag,
            key_image_y: input.key_image_y.map(hex::encode),
            commitment_image: Some(hex::encode(d8)),
            fake_responses,
        };

        signing_contexts.push(ctx);
    }

    Ok(PendingMultisigTx {
        tx_blob: tx_blob.to_string(),
        key_images: key_images_hex.to_vec(),
        tx_prefix_hash: hex::encode(prefix_hash),
        input_nonces: Vec::new(),
        input_partials: Vec::new(),
        fee,
        destinations: destinations.to_vec(),
        signing_contexts,
        signing_message: signing_message_hex,
        input_key_offsets: input_key_offsets.to_vec(),
        input_z_values: z_values_hex,
        input_y_keys: input_y_keys.to_vec(),
        proposer_signed: false,
    })
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

fn random_scalar() -> [u8; 32] {
    use rand::RngCore;
    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    to_32(&salvium_crypto::sc_reduce64(&buf))
}

/// Ed25519 compressed identity point (y=1, sign=0).
fn ed25519_identity() -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x01;
    id
}

/// Compute pseudo-output masks and commitments.
///
/// For inputs 0..n-2: random masks. For input n-1: balancing mask.
#[allow(clippy::type_complexity)]
fn compute_pseudo_outputs(
    inputs: &[MultisigInput],
    output_masks: &[[u8; 32]],
) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), String> {
    let n = inputs.len();
    let mut pseudo_masks = Vec::with_capacity(n);

    let output_mask_sum = sum_scalars(output_masks);

    if n == 1 {
        pseudo_masks.push(output_mask_sum);
    } else {
        let mut partial_sum = [0u8; 32];
        for _ in 0..n - 1 {
            let mask = random_scalar();
            partial_sum = to_32(&salvium_crypto::sc_add(&partial_sum, &mask));
            pseudo_masks.push(mask);
        }
        let last_mask = to_32(&salvium_crypto::sc_sub(&output_mask_sum, &partial_sum));
        pseudo_masks.push(last_mask);
    }

    let pseudo_outs: Vec<[u8; 32]> = inputs
        .iter()
        .zip(pseudo_masks.iter())
        .map(|(input, mask)| {
            to_32(&salvium_crypto::pedersen_commit(&input.amount.to_le_bytes(), mask))
        })
        .collect();

    Ok((pseudo_masks, pseudo_outs))
}

fn sum_scalars(scalars: &[[u8; 32]]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    for s in scalars {
        sum = to_32(&salvium_crypto::sc_add(&sum, s));
    }
    sum
}

/// Bulletproofs+ proof data (serialized components).
struct BpComponents {
    a: [u8; 32],
    a1: [u8; 32],
    b: [u8; 32],
    r1: [u8; 32],
    s1: [u8; 32],
    d1: [u8; 32],
    l_vec: Vec<[u8; 32]>,
    r_vec: Vec<[u8; 32]>,
}

fn generate_bp_data(amounts: &[u64], masks: &[[u8; 32]]) -> Result<BpComponents, String> {
    use curve25519_dalek::scalar::Scalar;

    let scalar_masks: Vec<Scalar> =
        masks.iter().map(|m| Scalar::from_bytes_mod_order(*m)).collect();

    let proof = salvium_crypto::bulletproofs_plus::bulletproof_plus_prove(amounts, &scalar_masks);

    Ok(BpComponents {
        a: proof.capital_a.compress().to_bytes(),
        a1: proof.capital_a1.compress().to_bytes(),
        b: proof.capital_b.compress().to_bytes(),
        r1: proof.r1.to_bytes(),
        s1: proof.s1.to_bytes(),
        d1: proof.d1.to_bytes(),
        l_vec: proof.l_vec.iter().map(|p| p.compress().to_bytes()).collect(),
        r_vec: proof.r_vec.iter().map(|p| p.compress().to_bytes()).collect(),
    })
}

/// Serialize RCT base for message hash computation.
fn serialize_rct_base(
    rct_type: u8,
    fee: u64,
    ecdh_info: &[[u8; 8]],
    out_pk: &[[u8; 32]],
    p_r: &[u8; 32],
    salvium_data_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    write_varint(&mut buf, rct_type as u64);
    write_varint(&mut buf, fee);
    for ea in ecdh_info {
        buf.extend_from_slice(ea);
    }
    for pk in out_pk {
        buf.extend_from_slice(pk);
    }
    buf.extend_from_slice(p_r);
    if let Some(sd) = salvium_data_bytes {
        buf.extend_from_slice(sd);
    }
    buf
}

/// Serialize BP+ components for message hash computation.
fn serialize_bp_components(bp: &BpComponents) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 * 32 + bp.l_vec.len() * 32 + bp.r_vec.len() * 32);
    buf.extend_from_slice(&bp.a);
    buf.extend_from_slice(&bp.a1);
    buf.extend_from_slice(&bp.b);
    buf.extend_from_slice(&bp.r1);
    buf.extend_from_slice(&bp.s1);
    buf.extend_from_slice(&bp.d1);
    for l in &bp.l_vec {
        buf.extend_from_slice(l);
    }
    for r in &bp.r_vec {
        buf.extend_from_slice(r);
    }
    buf
}

/// Build salvium_data pre-serialized bytes (pr_proof + sa_proof).
///
/// If `commitment_diff` is `Some(diff)` and non-zero, compute a real Schnorr proof:
///   R = r * G, c = H(R), z1 = r + c * diff, z2 = 0.
/// Otherwise use the trivial proof: R = r * G, z1 = r, z2 = 0.
fn build_salvium_data_bytes(rct_type: u8, commitment_diff: Option<&[u8; 32]>) -> Vec<u8> {
    let mut buf = Vec::new();

    if rct_type == 7 {
        // FULL_PROOFS: no type varint prefix
    } else {
        // SALVIUM_ZERO/ONE: type varint
        let sd_type: u64 = if rct_type == 9 { 2 } else { 0 };
        write_varint(&mut buf, sd_type);
    }

    let r_scalar = random_scalar();
    let r_point = to_32(&salvium_crypto::scalar_mult_base(&r_scalar));
    buf.extend_from_slice(&r_point);

    let has_diff = commitment_diff.is_some_and(|d| *d != [0u8; 32]);
    if has_diff {
        let diff = commitment_diff.unwrap();
        // c = H(R)
        let c = to_32(&salvium_crypto::sc_reduce32(&salvium_crypto::keccak256(&r_point)));
        // z1 = r + c * diff
        let c_diff = to_32(&salvium_crypto::sc_mul(&c, diff));
        let z1 = to_32(&salvium_crypto::sc_add(&r_scalar, &c_diff));
        buf.extend_from_slice(&z1);
    } else {
        // z1 = r (trivial proof: difference = 0)
        buf.extend_from_slice(&r_scalar);
    }
    buf.extend_from_slice(&[0u8; 32]); // z2 = 0

    // sa_proof (zeroed — C++ also disables sa_proof in multisig)
    buf.extend_from_slice(&[0u8; 96]);

    buf
}

/// Write a CryptoNote varint (7-bit encoding).
fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_scalar_test() -> [u8; 32] {
        random_scalar()
    }

    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = random_scalar_test();
        let pk = to_32(&salvium_crypto::scalar_mult_base(&sk));
        (sk, pk)
    }

    #[test]
    fn test_build_multisig_contexts_basic() {
        // Create a simple 1-input, 2-output TX context.
        let amount = 2_000_000_000u64;
        let send_amount = 500_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = amount - send_amount - fee;

        let (sk, pk) = test_keypair();
        let input_mask = random_scalar_test();
        let commitment =
            to_32(&salvium_crypto::pedersen_commit(&amount.to_le_bytes(), &input_mask));

        let ki = to_32(&salvium_crypto::scalar_mult_point(
            &sk,
            &to_32(&salvium_crypto::hash_to_point(&pk)),
        ));

        let input = MultisigInput {
            ring: vec![pk],
            ring_commitments: vec![commitment],
            real_index: 0,
            key_image: ki,
            amount,
            input_mask,
            use_tclsag: false,
            key_image_y: None,
        };

        let output_mask1 = random_scalar_test();
        let output_mask2 = random_scalar_test();
        let out_commit1 =
            to_32(&salvium_crypto::pedersen_commit(&send_amount.to_le_bytes(), &output_mask1));
        let out_commit2 =
            to_32(&salvium_crypto::pedersen_commit(&change_amount.to_le_bytes(), &output_mask2));

        let prefix_hash = to_32(&salvium_crypto::keccak256(b"test_prefix"));

        let pending = build_multisig_contexts(
            &[input],
            &[send_amount, change_amount],
            &[output_mask1, output_mask2],
            &[out_commit1, out_commit2],
            &[[0u8; 8], [0u8; 8]],
            fee,
            5, // CLSAG
            &prefix_hash,
            "deadbeef",
            &[hex::encode(ki)],
            &["test_dest".to_string()],
            &[],
            &[],
        )
        .unwrap();

        // Verify structure.
        assert_eq!(pending.signing_contexts.len(), 1);
        assert_eq!(pending.signing_message.len(), 64);
        assert_eq!(pending.fee, fee);

        let ctx = &pending.signing_contexts[0];
        assert_eq!(ctx.ring.len(), 1);
        assert_eq!(ctx.commitments.len(), 1);
        assert_eq!(ctx.real_index, 0);
        assert_eq!(ctx.fake_responses.len(), 1);
        assert!(ctx.commitment_image.is_some());
    }

    #[test]
    fn test_build_multisig_contexts_multi_ring() {
        let amount = 1_000_000_000u64;
        let send_amount = 500_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = amount - send_amount - fee;

        let (sk, pk) = test_keypair();
        let input_mask = random_scalar_test();
        let commitment =
            to_32(&salvium_crypto::pedersen_commit(&amount.to_le_bytes(), &input_mask));
        let ki = to_32(&salvium_crypto::scalar_mult_point(
            &sk,
            &to_32(&salvium_crypto::hash_to_point(&pk)),
        ));

        // Create a ring with 4 members (real at index 2).
        let mut ring = Vec::new();
        let mut ring_commitments = Vec::new();
        for i in 0..4 {
            if i == 2 {
                ring.push(pk);
                ring_commitments.push(commitment);
            } else {
                let (_, dk) = test_keypair();
                ring.push(dk);
                let (_, cm) = test_keypair();
                ring_commitments.push(cm);
            }
        }

        let input = MultisigInput {
            ring,
            ring_commitments,
            real_index: 2,
            key_image: ki,
            amount,
            input_mask,
            use_tclsag: false,
            key_image_y: None,
        };

        let output_mask1 = random_scalar_test();
        let output_mask2 = random_scalar_test();
        let out_commit1 =
            to_32(&salvium_crypto::pedersen_commit(&send_amount.to_le_bytes(), &output_mask1));
        let out_commit2 =
            to_32(&salvium_crypto::pedersen_commit(&change_amount.to_le_bytes(), &output_mask2));

        let prefix_hash = to_32(&salvium_crypto::keccak256(b"test_prefix"));

        let pending = build_multisig_contexts(
            &[input],
            &[send_amount, change_amount],
            &[output_mask1, output_mask2],
            &[out_commit1, out_commit2],
            &[[0u8; 8], [0u8; 8]],
            fee,
            5,
            &prefix_hash,
            "deadbeef",
            &[hex::encode(ki)],
            &[],
            &[],
            &[],
        )
        .unwrap();

        let ctx = &pending.signing_contexts[0];
        assert_eq!(ctx.ring.len(), 4);
        assert_eq!(ctx.real_index, 2);
        // Fake responses: positions 0, 1, 3 should be non-zero; position 2 should be zero.
        assert_eq!(ctx.fake_responses[2], "00".repeat(32));
        assert_ne!(ctx.fake_responses[0], "00".repeat(32));
        assert_ne!(ctx.fake_responses[1], "00".repeat(32));
        assert_ne!(ctx.fake_responses[3], "00".repeat(32));
    }

    #[test]
    fn test_build_rejects_empty_inputs() {
        let result = build_multisig_contexts(
            &[],
            &[100],
            &[[0u8; 32]],
            &[[0u8; 32]],
            &[[0u8; 8]],
            10,
            5,
            &[0u8; 32],
            "",
            &[],
            &[],
            &[],
            &[],
        );
        assert!(result.is_err());
    }
}
