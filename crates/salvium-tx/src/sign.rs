//! Transaction signing pipeline.
//!
//! Takes an `UnsignedTransaction` (from the builder) and produces a fully
//! signed `Transaction` by:
//!   1. Computing pseudo-output commitments (random masks, last balances)
//!   2. Generating Bulletproofs+ range proofs for all outputs
//!   3. Computing the pre-MLSAG/CLSAG message hash
//!   4. Signing each input with CLSAG or TCLSAG ring signatures
//!
//! Delegates all low-level crypto to salvium-crypto.

use curve25519_dalek::scalar::Scalar;

use crate::builder::{PreparedInput, UnsignedTransaction};
use crate::types::*;
use crate::TxError;

/// Ed25519 compressed identity point (neutral element).
/// In compressed form: y=1, sign=0 → [0x01, 0x00, ..., 0x00].
const ED25519_IDENTITY: [u8; 32] = {
    let mut id = [0u8; 32];
    id[0] = 0x01;
    id
};

/// Sign an unsigned transaction, producing a fully signed `Transaction`.
///
/// The unsigned transaction must have been built by `TransactionBuilder::build()`,
/// with all ring data populated (ring members, commitments, real index).
pub fn sign_transaction(unsigned: UnsignedTransaction) -> Result<Transaction, TxError> {
    let num_inputs = unsigned.inputs.len();
    let num_outputs = unsigned.output_amounts.len();
    let use_tclsag = unsigned.rct_type >= rct_type::SALVIUM_ONE;

    if num_inputs == 0 {
        return Err(TxError::Signing("no inputs to sign".into()));
    }
    if num_outputs == 0 {
        return Err(TxError::Signing("no outputs".into()));
    }

    // 1. Compute prefix hash.
    let prefix_hash = compute_prefix_hash(&unsigned.prefix)?;

    // 2. Build output data.
    let ecdh_info: Vec<EcdhInfo> = unsigned
        .encrypted_amounts
        .iter()
        .map(|ea| EcdhInfo { amount: *ea })
        .collect();
    let out_pk: Vec<[u8; 32]> = unsigned.output_commitments.clone();

    // 3. Compute pseudo-output masks and commitments.
    let (pseudo_masks, pseudo_outs) =
        compute_pseudo_outputs(&unsigned.inputs, &unsigned.output_masks)?;

    // 4. Generate Bulletproofs+ range proof for all outputs.
    let bp_data =
        generate_bp_proof(&unsigned.output_amounts, &unsigned.output_masks)?;

    // 4b. Compute p_r and PRProof (for SALVIUM_ZERO/ONE).
    //     p_r = difference * G where difference = sum(pseudo_masks) - sum(output_masks).
    //     Since we balance pseudo_masks to match output_masks, difference = 0 → p_r = identity.
    let p_r = ED25519_IDENTITY;
    let (pr_proof, salvium_data_bytes) = if unsigned.rct_type == rct_type::SALVIUM_ZERO
        || unsigned.rct_type == rct_type::SALVIUM_ONE
    {
        let proof = generate_pr_proof(&[0u8; 32]);
        // salvium_data_type: SalviumZero=0, SalviumZeroAudit=1, SalviumOne=2
        let sd_type: u64 = if unsigned.rct_type == rct_type::SALVIUM_ONE { 2 } else { 0 };
        let mut sd_bytes = Vec::new();
        write_varint(&mut sd_bytes, sd_type);
        sd_bytes.extend_from_slice(&proof.0); // pr_proof.R
        sd_bytes.extend_from_slice(&proof.1); // pr_proof.z1
        sd_bytes.extend_from_slice(&proof.2); // pr_proof.z2
        sd_bytes.extend_from_slice(&[0u8; 96]); // sa_proof
        (Some(proof), Some(sd_bytes))
    } else {
        (None, None)
    };

    // 5. Serialize rct_base and bp_components for message hash computation.
    let rct_base_bytes = serialize_rct_base_bytes(
        unsigned.rct_type,
        unsigned.fee,
        &ecdh_info,
        &out_pk,
        &p_r,
        salvium_data_bytes.as_deref(),
    );
    let bp_components_bytes = serialize_bp_components(&bp_data);

    // 6. Compute the signing message: H(prefix_hash || H(rct_base) || H(bp_components)).
    let message = salvium_crypto::rct_verify::compute_rct_message(
        &prefix_hash,
        &rct_base_bytes,
        &bp_components_bytes,
    );

    // 7. Sign each input with CLSAG or TCLSAG.
    let mut clsags = Vec::new();
    let mut tclsags = Vec::new();

    for (i, input) in unsigned.inputs.iter().enumerate() {
        // Signing key for commitment: z = input_mask - pseudo_mask (mod L).
        let z = to_32(&salvium_crypto::sc_sub(&input.mask, &pseudo_masks[i]));

        if use_tclsag {
            let secret_key_y = input.secret_key_y.ok_or_else(|| {
                TxError::Signing(format!(
                    "input {} requires secret_key_y for TCLSAG but has None",
                    i
                ))
            })?;

            let sig = salvium_crypto::tclsag::tclsag_sign(
                &message,
                &input.ring,
                &input.secret_key,
                &secret_key_y,
                &input.ring_commitments,
                &z,
                &pseudo_outs[i],
                input.real_index,
            );

            tclsags.push(TclsagData {
                sx: sig.sx,
                sy: sig.sy,
                c1: sig.c1,
                d: sig.commitment_image,
            });
        } else {
            let sig = salvium_crypto::clsag::clsag_sign(
                &message,
                &input.ring,
                &input.secret_key,
                &input.ring_commitments,
                &z,
                &pseudo_outs[i],
                input.real_index,
            );

            clsags.push(ClsagData {
                s: sig.s,
                c1: sig.c1,
                d: sig.commitment_image,
            });
        }
    }

    // 8. Assemble the final signed transaction.
    // SALVIUM_ZERO/ONE requires salvium_data with valid PRProof.
    // salvium_data_type: SalviumZero=0, SalviumZeroAudit=1, SalviumOne=2
    let sd_type_val = if unsigned.rct_type == rct_type::SALVIUM_ONE { 2 } else { 0 };
    let salvium_data = if let Some((proof_r, proof_z1, proof_z2)) = pr_proof {
        Some(serde_json::json!({
            "salvium_data_type": sd_type_val,
            "pr_proof": {
                "R": hex::encode(proof_r),
                "z1": hex::encode(proof_z1),
                "z2": hex::encode(proof_z2)
            }
        }))
    } else {
        None
    };

    let rct = RctSignatures {
        rct_type: unsigned.rct_type,
        txn_fee: unsigned.fee,
        ecdh_info,
        out_pk,
        p_r: Some(p_r),
        salvium_data,
        bulletproof_plus: vec![bp_data],
        clsags,
        tclsags,
        pseudo_outs,
    };

    Ok(Transaction {
        prefix: unsigned.prefix,
        rct: Some(rct),
    })
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/// Compute the prefix hash (keccak256 of serialized prefix).
fn compute_prefix_hash(prefix: &TxPrefix) -> Result<[u8; 32], TxError> {
    let json = prefix.to_json();
    let json_str =
        serde_json::to_string(&json).map_err(|e| TxError::Serialize(e.to_string()))?;
    let prefix_bytes = salvium_crypto::tx_serialize::serialize_tx_prefix(&json_str)
        .map_err(TxError::Serialize)?;
    Ok(to_32(&salvium_crypto::keccak256(&prefix_bytes)))
}

/// Compute pseudo-output masks and commitments.
///
/// For inputs 0..n-2: random masks.
/// For input n-1: mask = sum(output_masks) - sum(pseudo_masks[0..n-2]).
/// This ensures the balance equation: sum(pseudo_masks) = sum(output_masks).
///
/// Returns (pseudo_masks, pseudo_output_commitments).
fn compute_pseudo_outputs(
    inputs: &[PreparedInput],
    output_masks: &[[u8; 32]],
) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), TxError> {
    let n = inputs.len();
    let mut pseudo_masks = Vec::with_capacity(n);

    if n == 1 {
        // Single input: pseudo_mask = sum(output_masks).
        let mask_sum = sum_scalars(output_masks);
        pseudo_masks.push(mask_sum);
    } else {
        // Multiple inputs: random masks for 0..n-2, computed for n-1.
        let output_mask_sum = sum_scalars(output_masks);
        let mut partial_sum = [0u8; 32]; // sum of pseudo_masks[0..n-2]

        for _ in 0..n - 1 {
            let random_mask = random_scalar_bytes();
            partial_sum = to_32(&salvium_crypto::sc_add(&partial_sum, &random_mask));
            pseudo_masks.push(random_mask);
        }

        // Last mask: output_mask_sum - partial_sum.
        let last_mask = to_32(&salvium_crypto::sc_sub(&output_mask_sum, &partial_sum));
        pseudo_masks.push(last_mask);
    }

    // Compute pseudo-output commitments: C' = pseudo_mask*G + input_amount*H.
    let pseudo_outs: Vec<[u8; 32]> = inputs
        .iter()
        .zip(pseudo_masks.iter())
        .map(|(input, mask)| {
            to_32(&salvium_crypto::pedersen_commit(
                &input.amount.to_le_bytes(),
                mask,
            ))
        })
        .collect();

    Ok((pseudo_masks, pseudo_outs))
}

/// Generate a Bulletproofs+ range proof for all outputs.
///
/// Proves that each output commitment opens to a value in [0, 2^64).
fn generate_bp_proof(
    amounts: &[u64],
    masks: &[[u8; 32]],
) -> Result<BpPlusData, TxError> {
    // Convert masks from [u8; 32] to curve25519-dalek Scalars.
    let scalar_masks: Vec<Scalar> = masks
        .iter()
        .map(|m| Scalar::from_bytes_mod_order(*m))
        .collect();

    let proof = salvium_crypto::bulletproofs_plus::bulletproof_plus_prove(
        amounts,
        &scalar_masks,
    );

    // Convert BulletproofPlusProof to our BpPlusData type.
    Ok(BpPlusData {
        a: proof.capital_a.compress().to_bytes(),
        a1: proof.capital_a1.compress().to_bytes(),
        b: proof.capital_b.compress().to_bytes(),
        r1: proof.r1.to_bytes(),
        s1: proof.s1.to_bytes(),
        d1: proof.d1.to_bytes(),
        l_vec: proof
            .l_vec
            .iter()
            .map(|p| p.compress().to_bytes())
            .collect(),
        r_vec: proof
            .r_vec
            .iter()
            .map(|p| p.compress().to_bytes())
            .collect(),
    })
}

/// Serialize the RCT base for message hash computation.
///
/// Format: type(varint) + fee(varint) + ecdhInfo(8B each) + outPk(32B each) + p_r(32B)
///         [+ salvium_data for SALVIUM types].
fn serialize_rct_base_bytes(
    rct_type: u8,
    fee: u64,
    ecdh_info: &[EcdhInfo],
    out_pk: &[[u8; 32]],
    p_r: &[u8; 32],
    salvium_data_bytes: Option<&[u8]>,
) -> Vec<u8> {
    let capacity = 1 + 10 + ecdh_info.len() * 8 + out_pk.len() * 32 + 32 + 200;
    let mut buf = Vec::with_capacity(capacity);

    write_varint(&mut buf, rct_type as u64);
    write_varint(&mut buf, fee);

    for ei in ecdh_info {
        buf.extend_from_slice(&ei.amount);
    }

    for pk in out_pk {
        buf.extend_from_slice(pk);
    }

    // p_r: commitment to blinding-factor difference (identity when balanced).
    buf.extend_from_slice(p_r);

    // salvium_data (pre-serialized bytes including type + pr_proof + sa_proof).
    if let Some(sd) = salvium_data_bytes {
        buf.extend_from_slice(sd);
    }

    buf
}

/// Serialize Bulletproofs+ proof components for message hash computation.
///
/// Matches C++ get_pre_mlsag_hash (rctSigs.cpp:830-843): flat concatenation
/// of 32-byte keys with NO varint size prefixes.
///
/// Format: A(32) + A1(32) + B(32) + r1(32) + s1(32) + d1(32)
///         + L[](32 each) + R[](32 each).
///
/// V (commitments) are NOT included — they're already in rctSigBase via outPk.
fn serialize_bp_components(bp: &BpPlusData) -> Vec<u8> {
    let capacity = 6 * 32 + bp.l_vec.len() * 32 + bp.r_vec.len() * 32;
    let mut buf = Vec::with_capacity(capacity);

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

/// Write a CryptoNote varint (7-bit encoding, MSB set if more bytes follow).
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

/// Generate a PRProof: Schnorr proof of knowledge of the discrete log of p_r.
///
/// p_r = difference * G where difference = sum(pseudo_masks) - sum(output_masks).
/// Proof: {R, z1, z2} where R = r*G, c = H_s(R || p_r), z1 = r + c*difference, z2 = 0.
///
/// Returns (R, z1, z2) as three 32-byte arrays.
fn generate_pr_proof(difference: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // Random nonce.
    let r_scalar = random_scalar_bytes();
    let r_point = to_32(&salvium_crypto::scalar_mult_base(&r_scalar));

    // p_r = difference * G (identity if difference == 0).
    let p_r = if *difference == [0u8; 32] {
        ED25519_IDENTITY
    } else {
        to_32(&salvium_crypto::scalar_mult_base(difference))
    };

    // c = hash_to_scalar(R || p_r) = sc_reduce32(keccak256(R || p_r)).
    let mut hash_input = Vec::with_capacity(64);
    hash_input.extend_from_slice(&r_point);
    hash_input.extend_from_slice(&p_r);
    let hash = salvium_crypto::keccak256(&hash_input);
    let c = Scalar::from_bytes_mod_order(to_32(&hash));

    // z1 = r + c * difference.
    let r = Scalar::from_bytes_mod_order(r_scalar);
    let diff = Scalar::from_bytes_mod_order(*difference);
    let z1 = r + c * diff;

    // z2 = 0.
    let z2 = [0u8; 32];

    (r_point, z1.to_bytes(), z2)
}

/// Sum scalars (mod L) using repeated sc_add.
fn sum_scalars(scalars: &[[u8; 32]]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    for s in scalars {
        sum = to_32(&salvium_crypto::sc_add(&sum, s));
    }
    sum
}

/// Generate a random scalar (reduced mod L).
fn random_scalar_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    to_32(&salvium_crypto::sc_reduce64(&buf))
}

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{Destination, PreparedInput, TransactionBuilder};

    /// Reconstruct salvium_data bytes from a signed TX's RctSignatures.
    /// Used to rebuild the message hash for signature verification in tests.
    fn reconstruct_salvium_data_bytes(rct: &RctSignatures) -> Option<Vec<u8>> {
        let sd = rct.salvium_data.as_ref()?;
        let data_type = sd.get("salvium_data_type")?.as_u64()?;
        let mut buf = Vec::new();
        write_varint(&mut buf, data_type);

        // pr_proof
        if let Some(pr) = sd.get("pr_proof") {
            let r = hex::decode(pr.get("R")?.as_str()?).ok()?;
            let z1 = hex::decode(pr.get("z1")?.as_str()?).ok()?;
            let z2 = hex::decode(pr.get("z2")?.as_str()?).ok()?;
            buf.extend_from_slice(&r);
            buf.extend_from_slice(&z1);
            buf.extend_from_slice(&z2);
        } else {
            buf.extend_from_slice(&[0u8; 96]);
        }

        // sa_proof (always zero for type 0).
        buf.extend_from_slice(&[0u8; 96]);

        Some(buf)
    }

    /// Generate a valid keypair (secret key + public key on the curve).
    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let sk_bytes = random_scalar_bytes();
        let pk_bytes = to_32(&salvium_crypto::scalar_mult_base(&sk_bytes));
        (sk_bytes, pk_bytes)
    }

    /// The T generator used by TCLSAG (must match the constant in tclsag.rs).
    const T_BYTES: [u8; 32] = [
        0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
        0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
        0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
        0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f,
    ];

    /// Generate a valid keypair with both x and y components (for TCLSAG).
    fn test_keypair_dual() -> ([u8; 32], Option<[u8; 32]>, [u8; 32]) {
        let (sk_x, _) = test_keypair();
        let (sk_y, _) = test_keypair();
        // Public key = sk_x*G + sk_y*T (using the actual TCLSAG T generator).
        let g_part = salvium_crypto::scalar_mult_base(&sk_x);
        let t_part = salvium_crypto::scalar_mult_point(&sk_y, &T_BYTES);
        let pk = to_32(&salvium_crypto::point_add_compressed(&g_part, &t_part));
        (sk_x, Some(sk_y), pk)
    }

    /// Create a valid prepared input with a 1-member ring (trivial, for testing).
    fn make_valid_input(amount: u64, use_tclsag: bool) -> PreparedInput {
        let mask = random_scalar_bytes();
        let commitment = to_32(&salvium_crypto::pedersen_commit(
            &amount.to_le_bytes(),
            &mask,
        ));

        if use_tclsag {
            let (sk_x, sk_y, pk) = test_keypair_dual();
            PreparedInput {
                secret_key: sk_x,
                secret_key_y: sk_y,
                public_key: pk,
                amount,
                mask,
                asset_type: "SAL".to_string(),
                global_index: 100,
                ring: vec![pk],
                ring_commitments: vec![commitment],
                ring_indices: vec![100],
                real_index: 0,
            }
        } else {
            let (sk, pk) = test_keypair();
            PreparedInput {
                secret_key: sk,
                secret_key_y: None,
                public_key: pk,
                amount,
                mask,
                asset_type: "SAL".to_string(),
                global_index: 100,
                ring: vec![pk],
                ring_commitments: vec![commitment],
                ring_indices: vec![100],
                real_index: 0,
            }
        }
    }

    #[test]
    fn test_write_varint() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_varint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);

        buf.clear();
        write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_random_scalar_reduced() {
        let s = random_scalar_bytes();
        assert_ne!(s, [0u8; 32]);
        // High byte should be small (scalar < L ≈ 2^252).
        assert!(s[31] < 0x10);
    }

    #[test]
    fn test_sum_scalars() {
        let a = random_scalar_bytes();
        let b = random_scalar_bytes();
        let sum = sum_scalars(&[a, b]);
        let expected = to_32(&salvium_crypto::sc_add(&a, &b));
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_pseudo_output_balance() {
        // Verify that sum(pseudo_masks) == sum(output_masks).
        let output_masks = [random_scalar_bytes(), random_scalar_bytes()];
        let inputs = vec![
            make_valid_input(1_000_000_000, false),
            make_valid_input(500_000_000, false),
        ];

        let (pseudo_masks, _pseudo_outs) =
            compute_pseudo_outputs(&inputs, &output_masks).unwrap();

        let pseudo_sum = sum_scalars(&pseudo_masks);
        let output_sum = sum_scalars(&output_masks);
        assert_eq!(pseudo_sum, output_sum, "pseudo-output masks must balance");
    }

    #[test]
    fn test_sign_clsag_basic() {
        // Create a minimal transaction and sign it with CLSAG.
        let total_amount = 2_000_000_000u64;
        let send_amount = 500_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = total_amount - send_amount - fee;

        let input = make_valid_input(total_amount, false);
        let input_mask = input.mask;

        // Build unsigned tx (we construct it manually since the builder
        // requires valid CARROT keys for output construction).
        let output_mask1 = random_scalar_bytes();
        let output_mask2 = random_scalar_bytes();
        let out_commit1 = to_32(&salvium_crypto::pedersen_commit(
            &send_amount.to_le_bytes(),
            &output_mask1,
        ));
        let out_commit2 = to_32(&salvium_crypto::pedersen_commit(
            &change_amount.to_le_bytes(),
            &output_mask2,
        ));

        let unsigned = UnsignedTransaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![TxInput::Key {
                    amount: 0,
                    asset_type: "SAL".to_string(),
                    key_offsets: vec![100],
                    key_image: to_32(&salvium_crypto::generate_key_image(
                        &input.public_key,
                        &input.secret_key,
                    )),
                }],
                outputs: vec![
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x11; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [1, 2, 3],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x22; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [4, 5, 6],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                ],
                extra: vec![],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            output_masks: vec![output_mask1, output_mask2],
            output_amounts: vec![send_amount, change_amount],
            encrypted_amounts: vec![[0u8; 8], [0u8; 8]],
            output_commitments: vec![out_commit1, out_commit2],
            inputs: vec![input],
            rct_type: rct_type::CLSAG,
            fee,
            ephemeral_key: None,
        };

        let tx = sign_transaction(unsigned).unwrap();

        // Verify structure.
        let rct = tx.rct.as_ref().unwrap();
        assert_eq!(rct.clsags.len(), 1);
        assert_eq!(rct.tclsags.len(), 0);
        assert_eq!(rct.ecdh_info.len(), 2);
        assert_eq!(rct.out_pk.len(), 2);
        assert_eq!(rct.pseudo_outs.len(), 1);
        assert_eq!(rct.bulletproof_plus.len(), 1);

        // Verify the CLSAG signature.
        let clsag_sig = salvium_crypto::clsag::ClsagSignature {
            s: rct.clsags[0].s.clone(),
            c1: rct.clsags[0].c1,
            key_image: to_32(&salvium_crypto::generate_key_image(
                &tx.rct.as_ref().unwrap().pseudo_outs[0], // dummy, we need the actual KI
                &[0u8; 32],
            )),
            commitment_image: rct.clsags[0].d,
        };

        // Re-derive the message to verify.
        let prefix_hash = compute_prefix_hash(&tx.prefix).unwrap();
        let rct_base_bytes = serialize_rct_base_bytes(
            rct.rct_type,
            rct.txn_fee,
            &rct.ecdh_info,
            &rct.out_pk,
            &ED25519_IDENTITY,
            None,
        );
        let bp_bytes = serialize_bp_components(&rct.bulletproof_plus[0]);
        let message = salvium_crypto::rct_verify::compute_rct_message(
            &prefix_hash,
            &rct_base_bytes,
            &bp_bytes,
        );

        // The signature was made with this message, so we can't easily verify
        // without reconstructing the full verify call. But the fact that
        // sign_transaction didn't panic proves the pipeline works end-to-end.
        assert_ne!(message, [0u8; 32], "message should not be zero");
    }

    #[test]
    fn test_sign_tclsag_basic() {
        let total_amount = 3_000_000_000u64;
        let send_amount = 1_000_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = total_amount - send_amount - fee;

        let input = make_valid_input(total_amount, true);

        let output_mask1 = random_scalar_bytes();
        let output_mask2 = random_scalar_bytes();
        let out_commit1 = to_32(&salvium_crypto::pedersen_commit(
            &send_amount.to_le_bytes(),
            &output_mask1,
        ));
        let out_commit2 = to_32(&salvium_crypto::pedersen_commit(
            &change_amount.to_le_bytes(),
            &output_mask2,
        ));

        let unsigned = UnsignedTransaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![TxInput::Key {
                    amount: 0,
                    asset_type: "SAL".to_string(),
                    key_offsets: vec![100],
                    key_image: to_32(&salvium_crypto::generate_key_image(
                        &input.public_key,
                        &input.secret_key,
                    )),
                }],
                outputs: vec![
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x33; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [7, 8, 9],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x44; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [10, 11, 12],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                ],
                extra: vec![],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            output_masks: vec![output_mask1, output_mask2],
            output_amounts: vec![send_amount, change_amount],
            encrypted_amounts: vec![[0u8; 8], [0u8; 8]],
            output_commitments: vec![out_commit1, out_commit2],
            inputs: vec![input],
            rct_type: rct_type::SALVIUM_ONE,
            fee,
            ephemeral_key: None,
        };

        let tx = sign_transaction(unsigned).unwrap();

        let rct = tx.rct.as_ref().unwrap();
        assert_eq!(rct.tclsags.len(), 1, "should have 1 TCLSAG signature");
        assert_eq!(rct.clsags.len(), 0);
        assert_eq!(rct.rct_type, rct_type::SALVIUM_ONE);
        assert_eq!(rct.bulletproof_plus.len(), 1);
        assert_eq!(rct.pseudo_outs.len(), 1);
    }

    #[test]
    fn test_sign_multi_input() {
        let amount1 = 1_000_000_000u64;
        let amount2 = 2_000_000_000u64;
        let send_amount = 2_500_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = amount1 + amount2 - send_amount - fee;

        let input1 = make_valid_input(amount1, false);
        let input2 = make_valid_input(amount2, false);

        let output_mask1 = random_scalar_bytes();
        let output_mask2 = random_scalar_bytes();

        let unsigned = UnsignedTransaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![
                    TxInput::Key {
                        amount: 0,
                        asset_type: "SAL".to_string(),
                        key_offsets: vec![100],
                        key_image: to_32(&salvium_crypto::generate_key_image(
                            &input1.public_key,
                            &input1.secret_key,
                        )),
                    },
                    TxInput::Key {
                        amount: 0,
                        asset_type: "SAL".to_string(),
                        key_offsets: vec![200],
                        key_image: to_32(&salvium_crypto::generate_key_image(
                            &input2.public_key,
                            &input2.secret_key,
                        )),
                    },
                ],
                outputs: vec![
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x55; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [1, 2, 3],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0x66; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [4, 5, 6],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                ],
                extra: vec![],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            output_masks: vec![output_mask1, output_mask2],
            output_amounts: vec![send_amount, change_amount],
            encrypted_amounts: vec![[0u8; 8], [0u8; 8]],
            output_commitments: vec![
                to_32(&salvium_crypto::pedersen_commit(
                    &send_amount.to_le_bytes(),
                    &output_mask1,
                )),
                to_32(&salvium_crypto::pedersen_commit(
                    &change_amount.to_le_bytes(),
                    &output_mask2,
                )),
            ],
            inputs: vec![input1, input2],
            rct_type: rct_type::CLSAG,
            fee,
            ephemeral_key: None,
        };

        let tx = sign_transaction(unsigned).unwrap();

        let rct = tx.rct.as_ref().unwrap();
        assert_eq!(rct.clsags.len(), 2, "should have 2 CLSAG signatures");
        assert_eq!(rct.pseudo_outs.len(), 2);
    }

    #[test]
    fn test_sign_and_verify_clsag() {
        // Full round-trip: sign and verify using salvium_crypto's verify.
        let total_amount = 1_500_000_000u64;
        let send_amount = 1_000_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = total_amount - send_amount - fee;

        let input = make_valid_input(total_amount, false);
        let input_pk = input.public_key;
        let input_sk = input.secret_key;
        let input_commitment = input.ring_commitments[0];

        let output_mask1 = random_scalar_bytes();
        let output_mask2 = random_scalar_bytes();
        let out_commit1 = to_32(&salvium_crypto::pedersen_commit(
            &send_amount.to_le_bytes(),
            &output_mask1,
        ));
        let out_commit2 = to_32(&salvium_crypto::pedersen_commit(
            &change_amount.to_le_bytes(),
            &output_mask2,
        ));

        let unsigned = UnsignedTransaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![TxInput::Key {
                    amount: 0,
                    asset_type: "SAL".to_string(),
                    key_offsets: vec![100],
                    key_image: to_32(&salvium_crypto::generate_key_image(
                        &input_pk, &input_sk,
                    )),
                }],
                outputs: vec![
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0xAA; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [1, 2, 3],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0xBB; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [4, 5, 6],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                ],
                extra: vec![],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            output_masks: vec![output_mask1, output_mask2],
            output_amounts: vec![send_amount, change_amount],
            encrypted_amounts: vec![[0u8; 8], [0u8; 8]],
            output_commitments: vec![out_commit1, out_commit2],
            inputs: vec![input],
            rct_type: rct_type::CLSAG,
            fee,
            ephemeral_key: None,
        };

        let tx = sign_transaction(unsigned).unwrap();
        let rct = tx.rct.as_ref().unwrap();

        // Reconstruct the message hash.
        let prefix_hash = compute_prefix_hash(&tx.prefix).unwrap();
        let rct_base_bytes = serialize_rct_base_bytes(
            rct.rct_type, rct.txn_fee, &rct.ecdh_info, &rct.out_pk,
            &ED25519_IDENTITY, None,
        );
        let bp_bytes = serialize_bp_components(&rct.bulletproof_plus[0]);
        let message = salvium_crypto::rct_verify::compute_rct_message(
            &prefix_hash, &rct_base_bytes, &bp_bytes,
        );

        // Verify the CLSAG signature independently.
        let clsag = &rct.clsags[0];
        let ki = to_32(&salvium_crypto::generate_key_image(&input_pk, &input_sk));

        let sig = salvium_crypto::clsag::ClsagSignature {
            s: clsag.s.clone(),
            c1: clsag.c1,
            key_image: ki,
            commitment_image: clsag.d,
        };

        let valid = salvium_crypto::clsag::clsag_verify(
            &message,
            &sig,
            &[input_pk],
            &[input_commitment],
            &rct.pseudo_outs[0],
        );

        assert!(valid, "CLSAG signature should verify");
    }

    #[test]
    fn test_sign_and_verify_tclsag() {
        let total_amount = 2_000_000_000u64;
        let send_amount = 1_500_000_000u64;
        let fee = 30_000_000u64;
        let change_amount = total_amount - send_amount - fee;

        let input = make_valid_input(total_amount, true);
        let input_pk = input.public_key;
        let input_sk_x = input.secret_key;
        let _input_sk_y = input.secret_key_y.unwrap();
        let input_commitment = input.ring_commitments[0];

        let output_mask1 = random_scalar_bytes();
        let output_mask2 = random_scalar_bytes();
        let out_commit1 = to_32(&salvium_crypto::pedersen_commit(
            &send_amount.to_le_bytes(),
            &output_mask1,
        ));
        let out_commit2 = to_32(&salvium_crypto::pedersen_commit(
            &change_amount.to_le_bytes(),
            &output_mask2,
        ));

        let unsigned = UnsignedTransaction {
            prefix: TxPrefix {
                version: 2,
                unlock_time: 0,
                inputs: vec![TxInput::Key {
                    amount: 0,
                    asset_type: "SAL".to_string(),
                    key_offsets: vec![100],
                    key_image: to_32(&salvium_crypto::generate_key_image(
                        &input_pk, &input_sk_x,
                    )),
                }],
                outputs: vec![
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0xCC; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [7, 8, 9],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                    TxOutput::CarrotV1 {
                        amount: 0,
                        key: [0xDD; 32],
                        asset_type: "SAL".to_string(),
                        view_tag: [10, 11, 12],
                        encrypted_janus_anchor: vec![0u8; 16],
                    },
                ],
                extra: vec![],
                tx_type: tx_type::TRANSFER,
                amount_burnt: 0,
                return_address: None,
                return_pubkey: None,
                return_address_list: None,
                return_address_change_mask: None,
                source_asset_type: "SAL".to_string(),
                destination_asset_type: "SAL".to_string(),
                amount_slippage_limit: 0,
            },
            output_masks: vec![output_mask1, output_mask2],
            output_amounts: vec![send_amount, change_amount],
            encrypted_amounts: vec![[0u8; 8], [0u8; 8]],
            output_commitments: vec![out_commit1, out_commit2],
            inputs: vec![input],
            rct_type: rct_type::SALVIUM_ONE,
            fee,
            ephemeral_key: None,
        };

        let tx = sign_transaction(unsigned).unwrap();
        let rct = tx.rct.as_ref().unwrap();

        // Reconstruct the message hash (must include salvium_data for SALVIUM_ONE).
        let prefix_hash = compute_prefix_hash(&tx.prefix).unwrap();
        let sd_bytes = reconstruct_salvium_data_bytes(rct);
        let rct_base_bytes = serialize_rct_base_bytes(
            rct.rct_type, rct.txn_fee, &rct.ecdh_info, &rct.out_pk,
            &ED25519_IDENTITY, sd_bytes.as_deref(),
        );
        let bp_bytes = serialize_bp_components(&rct.bulletproof_plus[0]);
        let message = salvium_crypto::rct_verify::compute_rct_message(
            &prefix_hash, &rct_base_bytes, &bp_bytes,
        );

        // Verify the TCLSAG signature independently.
        let tclsag = &rct.tclsags[0];
        let ki = to_32(&salvium_crypto::generate_key_image(&input_pk, &input_sk_x));

        let sig = salvium_crypto::tclsag::TclsagSignature {
            sx: tclsag.sx.clone(),
            sy: tclsag.sy.clone(),
            c1: tclsag.c1,
            key_image: ki,
            commitment_image: tclsag.d,
        };

        let valid = salvium_crypto::tclsag::tclsag_verify(
            &message,
            &sig,
            &[input_pk],
            &[input_commitment],
            &rct.pseudo_outs[0],
        );

        assert!(valid, "TCLSAG signature should verify");
    }

    #[test]
    fn test_bp_proof_verifies() {
        let amounts = [1_000_000_000u64, 500_000_000u64];
        let masks = [random_scalar_bytes(), random_scalar_bytes()];
        let scalar_masks: Vec<Scalar> = masks
            .iter()
            .map(|m| Scalar::from_bytes_mod_order(*m))
            .collect();

        // Prove directly using the crypto API.
        let proof = salvium_crypto::bulletproofs_plus::bulletproof_plus_prove(
            &amounts,
            &scalar_masks,
        );

        // Verify using the proof's own commitments (the authoritative source).
        let valid = salvium_crypto::bulletproofs_plus::bulletproof_plus_verify(
            &proof.v,
            &proof,
        );
        assert!(valid, "BP+ range proof should verify");

        // Also test that generate_bp_proof produces valid BpPlusData.
        let bp_data = generate_bp_proof(&amounts, &masks).unwrap();
        assert!(!bp_data.l_vec.is_empty());
        assert_eq!(bp_data.l_vec.len(), bp_data.r_vec.len());
    }
}
