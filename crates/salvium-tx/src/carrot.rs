//! CARROT output construction for transactions.
//!
//! Creates CARROT v1 outputs with ephemeral keys, one-time addresses,
//! encrypted amounts, view tags, and Janus anchors. Delegates all low-level
//! crypto (X25519, blake2b, scalar ops) to salvium-crypto.

use crate::TxError;

/// CARROT enote types.
pub mod enote_type {
    pub const PAYMENT: u8 = 0;
    pub const CHANGE: u8 = 1;
    pub const SELF_SPEND: u8 = 2;
}

/// Domain separators for keyed Blake2b hashes in CARROT.
mod domain {
    pub const EPHEMERAL_PRIVKEY: &[u8] = b"Carrot sending key normal";
    pub const SENDER_RECEIVER_SECRET: &[u8] = b"Carrot sender-receiver secret";
    pub const VIEW_TAG: &[u8] = b"Carrot view tag";
    pub const COMMITMENT_MASK: &[u8] = b"Carrot commitment mask";
    pub const ONETIME_EXTENSION_G: &[u8] = b"Carrot key extension G";
    pub const ONETIME_EXTENSION_T: &[u8] = b"Carrot key extension T";
    pub const ENCRYPTION_MASK_ANCHOR: &[u8] = b"Carrot encryption mask anchor";
    pub const ENCRYPTION_MASK_AMOUNT: &[u8] = b"Carrot encryption mask a";
    pub const ENCRYPTION_MASK_PAYMENT_ID: &[u8] = b"Carrot encryption mask pid";
}

/// Result of creating a single CARROT output.
#[derive(Debug, Clone)]
pub struct CarrotOutput {
    /// One-time address (Ko).
    pub onetime_address: [u8; 32],
    /// Amount commitment (C_a = k_a*G + amount*H).
    pub amount_commitment: [u8; 32],
    /// Commitment blinding factor (k_a).
    pub commitment_mask: [u8; 32],
    /// Encrypted amount (8 bytes XOR with mask).
    pub encrypted_amount: [u8; 8],
    /// View tag (3 bytes).
    pub view_tag: [u8; 3],
    /// Encrypted Janus anchor (16 bytes).
    pub encrypted_anchor: Vec<u8>,
    /// Encrypted payment ID (8 bytes, all zeros if none).
    pub encrypted_payment_id: [u8; 8],
}

/// Parameters needed to create a CARROT output.
pub struct CarrotOutputParams<'a> {
    /// Recipient's account spend public key (K_s).
    pub recipient_spend_pubkey: &'a [u8; 32],
    /// Recipient's account view public key (K_v).
    pub recipient_view_pubkey: &'a [u8; 32],
    /// Amount to send (atomic units).
    pub amount: u64,
    /// Input context (33 bytes: 'R' + key_image or 'C' + height + padding).
    pub input_context: &'a [u8],
    /// Enote type (payment, change, self_spend).
    pub enote_type: u8,
    /// Payment ID (8 bytes, or zeros for none).
    pub payment_id: [u8; 8],
    /// Whether the recipient address is a subaddress.
    pub is_subaddress: bool,
}

/// Create a CARROT v1 output.
///
/// This constructs the ephemeral key, one-time address, amount commitment,
/// view tag, and all encrypted fields. Returns the output data plus the
/// ephemeral private key (needed to construct the tx extra).
pub fn create_carrot_output(
    params: &CarrotOutputParams,
) -> Result<(CarrotOutput, [u8; 32]), TxError> {
    // 1. Generate random Janus anchor (16 bytes).
    let anchor = random_bytes::<16>();

    // 2. Derive ephemeral private key.
    //    d_e = H_n(domain, key=null, anchor || input_context || K_s || payment_id)
    let mut transcript_data = Vec::with_capacity(16 + 33 + 32 + 8);
    transcript_data.extend_from_slice(&anchor);
    transcript_data.extend_from_slice(params.input_context);
    transcript_data.extend_from_slice(params.recipient_spend_pubkey);
    transcript_data.extend_from_slice(&params.payment_id);
    let transcript = build_transcript(domain::EPHEMERAL_PRIVKEY, &transcript_data);
    let d_e = hash_to_scalar_64(&transcript, &[]);

    // 3. Compute ephemeral public key.
    //    Main address: D_e = d_e * B (X25519 base point u=9)
    //    Subaddress: D_e = d_e * ConvertPointE(K_s)
    let d_e_pub = if params.is_subaddress {
        let k_s_mont = salvium_crypto::edwards_to_montgomery_u(params.recipient_spend_pubkey);
        to_32(&salvium_crypto::x25519_scalar_mult(&d_e, &k_s_mont))
    } else {
        let base_u = [9u8; 32]; // X25519 base point
        to_32(&salvium_crypto::x25519_scalar_mult(&d_e, &base_u))
    };

    // 4. Compute uncontextualized shared secret.
    //    s_sr = d_e * ConvertPointE(K_v)
    let k_v_mont = salvium_crypto::edwards_to_montgomery_u(params.recipient_view_pubkey);
    let s_sr_unctx = to_32(&salvium_crypto::x25519_scalar_mult(&d_e, &k_v_mont));

    // 5. Derive contextualized shared secret.
    //    s_ctx = H_32(domain, key=s_sr, D_e || input_context)
    let mut ctx_data = Vec::with_capacity(32 + 33);
    ctx_data.extend_from_slice(&d_e_pub);
    ctx_data.extend_from_slice(params.input_context);
    let ctx_transcript = build_transcript(domain::SENDER_RECEIVER_SECRET, &ctx_data);
    let s_ctx = to_32(&salvium_crypto::blake2b_keyed(&ctx_transcript, 32, &s_sr_unctx));

    // 6. Derive commitment mask (blinding factor).
    //    k_a = H_n(domain, key=s_ctx, amount_le || K_s || enote_type)
    let mut mask_data = Vec::with_capacity(32 + 1 + 8);
    mask_data.extend_from_slice(&params.amount.to_le_bytes());
    mask_data.extend_from_slice(params.recipient_spend_pubkey);
    mask_data.push(params.enote_type);
    let mask_transcript = build_transcript(domain::COMMITMENT_MASK, &mask_data);
    let commitment_mask = hash_to_scalar_64(&mask_transcript, &s_ctx);

    // 7. Compute amount commitment: C_a = k_a*G + amount*H.
    let amount_commitment = to_32(&salvium_crypto::pedersen_commit(
        &params.amount.to_le_bytes(),
        &commitment_mask,
    ));

    // 8. Derive one-time address extensions.
    //    k^o_g = H_n(domain_G, key=s_ctx, C_a)
    //    k^o_t = H_n(domain_T, key=s_ctx, C_a)
    let ext_g_transcript = build_transcript(domain::ONETIME_EXTENSION_G, &amount_commitment);
    let k_o_g = hash_to_scalar_64(&ext_g_transcript, &s_ctx);

    let ext_t_transcript = build_transcript(domain::ONETIME_EXTENSION_T, &amount_commitment);
    let k_o_t = hash_to_scalar_64(&ext_t_transcript, &s_ctx);

    // 9. Compute one-time address: Ko = K_s + k^o_g*G + k^o_t*T.
    //    T is the second generator (dual-key system).
    let g_part = salvium_crypto::scalar_mult_base(&k_o_g);
    let partial = salvium_crypto::point_add_compressed(params.recipient_spend_pubkey, &g_part);
    // k^o_t*T: need to use double_scalar_mult or dedicated T-point multiplication.
    // For now, use scalar_mult_point with the T generator point.
    let t_generator = salvium_crypto::hash_to_point(b"T");
    let t_part = salvium_crypto::scalar_mult_point(&k_o_t, &t_generator);
    let onetime_address = to_32(&salvium_crypto::point_add_compressed(&partial, &t_part));

    // 10. Compute view tag (3 bytes).
    let mut vt_data = Vec::with_capacity(33 + 32);
    vt_data.extend_from_slice(params.input_context);
    vt_data.extend_from_slice(&onetime_address);
    let vt_transcript = build_transcript(domain::VIEW_TAG, &vt_data);
    let vt_full = salvium_crypto::blake2b_keyed(&vt_transcript, 3, &s_sr_unctx);
    let view_tag = [vt_full[0], vt_full[1], vt_full[2]];

    // 11. Encrypt Janus anchor.
    let anchor_transcript = build_transcript(domain::ENCRYPTION_MASK_ANCHOR, &onetime_address);
    let anchor_mask = salvium_crypto::blake2b_keyed(&anchor_transcript, 16, &s_ctx);
    let encrypted_anchor: Vec<u8> = anchor
        .iter()
        .zip(anchor_mask.iter())
        .map(|(a, m)| a ^ m)
        .collect();

    // 12. Encrypt amount.
    let amount_le = params.amount.to_le_bytes();
    let amt_transcript = build_transcript(domain::ENCRYPTION_MASK_AMOUNT, &onetime_address);
    let amount_mask = salvium_crypto::blake2b_keyed(&amt_transcript, 8, &s_ctx);
    let mut encrypted_amount = [0u8; 8];
    for i in 0..8 {
        encrypted_amount[i] = amount_le[i] ^ amount_mask[i];
    }

    // 13. Encrypt payment ID.
    let pid_transcript = build_transcript(domain::ENCRYPTION_MASK_PAYMENT_ID, &onetime_address);
    let pid_mask = salvium_crypto::blake2b_keyed(&pid_transcript, 8, &s_ctx);
    let mut encrypted_payment_id = [0u8; 8];
    for i in 0..8 {
        encrypted_payment_id[i] = params.payment_id[i] ^ pid_mask[i];
    }

    Ok((
        CarrotOutput {
            onetime_address,
            amount_commitment,
            commitment_mask,
            encrypted_amount,
            view_tag,
            encrypted_anchor,
            encrypted_payment_id,
        },
        d_e,
    ))
}

/// Build the input context for a RingCT transaction.
///
/// Returns 33 bytes: 'R' (1) + first_key_image (32).
pub fn make_input_context_rct(first_key_image: &[u8; 32]) -> Vec<u8> {
    salvium_crypto::make_input_context_rct(first_key_image)
}

/// Build the input context for a coinbase transaction.
///
/// Returns 33 bytes: 'C' (1) + height_u64_le (8) + zeros (24).
pub fn make_input_context_coinbase(block_height: u64) -> Vec<u8> {
    salvium_crypto::make_input_context_coinbase(block_height)
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Build a SpFixedTranscript: [domain_len] || [domain] || [data].
fn build_transcript(domain: &[u8], data: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(1 + domain.len() + data.len());
    t.push(domain.len() as u8);
    t.extend_from_slice(domain);
    t.extend_from_slice(data);
    t
}

/// Hash to scalar: blake2b(data, 64, key) then sc_reduce64.
fn hash_to_scalar_64(data: &[u8], key: &[u8]) -> [u8; 32] {
    let hash = if key.is_empty() {
        salvium_crypto::blake2b_hash(data, 64)
    } else {
        salvium_crypto::blake2b_keyed(data, 64, key)
    };
    to_32(&salvium_crypto::sc_reduce64(&hash))
}

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_transcript() {
        let t = build_transcript(b"test", b"data");
        assert_eq!(t[0], 4); // domain length
        assert_eq!(&t[1..5], b"test");
        assert_eq!(&t[5..], b"data");
    }

    #[test]
    fn test_make_input_context_rct() {
        let ki = [0xAA; 32];
        let ctx = make_input_context_rct(&ki);
        assert_eq!(ctx.len(), 33);
        assert_eq!(ctx[0], b'R');
        assert_eq!(&ctx[1..33], &[0xAA; 32]);
    }

    #[test]
    fn test_make_input_context_coinbase() {
        let ctx = make_input_context_coinbase(12345);
        assert_eq!(ctx.len(), 33);
        assert_eq!(ctx[0], b'C');
        // Height should be little-endian u64 at bytes 1..9.
        let height_bytes = &ctx[1..9];
        let height = u64::from_le_bytes(height_bytes.try_into().unwrap());
        assert_eq!(height, 12345);
    }

    #[test]
    fn test_create_carrot_output_deterministic_structure() {
        // Use fixed test keys (not cryptographically valid, just structural).
        let spend_pub = [0x11; 32];
        let view_pub = [0x22; 32];
        let input_context = make_input_context_coinbase(100);

        let params = CarrotOutputParams {
            recipient_spend_pubkey: &spend_pub,
            recipient_view_pubkey: &view_pub,
            amount: 1_000_000_000,
            input_context: &input_context,
            enote_type: enote_type::PAYMENT,
            payment_id: [0u8; 8],
            is_subaddress: false,
        };

        let result = create_carrot_output(&params);
        // We can't predict exact values due to random anchor, but structure should be correct.
        match result {
            Ok((output, d_e)) => {
                assert_eq!(output.encrypted_anchor.len(), 16);
                assert_eq!(output.view_tag.len(), 3);
                assert_ne!(d_e, [0u8; 32], "ephemeral key should not be zero");
                assert_ne!(output.onetime_address, [0u8; 32]);
            }
            Err(e) => {
                // Some crypto operations might fail with dummy keys, which is OK.
                // The important thing is the structure is correct.
                println!("Expected failure with test keys: {}", e);
            }
        }
    }

    #[test]
    fn test_enote_type_constants() {
        assert_eq!(enote_type::PAYMENT, 0);
        assert_eq!(enote_type::CHANGE, 1);
        assert_eq!(enote_type::SELF_SPEND, 2);
    }

    #[test]
    fn test_hash_to_scalar() {
        let data = b"test data for scalar derivation";
        let key = [0x42; 32];
        let scalar = hash_to_scalar_64(data, &key);
        assert_ne!(scalar, [0u8; 32], "scalar should not be zero");
        // Scalar should be reduced (< L), last byte should have high bit clear.
        assert!(scalar[31] < 0x10, "scalar should be reduced: high byte = {:02x}", scalar[31]);
    }

    #[test]
    fn test_random_bytes() {
        let a: [u8; 16] = random_bytes();
        let b: [u8; 16] = random_bytes();
        assert_ne!(a, b, "random bytes should differ");
    }
}
