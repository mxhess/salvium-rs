//! MuSig2-style partial CLSAG signing for multisig transactions.
//!
//! Implements the partial signing protocol where each signer produces:
//! - 2 random nonces per input (`alpha_0`, `alpha_1`)
//! - Public nonces: `alpha_G_i = alpha_i * G`, `alpha_H_i = alpha_i * H_p(pubkey)`
//! - Combined nonce: `b = H(domain, ring, commitment, msg, total_alpha_G, total_alpha_H)`
//!   `alpha = b^0 * alpha_0 + b^1 * alpha_1`
//! - Partial response: `s_partial = alpha - c * privkey_share`

use serde::{Deserialize, Serialize};

/// Per-input context for multisig CLSAG signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigClsagContext {
    /// Ring member public keys (hex-encoded, `ring_size` entries).
    pub ring: Vec<String>,
    /// Ring member commitments (hex-encoded, `ring_size` entries).
    pub commitments: Vec<String>,
    /// The key image for this input (hex-encoded).
    pub key_image: String,
    /// The pseudo-output commitment (hex-encoded).
    pub pseudo_output_commitment: String,
    /// Message to sign (hex-encoded transaction prefix hash).
    pub message: String,
    /// Index of the real input in the ring.
    pub real_index: usize,
    /// Whether to use TCLSAG (for CARROT outputs, rct_type >= 9).
    /// TCLSAG adds `sy` responses for the second key image dimension.
    #[serde(default)]
    pub use_tclsag: bool,
    /// Second key image (K_y) for TCLSAG, if applicable (hex-encoded).
    #[serde(default)]
    pub key_image_y: Option<String>,
}

/// A signer's nonce contribution for one input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerNonces {
    /// Signer index.
    pub signer_index: usize,
    /// Secret nonces (2 per input) — kept private, NOT serialized for exchange.
    #[serde(skip)]
    pub secret_nonces: Vec<[u8; 32]>,
    /// Public nonces on G: `alpha_i * G` (hex-encoded, 2 entries).
    pub pub_nonces_g: Vec<String>,
    /// Public nonces on H_p: `alpha_i * H_p(key_image)` (hex-encoded, 2 entries).
    pub pub_nonces_hp: Vec<String>,
    /// TCLSAG: secret nonces for the Y dimension (2 per input).
    #[serde(skip, default)]
    pub secret_nonces_y: Vec<[u8; 32]>,
    /// TCLSAG: public nonces on G for Y dimension (hex-encoded, 2 entries).
    #[serde(default)]
    pub pub_nonces_g_y: Vec<String>,
    /// TCLSAG: public nonces on H_p(K_y) for Y dimension (hex-encoded, 2 entries).
    #[serde(default)]
    pub pub_nonces_hp_y: Vec<String>,
}

/// A partial CLSAG signature from one signer for one input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialClsag {
    /// Signer index.
    pub signer_index: usize,
    /// The partial response scalar s (hex-encoded).
    pub s_partial: String,
    /// The challenge scalar c_0 (hex-encoded, only meaningful from first signer).
    pub c_0: String,
    /// TCLSAG: partial response scalar for the Y dimension (hex-encoded).
    #[serde(default)]
    pub sy_partial: Option<String>,
}

/// Decode a hex string to exactly 32 bytes.
fn hex_to_32(hex_str: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex for {}: {}", label, e))?;
    if bytes.len() != 32 {
        return Err(format!("{}: expected 32 bytes, got {}", label, bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Generate nonces for a single input.
///
/// Returns `SignerNonces` with 2 random scalar nonces and their public points.
/// If `key_image_y_hex` is provided, also generates TCLSAG Y-dimension nonces.
pub fn generate_nonces(signer_index: usize, key_image_hex: &str) -> Result<SignerNonces, String> {
    generate_nonces_ext(signer_index, key_image_hex, None)
}

/// Extended nonce generation with optional TCLSAG Y key image.
pub fn generate_nonces_ext(
    signer_index: usize,
    key_image_hex: &str,
    key_image_y_hex: Option<&str>,
) -> Result<SignerNonces, String> {
    let mut rng = rand::thread_rng();
    let key_image_bytes =
        hex::decode(key_image_hex).map_err(|e| format!("invalid key_image hex: {}", e))?;
    if key_image_bytes.len() != 32 {
        return Err(format!(
            "key_image: expected 32 bytes, got {}",
            key_image_bytes.len()
        ));
    }
    let hp = salvium_crypto::hash_to_point(&key_image_bytes);

    let mut secret_nonces = Vec::with_capacity(2);
    let mut pub_nonces_g = Vec::with_capacity(2);
    let mut pub_nonces_hp = Vec::with_capacity(2);

    for _ in 0..2 {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut buf);
        let scalar = salvium_crypto::sc_reduce32(&buf);
        let mut scalar32 = [0u8; 32];
        scalar32.copy_from_slice(&scalar[..32]);

        let point_g = salvium_crypto::scalar_mult_base(&scalar32);
        pub_nonces_g.push(hex::encode(&point_g));

        let point_hp = salvium_crypto::scalar_mult_point(&scalar32, &hp);
        pub_nonces_hp.push(hex::encode(&point_hp));

        secret_nonces.push(scalar32);
    }

    // TCLSAG: generate Y-dimension nonces if a second key image is provided.
    let (secret_nonces_y, pub_nonces_g_y, pub_nonces_hp_y) = if let Some(ki_y_hex) = key_image_y_hex
    {
        let ki_y_bytes =
            hex::decode(ki_y_hex).map_err(|e| format!("invalid key_image_y hex: {}", e))?;
        if ki_y_bytes.len() != 32 {
            return Err(format!(
                "key_image_y: expected 32 bytes, got {}",
                ki_y_bytes.len()
            ));
        }
        let hp_y = salvium_crypto::hash_to_point(&ki_y_bytes);

        let mut sec_y = Vec::with_capacity(2);
        let mut pub_g_y = Vec::with_capacity(2);
        let mut pub_hp_y = Vec::with_capacity(2);

        for _ in 0..2 {
            let mut buf = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut buf);
            let scalar = salvium_crypto::sc_reduce32(&buf);
            let mut s32 = [0u8; 32];
            s32.copy_from_slice(&scalar[..32]);

            let pg = salvium_crypto::scalar_mult_base(&s32);
            pub_g_y.push(hex::encode(&pg));

            let php = salvium_crypto::scalar_mult_point(&s32, &hp_y);
            pub_hp_y.push(hex::encode(&php));

            sec_y.push(s32);
        }
        (sec_y, pub_g_y, pub_hp_y)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    Ok(SignerNonces {
        signer_index,
        secret_nonces,
        pub_nonces_g,
        pub_nonces_hp,
        secret_nonces_y,
        pub_nonces_g_y,
        pub_nonces_hp_y,
    })
}

/// Compute the nonce combination factor `b` from all signers' public nonces.
///
/// b = H("CLSAG_round_nonce" || ring || commitment || message || sum_alpha_G || sum_alpha_H)
pub fn compute_nonce_binding(
    ctx: &MultisigClsagContext,
    all_nonces: &[SignerNonces],
) -> Result<Vec<u8>, String> {
    if all_nonces.len() < 2 {
        return Err(format!(
            "need at least 2 signers' nonces, got {}",
            all_nonces.len()
        ));
    }
    for (i, nonces) in all_nonces.iter().enumerate() {
        if nonces.pub_nonces_g.len() != 2 || nonces.pub_nonces_hp.len() != 2 {
            return Err(format!(
                "signer {} nonces must have exactly 2 components",
                i
            ));
        }
    }

    // Sum all public nonces across signers.
    let mut total_g = [[0u8; 32]; 2];
    let mut total_hp = [[0u8; 32]; 2];

    for nonces in all_nonces {
        for i in 0..2 {
            let g_bytes = hex_to_32(&nonces.pub_nonces_g[i], "pub_nonce_g")?;
            let hp_bytes = hex_to_32(&nonces.pub_nonces_hp[i], "pub_nonce_hp")?;

            if total_g[i] == [0u8; 32] {
                total_g[i] = g_bytes;
                total_hp[i] = hp_bytes;
            } else {
                let sum_g = salvium_crypto::point_add_compressed(&total_g[i], &g_bytes);
                total_g[i].copy_from_slice(&sum_g[..32]);
                let sum_hp = salvium_crypto::point_add_compressed(&total_hp[i], &hp_bytes);
                total_hp[i].copy_from_slice(&sum_hp[..32]);
            }
        }
    }

    // Hash everything together.
    let mut data = Vec::new();
    data.extend_from_slice(b"CLSAG_round_nonce");
    for ring_member in &ctx.ring {
        let bytes = hex_to_32(ring_member, "ring member")?;
        data.extend_from_slice(&bytes);
    }
    for commitment in &ctx.commitments {
        let bytes = hex_to_32(commitment, "commitment")?;
        data.extend_from_slice(&bytes);
    }
    let msg_bytes = hex_to_32(&ctx.message, "message")?;
    data.extend_from_slice(&msg_bytes);
    for i in 0..2 {
        data.extend_from_slice(&total_g[i]);
        data.extend_from_slice(&total_hp[i]);
    }

    Ok(salvium_crypto::keccak256(&data))
}

/// Produce a partial CLSAG signature for one input.
///
/// Each signer computes:
///   `combined_alpha = b^0 * alpha_0 + b^1 * alpha_1`
///   s_partial = combined_alpha - c * privkey_share
///
/// where `c` is the challenge at the real input index and `privkey_share` is this
/// signer's share of the private key.
pub fn partial_sign(
    ctx: &MultisigClsagContext,
    nonces: &SignerNonces,
    privkey_share_hex: &str,
    all_nonces: &[SignerNonces],
) -> Result<PartialClsag, String> {
    // Input validation
    if ctx.ring.is_empty() {
        return Err("ring is empty".to_string());
    }
    if ctx.real_index >= ctx.ring.len() {
        return Err(format!(
            "real_index {} >= ring size {}",
            ctx.real_index,
            ctx.ring.len()
        ));
    }
    if all_nonces.len() < 2 {
        return Err(format!(
            "need at least 2 signers' nonces, got {}",
            all_nonces.len()
        ));
    }

    let b = compute_nonce_binding(ctx, all_nonces)?;
    let mut b32 = [0u8; 32];
    b32.copy_from_slice(&b[..32]);
    let b_reduced = salvium_crypto::sc_reduce32(&b32);

    // combined_alpha = alpha[0] + b * alpha[1]
    let alpha0 = nonces.secret_nonces[0];
    let alpha1 = nonces.secret_nonces[1];

    // Compute: combined_alpha = alpha0 + b * alpha1
    // Using: neg_b = -b, then sc_mul_sub(neg_b, alpha1, alpha0) = alpha0 - (-b)*alpha1 = alpha0 + b*alpha1
    let one = {
        let mut v = [0u8; 32];
        v[0] = 1;
        v
    };
    let zero = [0u8; 32];

    let mut b_arr = [0u8; 32];
    b_arr.copy_from_slice(&b_reduced[..32]);
    let neg_b_vec = salvium_crypto::sc_mul_sub(&one, &b_arr, &zero);
    let mut neg_b = [0u8; 32];
    neg_b.copy_from_slice(&neg_b_vec[..32]);

    let combined_vec = salvium_crypto::sc_mul_sub(&neg_b, &alpha1, &alpha0);
    let mut combined_alpha = [0u8; 32];
    combined_alpha.copy_from_slice(&combined_vec[..32]);

    // Compute challenge c at the real index.
    let combined_g = salvium_crypto::scalar_mult_base(&combined_alpha);
    let mut c_data = Vec::new();
    c_data.extend_from_slice(b"CLSAG_c");
    let ring_real = hex_to_32(&ctx.ring[ctx.real_index], "ring[real_index]")?;
    c_data.extend_from_slice(&ring_real);
    let ki_bytes = hex_to_32(&ctx.key_image, "key_image")?;
    c_data.extend_from_slice(&ki_bytes);
    let pseudo_bytes = hex_to_32(&ctx.pseudo_output_commitment, "pseudo_output_commitment")?;
    c_data.extend_from_slice(&pseudo_bytes);
    let msg_bytes = hex_to_32(&ctx.message, "message")?;
    c_data.extend_from_slice(&msg_bytes);
    c_data.extend_from_slice(&combined_g);
    let c_hash = salvium_crypto::keccak256(&c_data);
    let c_reduced = salvium_crypto::sc_reduce32(&c_hash);
    let mut c32 = [0u8; 32];
    c32.copy_from_slice(&c_reduced[..32]);

    // s_partial = combined_alpha - c * privkey_share
    let privkey32 = hex_to_32(privkey_share_hex, "privkey_share")?;

    // sc_mul_sub(c, privkey, combined_alpha) = combined_alpha - c*privkey
    let s_vec = salvium_crypto::sc_mul_sub(&c32, &privkey32, &combined_alpha);

    Ok(PartialClsag {
        signer_index: nonces.signer_index,
        s_partial: hex::encode(&s_vec),
        c_0: hex::encode(c32),
        sy_partial: None,
    })
}

/// Produce a partial TCLSAG signature for one input (CARROT outputs).
///
/// In addition to the standard `s_partial`, computes `sy_partial` for the Y dimension
/// using the second private key share (`privkey_y_share_hex`).
pub fn partial_sign_tclsag(
    ctx: &MultisigClsagContext,
    nonces: &SignerNonces,
    privkey_share_hex: &str,
    privkey_y_share_hex: &str,
    all_nonces: &[SignerNonces],
) -> Result<PartialClsag, String> {
    // Get the standard partial first.
    let mut partial = partial_sign(ctx, nonces, privkey_share_hex, all_nonces)?;

    // TCLSAG: compute sy_partial = combined_alpha_y - c * privkey_y_share
    if !nonces.secret_nonces_y.is_empty() && nonces.secret_nonces_y.len() >= 2 {
        let b = compute_nonce_binding(ctx, all_nonces)?;
        let b_reduced = salvium_crypto::sc_reduce32(&b);

        let one = {
            let mut v = [0u8; 32];
            v[0] = 1;
            v
        };
        let zero = [0u8; 32];

        let mut b_arr = [0u8; 32];
        b_arr.copy_from_slice(&b_reduced[..32]);
        let neg_b_vec = salvium_crypto::sc_mul_sub(&one, &b_arr, &zero);
        let mut neg_b = [0u8; 32];
        neg_b.copy_from_slice(&neg_b_vec[..32]);

        let alpha0_y = nonces.secret_nonces_y[0];
        let alpha1_y = nonces.secret_nonces_y[1];

        // combined_alpha_y = alpha0_y + b * alpha1_y
        let combined_y_vec = salvium_crypto::sc_mul_sub(&neg_b, &alpha1_y, &alpha0_y);
        let mut combined_alpha_y = [0u8; 32];
        combined_alpha_y.copy_from_slice(&combined_y_vec[..32]);

        // Use the same challenge c
        let c32 = hex_to_32(&partial.c_0, "c_0")?;
        let privkey_y32 = hex_to_32(privkey_y_share_hex, "privkey_y_share")?;

        // sy_partial = combined_alpha_y - c * privkey_y_share
        let sy_vec = salvium_crypto::sc_mul_sub(&c32, &privkey_y32, &combined_alpha_y);
        partial.sy_partial = Some(hex::encode(&sy_vec));
    }

    Ok(partial)
}

/// Add two scalars: a + b (mod l).
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    // sc_mul_sub(x, y, c) = c - x*y. We want a + b = b - (-1)*a.
    let neg_one = {
        let mut v = [0u8; 32];
        v[0] = 1;
        let zero = [0u8; 32];
        let neg = salvium_crypto::sc_mul_sub(&v, &v, &zero); // 0 - 1*1 = -1
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&neg[..32]);
        arr
    };
    let sum_vec = salvium_crypto::sc_mul_sub(&neg_one, a, b);
    let mut result = [0u8; 32];
    result.copy_from_slice(&sum_vec[..32]);
    result
}

/// Combined CLSAG result with optional TCLSAG `sy` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedClsag {
    /// Combined `s` response scalar (hex-encoded).
    pub s: String,
    /// Challenge `c_0` at the real index (hex-encoded).
    pub c_0: String,
    /// TCLSAG: combined `sy` response scalar (hex-encoded), if applicable.
    pub sy: Option<String>,
}

/// Combine partial signatures from all signers into a final CLSAG response.
///
/// The final s = sum(s_partial_i) for each input.
/// For TCLSAG, also combines sy_partial values.
pub fn combine_partial_signatures(partials: &[PartialClsag]) -> Result<(String, String), String> {
    let combined = combine_partial_signatures_ext(partials)?;
    Ok((combined.s, combined.c_0))
}

/// Extended combination that also returns the TCLSAG `sy` response.
pub fn combine_partial_signatures_ext(partials: &[PartialClsag]) -> Result<CombinedClsag, String> {
    if partials.is_empty() {
        return Ok(CombinedClsag {
            s: hex::encode([0u8; 32]),
            c_0: hex::encode([0u8; 32]),
            sy: None,
        });
    }

    let c_0 = partials[0].c_0.clone();
    let mut s_sum = [0u8; 32];
    let mut has_sy = false;
    let mut sy_sum = [0u8; 32];

    for (i, partial) in partials.iter().enumerate() {
        let s32 = hex_to_32(&partial.s_partial, "s_partial")?;

        if i == 0 {
            s_sum = s32;
        } else {
            s_sum = scalar_add(&s_sum, &s32);
        }

        // TCLSAG sy accumulation
        if let Some(ref sy_hex) = partial.sy_partial {
            has_sy = true;
            let sy32 = hex_to_32(sy_hex, "sy_partial")?;
            if i == 0 {
                sy_sum = sy32;
            } else {
                sy_sum = scalar_add(&sy_sum, &sy32);
            }
        }
    }

    Ok(CombinedClsag {
        s: hex::encode(s_sum),
        c_0,
        sy: if has_sy {
            Some(hex::encode(sy_sum))
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonces() {
        // Use a well-known base point as a stand-in key image.
        let key_image = "58".repeat(32);
        let nonces = generate_nonces(0, &key_image).unwrap();
        assert_eq!(nonces.signer_index, 0);
        assert_eq!(nonces.secret_nonces.len(), 2);
        assert_eq!(nonces.pub_nonces_g.len(), 2);
        assert_eq!(nonces.pub_nonces_hp.len(), 2);
        // Public nonces should be valid 32-byte hex.
        for pn in &nonces.pub_nonces_g {
            assert_eq!(pn.len(), 64);
            hex::decode(pn).unwrap();
        }
    }

    #[test]
    fn test_generate_nonces_invalid_hex() {
        let result = generate_nonces(0, "not_valid_hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_nonces_wrong_length() {
        let result = generate_nonces(0, "aabb");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 32 bytes"));
    }

    #[test]
    fn test_partial_sign_produces_valid_output() {
        let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
        let ctx = MultisigClsagContext {
            ring: vec!["aa".repeat(32), "bb".repeat(32)],
            commitments: vec!["cc".repeat(32), "dd".repeat(32)],
            key_image: key_image.clone(),
            pseudo_output_commitment: "ee".repeat(32),
            message: "ff".repeat(32),
            real_index: 0,
            use_tclsag: false,
            key_image_y: None,
        };

        let nonces0 = generate_nonces(0, &key_image).unwrap();
        let nonces1 = generate_nonces(1, &key_image).unwrap();
        let privkey = "11".repeat(32);

        let partial = partial_sign(&ctx, &nonces0, &privkey, &[nonces0.clone(), nonces1]).unwrap();
        assert_eq!(partial.signer_index, 0);
        assert_eq!(partial.s_partial.len(), 64);
        assert_eq!(partial.c_0.len(), 64);
    }

    #[test]
    fn test_partial_sign_rejects_empty_ring() {
        let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
        let ctx = MultisigClsagContext {
            ring: vec![],
            commitments: vec![],
            key_image: key_image.clone(),
            pseudo_output_commitment: "ee".repeat(32),
            message: "ff".repeat(32),
            real_index: 0,
            use_tclsag: false,
            key_image_y: None,
        };
        let nonces0 = generate_nonces(0, &key_image).unwrap();
        let nonces1 = generate_nonces(1, &key_image).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            &[nonces0.clone(), nonces1],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_sign_rejects_bad_real_index() {
        let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
        let ctx = MultisigClsagContext {
            ring: vec!["aa".repeat(32)],
            commitments: vec!["cc".repeat(32)],
            key_image: key_image.clone(),
            pseudo_output_commitment: "ee".repeat(32),
            message: "ff".repeat(32),
            real_index: 5,
            use_tclsag: false,
            key_image_y: None,
        };
        let nonces0 = generate_nonces(0, &key_image).unwrap();
        let nonces1 = generate_nonces(1, &key_image).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            &[nonces0.clone(), nonces1],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("real_index"));
    }

    #[test]
    fn test_partial_sign_rejects_single_nonce() {
        let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
        let ctx = MultisigClsagContext {
            ring: vec!["aa".repeat(32), "bb".repeat(32)],
            commitments: vec!["cc".repeat(32), "dd".repeat(32)],
            key_image: key_image.clone(),
            pseudo_output_commitment: "ee".repeat(32),
            message: "ff".repeat(32),
            real_index: 0,
            use_tclsag: false,
            key_image_y: None,
        };
        let nonces0 = generate_nonces(0, &key_image).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            std::slice::from_ref(&nonces0),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 2"));
    }

    #[test]
    fn test_combine_partial_signatures() {
        let p1 = PartialClsag {
            signer_index: 0,
            s_partial: "01".repeat(32),
            c_0: "aa".repeat(32),
            sy_partial: None,
        };
        let p2 = PartialClsag {
            signer_index: 1,
            s_partial: "02".repeat(32),
            c_0: "aa".repeat(32),
            sy_partial: None,
        };

        let (s, c) = combine_partial_signatures(&[p1, p2]).unwrap();
        assert_eq!(s.len(), 64);
        assert_eq!(c.len(), 64);
        // c should be from the first partial.
        assert_eq!(c, "aa".repeat(32));
    }
}
