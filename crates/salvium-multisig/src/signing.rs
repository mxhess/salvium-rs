//! MuSig2-style partial CLSAG signing for multisig transactions.
//!
//! Implements the partial signing protocol where each signer produces:
//! - 2 random nonces per input (`alpha_0`, `alpha_1`)
//! - Public nonces: `alpha_G_i = alpha_i * G`, `alpha_H_i = alpha_i * H_p(pubkey)`
//! - Combined nonce via MuSig2 binding: `b = H(context)`, `alpha = alpha_0 + b * alpha_1`
//! - Ring traversal to compute challenge `c` at the real index
//! - Partial response: `s_partial = alpha_combined - c * (mu_P * privkey_share + mu_C * z_share)`

use serde::{Deserialize, Serialize};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a byte slice to a fixed 32-byte array.
fn to_arr32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

/// Pad a domain separator to 32 bytes (matching clsag.rs pad_domain).
fn pad_domain(s: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = s.len().min(32);
    buf[..len].copy_from_slice(&s[..len]);
    buf
}

/// Hash data to a scalar: keccak256(data) then reduce mod L.
fn hash_to_scalar_bytes(data: &[u8]) -> [u8; 32] {
    let hash = salvium_crypto::keccak256(data);
    to_arr32(&salvium_crypto::sc_reduce32(&hash))
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

// ─── Data Structures ─────────────────────────────────────────────────────────

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
    #[serde(default)]
    pub use_tclsag: bool,
    /// Second key image (K_y) for TCLSAG, if applicable (hex-encoded).
    #[serde(default)]
    pub key_image_y: Option<String>,
    /// Commitment key image D/8 (hex-encoded compressed point).
    /// D = z * H_p(P_l), D/8 = inv(8) * D.
    #[serde(default)]
    pub commitment_image: Option<String>,
    /// Fake responses for non-real ring positions (hex-encoded scalars, `ring_size` entries).
    /// The entry at `real_index` is ignored.
    #[serde(default)]
    pub fake_responses: Vec<String>,
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
    /// Public nonces on H_p: `alpha_i * H_p(pubkey)` (hex-encoded, 2 entries).
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
    /// The challenge scalar c_0 at ring position 0 (hex-encoded).
    pub c_0: String,
    /// TCLSAG: partial response scalar for the Y dimension (hex-encoded).
    #[serde(default)]
    pub sy_partial: Option<String>,
}

// ─── ClsagContext — Ring Traversal Engine ─────────────────────────────────────

/// CLSAG context for multisig ring traversal.
///
/// Mirrors the C++ `CLSAG_context_t` from `multisig_clsag_context.cpp`.
/// Pre-computes aggregation coefficients (mu_P, mu_C), weighted ring members,
/// and hash-to-point values, then performs the ring traversal to find the
/// challenge at the real index.
pub struct ClsagContext {
    ring: Vec<[u8; 32]>,
    commitments: Vec<[u8; 32]>,
    key_image: [u8; 32],
    commitment_image_d8: [u8; 32],
    d_full: [u8; 32],
    pseudo_output: [u8; 32],
    message: [u8; 32],
    real_index: usize,
    n: usize,
    mu_p: [u8; 32],
    mu_c: [u8; 32],
    c_diff: Vec<[u8; 32]>,
    hp: Vec<[u8; 32]>,
    fake_responses: Vec<[u8; 32]>,
}

impl ClsagContext {
    /// Initialize a CLSAG context with ring data and precomputed values.
    ///
    /// # Arguments
    /// * `ring` — ring member public keys (compressed points)
    /// * `commitments` — ring member commitments (compressed points)
    /// * `pseudo_output` — pseudo-output commitment C_offset
    /// * `message` — signing message (32 bytes)
    /// * `key_image` — combined key image I
    /// * `commitment_image_d8` — D/8 = inv(8) * z * H_p(P_l)
    /// * `real_index` — index of real input in ring
    /// * `fake_responses` — fake response scalars (n entries, entry at real_index is ignored)
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        ring: &[[u8; 32]],
        commitments: &[[u8; 32]],
        pseudo_output: &[u8; 32],
        message: &[u8; 32],
        key_image: &[u8; 32],
        commitment_image_d8: &[u8; 32],
        real_index: usize,
        fake_responses: &[[u8; 32]],
    ) -> Result<Self, String> {
        let n = ring.len();
        if n == 0 {
            return Err("ring is empty".to_string());
        }
        if n != commitments.len() {
            return Err(format!("ring size {} != commitments size {}", n, commitments.len()));
        }
        if real_index >= n {
            return Err(format!("real_index {} >= ring size {}", real_index, n));
        }
        if fake_responses.len() != n {
            return Err(format!("fake_responses size {} != ring size {}", fake_responses.len(), n));
        }

        // Compute D_full = 8 * D/8 (three doublings)
        let d_full = {
            let t = salvium_crypto::point_add_compressed(commitment_image_d8, commitment_image_d8);
            let t = to_arr32(&t);
            let t = salvium_crypto::point_add_compressed(&t, &t);
            let t = to_arr32(&t);
            let t = salvium_crypto::point_add_compressed(&t, &t);
            to_arr32(&t)
        };

        // Compute mu_P and mu_C (CLSAG aggregation coefficients)
        // mu_P = H("CLSAG_agg_0" || ring || commitments || I || D/8 || pseudo_output)
        let agg0 = pad_domain(b"CLSAG_agg_0");
        let agg1 = pad_domain(b"CLSAG_agg_1");
        let mut agg_data = Vec::with_capacity(32 + 32 * n * 2 + 32 * 3);
        agg_data.extend_from_slice(&agg0);
        for p in ring {
            agg_data.extend_from_slice(p);
        }
        for c in commitments {
            agg_data.extend_from_slice(c);
        }
        agg_data.extend_from_slice(key_image);
        agg_data.extend_from_slice(commitment_image_d8);
        agg_data.extend_from_slice(pseudo_output);
        let mu_p = hash_to_scalar_bytes(&agg_data);

        // mu_C = H("CLSAG_agg_1" || ... same data ...)
        agg_data[..32].copy_from_slice(&agg1);
        let mu_c = hash_to_scalar_bytes(&agg_data);

        // Precompute commitment differences: C_diff[i] = C[i] - pseudo_output
        let c_diff: Vec<[u8; 32]> = commitments
            .iter()
            .map(|c| to_arr32(&salvium_crypto::point_sub_compressed(c, pseudo_output)))
            .collect();

        // Precompute H_p(P[i]) for each ring member
        let hp: Vec<[u8; 32]> =
            ring.iter().map(|p| to_arr32(&salvium_crypto::hash_to_point(p))).collect();

        Ok(ClsagContext {
            ring: ring.to_vec(),
            commitments: commitments.to_vec(),
            key_image: *key_image,
            commitment_image_d8: *commitment_image_d8,
            d_full,
            pseudo_output: *pseudo_output,
            message: *message,
            real_index,
            n,
            mu_p,
            mu_c,
            c_diff,
            hp,
            fake_responses: fake_responses.to_vec(),
        })
    }

    /// Combine all signers' nonces and compute the challenge via ring traversal.
    ///
    /// # Arguments
    /// * `total_alpha_g` — aggregate public nonces on G: `sum_i(alpha_k_i * G)` for k=0,1
    /// * `total_alpha_hp` — aggregate public nonces on H_p: `sum_i(alpha_k_i * H_p(P_l))` for k=0,1
    /// * `my_alpha` — this signer's secret nonces `[alpha_0, alpha_1]`
    /// * `total_alpha_g_y` — (TCLSAG) aggregate Y-nonces on G, if present
    /// * `total_alpha_hp_y` — (TCLSAG) aggregate Y-nonces on H_p(K_y), if present
    ///
    /// # Returns
    /// `(alpha_combined, c_0, c_at_real_index, b)` where:
    /// * `alpha_combined` — this signer's combined secret nonce
    /// * `c_0` — challenge at ring position 0 (used as `c1` in ClsagSignature)
    /// * `c_at_real_index` — challenge at the real position (used for partial signing)
    /// * `b` — the MuSig2 binding factor (reusable for Y-dimension combination)
    #[allow(clippy::type_complexity)]
    pub fn combine_alpha_and_compute_challenge(
        &self,
        total_alpha_g: &[[u8; 32]; 2],
        total_alpha_hp: &[[u8; 32]; 2],
        my_alpha: &[[u8; 32]; 2],
        total_alpha_g_y: Option<&[[u8; 32]; 2]>,
        total_alpha_hp_y: Option<&[[u8; 32]; 2]>,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), String> {
        // 1. Compute MuSig2 binding factor b
        let mut b_data = Vec::new();
        b_data.extend_from_slice(b"CLSAG_round_ms_merge_factor");
        for p in &self.ring {
            b_data.extend_from_slice(p);
        }
        for c in &self.commitments {
            b_data.extend_from_slice(c);
        }
        b_data.extend_from_slice(&self.pseudo_output);
        b_data.extend_from_slice(&self.message);
        for k in 0..2 {
            b_data.extend_from_slice(&total_alpha_g[k]);
            b_data.extend_from_slice(&total_alpha_hp[k]);
        }
        // Include Y-dimension aggregate nonces in binding factor when present
        if let Some(y_g) = total_alpha_g_y {
            for item in y_g {
                b_data.extend_from_slice(item);
            }
        }
        if let Some(y_hp) = total_alpha_hp_y {
            for item in y_hp {
                b_data.extend_from_slice(item);
            }
        }
        b_data.extend_from_slice(&self.key_image);
        b_data.extend_from_slice(&self.commitment_image_d8);
        for (j, s) in self.fake_responses.iter().enumerate() {
            if j != self.real_index {
                b_data.extend_from_slice(s);
            }
        }
        b_data.extend_from_slice(&(self.real_index as u32).to_le_bytes());
        b_data.extend_from_slice(&2u32.to_le_bytes()); // num_alpha_components
        b_data.extend_from_slice(&(self.n as u32).to_le_bytes());

        let b = hash_to_scalar_bytes(&b_data);

        // 2. Combine aggregate nonces using binding factor
        // L_l = total_alpha_g[0] + b * total_alpha_g[1]
        let b_ag1 = to_arr32(&salvium_crypto::scalar_mult_point(&b, &total_alpha_g[1]));
        let l_l = to_arr32(&salvium_crypto::point_add_compressed(&total_alpha_g[0], &b_ag1));

        // R_l = total_alpha_hp[0] + b * total_alpha_hp[1]
        let b_ahp1 = to_arr32(&salvium_crypto::scalar_mult_point(&b, &total_alpha_hp[1]));
        let r_l = to_arr32(&salvium_crypto::point_add_compressed(&total_alpha_hp[0], &b_ahp1));

        // 3. Compute this signer's combined secret nonce
        // alpha_combined = my_alpha[0] + b * my_alpha[1]
        let b_alpha1 = to_arr32(&salvium_crypto::sc_mul(&b, &my_alpha[1]));
        let alpha_combined = to_arr32(&salvium_crypto::sc_add(&my_alpha[0], &b_alpha1));

        // 4. Compute initial challenge from nonce commitments at real index
        let mut c_current = self.hash_round(&l_l, &r_l);

        // 5. Ring traversal: go from (l+1)%n around to l
        let mut c_0 = [0u8; 32];
        let mut i = (self.real_index + 1) % self.n;

        if i == 0 {
            c_0 = c_current;
        }

        while i != self.real_index {
            let (l_i, r_i) = self.compute_lr(&self.fake_responses[i], &c_current, i);
            c_current = self.hash_round(&l_i, &r_i);

            i = (i + 1) % self.n;
            if i == 0 {
                c_0 = c_current;
            }
        }

        // c_current is now the challenge at the real index
        Ok((alpha_combined, c_0, c_current, b))
    }

    /// Compute the CLSAG round hash: H(round_domain || ring || commitments || pseudo || msg || L || R)
    fn hash_round(&self, l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        let round_domain = pad_domain(b"CLSAG_round");
        let mut data = Vec::with_capacity(32 + 32 * self.n * 2 + 32 * 4);
        data.extend_from_slice(&round_domain);
        for p in &self.ring {
            data.extend_from_slice(p);
        }
        for c in &self.commitments {
            data.extend_from_slice(c);
        }
        data.extend_from_slice(&self.pseudo_output);
        data.extend_from_slice(&self.message);
        data.extend_from_slice(l);
        data.extend_from_slice(r);
        hash_to_scalar_bytes(&data)
    }

    /// Compute L and R for a ring member at position i.
    ///
    /// L = s_i*G + c*(mu_P*P[i] + mu_C*(C[i] - pseudo))
    /// R = s_i*H_p(P[i]) + c*(mu_P*I + mu_C*D_full)
    fn compute_lr(&self, s_i: &[u8; 32], c: &[u8; 32], i: usize) -> ([u8; 32], [u8; 32]) {
        let c_mu_p = to_arr32(&salvium_crypto::sc_mul(c, &self.mu_p));
        let c_mu_c = to_arr32(&salvium_crypto::sc_mul(c, &self.mu_c));

        // L = s_i*G + c*mu_P*P[i] + c*mu_C*(C[i]-pseudo)
        let s_g = to_arr32(&salvium_crypto::scalar_mult_base(s_i));
        let cmp_p = to_arr32(&salvium_crypto::scalar_mult_point(&c_mu_p, &self.ring[i]));
        let cmc_cd = to_arr32(&salvium_crypto::scalar_mult_point(&c_mu_c, &self.c_diff[i]));
        let l = to_arr32(&salvium_crypto::point_add_compressed(&s_g, &cmp_p));
        let l = to_arr32(&salvium_crypto::point_add_compressed(&l, &cmc_cd));

        // R = s_i*H_p(P[i]) + c*mu_P*I + c*mu_C*D_full
        let s_hp = to_arr32(&salvium_crypto::scalar_mult_point(s_i, &self.hp[i]));
        let cmp_i = to_arr32(&salvium_crypto::scalar_mult_point(&c_mu_p, &self.key_image));
        let cmc_d = to_arr32(&salvium_crypto::scalar_mult_point(&c_mu_c, &self.d_full));
        let r = to_arr32(&salvium_crypto::point_add_compressed(&s_hp, &cmp_i));
        let r = to_arr32(&salvium_crypto::point_add_compressed(&r, &cmc_d));

        (l, r)
    }

    /// Get the mu_P aggregation coefficient.
    pub fn mu_p(&self) -> &[u8; 32] {
        &self.mu_p
    }

    /// Get the mu_C aggregation coefficient.
    pub fn mu_c(&self) -> &[u8; 32] {
        &self.mu_c
    }

    /// Get the fake responses.
    pub fn fake_responses(&self) -> &[[u8; 32]] {
        &self.fake_responses
    }
}

// ─── Nonce Generation ────────────────────────────────────────────────────────

/// Generate nonces for a single input.
///
/// `pubkey_hex` is the public key at the real ring position (P_l), used to
/// compute H_p(P_l) for the nonce commitments on the H_p basis.
pub fn generate_nonces(signer_index: usize, pubkey_hex: &str) -> Result<SignerNonces, String> {
    generate_nonces_ext(signer_index, pubkey_hex, None)
}

/// Extended nonce generation with optional TCLSAG Y key image.
pub fn generate_nonces_ext(
    signer_index: usize,
    pubkey_hex: &str,
    key_image_y_hex: Option<&str>,
) -> Result<SignerNonces, String> {
    let mut rng = rand::thread_rng();
    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|e| format!("invalid pubkey hex: {}", e))?;
    if pubkey_bytes.len() != 32 {
        return Err(format!("pubkey: expected 32 bytes, got {}", pubkey_bytes.len()));
    }
    let hp = salvium_crypto::hash_to_point(&pubkey_bytes);

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
            return Err(format!("key_image_y: expected 32 bytes, got {}", ki_y_bytes.len()));
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

// ─── Nonce Aggregation ───────────────────────────────────────────────────────

/// Aggregate all signers' public nonces into totals.
///
/// Returns `(total_alpha_G, total_alpha_Hp)` where each is `[sum_component_0, sum_component_1]`.
#[allow(clippy::type_complexity)]
pub fn aggregate_nonces(
    all_nonces: &[SignerNonces],
) -> Result<([[u8; 32]; 2], [[u8; 32]; 2]), String> {
    if all_nonces.len() < 2 {
        return Err(format!("need at least 2 signers' nonces, got {}", all_nonces.len()));
    }

    let mut total_g = [[0u8; 32]; 2];
    let mut total_hp = [[0u8; 32]; 2];

    for (idx, nonces) in all_nonces.iter().enumerate() {
        if nonces.pub_nonces_g.len() != 2 || nonces.pub_nonces_hp.len() != 2 {
            return Err(format!("signer {} nonces must have exactly 2 components", idx));
        }
        for k in 0..2 {
            let g = hex_to_32(&nonces.pub_nonces_g[k], "pub_nonce_g")?;
            let hp = hex_to_32(&nonces.pub_nonces_hp[k], "pub_nonce_hp")?;

            if idx == 0 {
                total_g[k] = g;
                total_hp[k] = hp;
            } else {
                total_g[k] = to_arr32(&salvium_crypto::point_add_compressed(&total_g[k], &g));
                total_hp[k] = to_arr32(&salvium_crypto::point_add_compressed(&total_hp[k], &hp));
            }
        }
    }

    Ok((total_g, total_hp))
}

/// Compute the nonce combination factor `b` from all signers' public nonces (legacy).
///
/// b = H("CLSAG_round_nonce" || ring || commitment || message || sum_alpha_G || sum_alpha_H)
///
/// Note: `partial_sign()` now uses `ClsagContext` for binding factor computation.
/// This function is kept for backward compatibility.
#[deprecated(
    note = "uses wrong domain tag; use ClsagContext::combine_alpha_and_compute_challenge instead"
)]
pub fn compute_nonce_binding(
    ctx: &MultisigClsagContext,
    all_nonces: &[SignerNonces],
) -> Result<Vec<u8>, String> {
    let (total_g, total_hp) = aggregate_nonces(all_nonces)?;

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
    for k in 0..2 {
        data.extend_from_slice(&total_g[k]);
        data.extend_from_slice(&total_hp[k]);
    }

    Ok(salvium_crypto::keccak256(&data))
}

/// Aggregate all signers' Y-dimension public nonces into totals (TCLSAG).
///
/// Returns `(total_alpha_G_y, total_alpha_Hp_y)` where each is `[sum_component_0, sum_component_1]`.
/// Returns `None` if no signers have Y nonces.
#[allow(clippy::type_complexity)]
pub fn aggregate_nonces_y(
    all_nonces: &[SignerNonces],
) -> Result<Option<([[u8; 32]; 2], [[u8; 32]; 2])>, String> {
    let has_y = all_nonces.iter().any(|n| n.pub_nonces_g_y.len() >= 2);
    if !has_y {
        return Ok(None);
    }

    let mut total_g_y = [[0u8; 32]; 2];
    let mut total_hp_y = [[0u8; 32]; 2];
    let mut first = true;

    for (idx, nonces) in all_nonces.iter().enumerate() {
        if nonces.pub_nonces_g_y.len() < 2 || nonces.pub_nonces_hp_y.len() < 2 {
            return Err(format!(
                "signer {} has Y nonce mismatch (g_y={}, hp_y={})",
                idx,
                nonces.pub_nonces_g_y.len(),
                nonces.pub_nonces_hp_y.len()
            ));
        }
        for k in 0..2 {
            let g_y = hex_to_32(&nonces.pub_nonces_g_y[k], "pub_nonce_g_y")?;
            let hp_y = hex_to_32(&nonces.pub_nonces_hp_y[k], "pub_nonce_hp_y")?;

            if first {
                total_g_y[k] = g_y;
                total_hp_y[k] = hp_y;
            } else {
                total_g_y[k] = to_arr32(&salvium_crypto::point_add_compressed(&total_g_y[k], &g_y));
                total_hp_y[k] =
                    to_arr32(&salvium_crypto::point_add_compressed(&total_hp_y[k], &hp_y));
            }
        }
        first = false;
    }

    Ok(Some((total_g_y, total_hp_y)))
}

// ─── Partial Signing ─────────────────────────────────────────────────────────

/// Produce a partial CLSAG signature for one input using proper ring traversal.
///
/// Each signer computes:
///   1. Aggregate all public nonces, compute MuSig2 binding factor
///   2. Ring traversal → challenge `c` at real index, `c_0` at ring position 0
///   3. Weighted key: `w = mu_P * privkey_share + mu_C * commitment_mask_share`
///   4. Partial response: `s_partial = alpha_combined - c * w`
///
/// # Arguments
/// * `ctx` — signing context with ring, commitments, key image, commitment image, fake responses
/// * `nonces` — this signer's nonces (must have `secret_nonces`)
/// * `privkey_share_hex` — this signer's private key share (hex)
/// * `commitment_mask_share_hex` — this signer's commitment mask share z_i (hex)
/// * `all_nonces` — all signers' public nonces
pub fn partial_sign(
    ctx: &MultisigClsagContext,
    nonces: &SignerNonces,
    privkey_share_hex: &str,
    commitment_mask_share_hex: &str,
    all_nonces: &[SignerNonces],
) -> Result<PartialClsag, String> {
    // Input validation
    if ctx.ring.is_empty() {
        return Err("ring is empty".to_string());
    }
    if ctx.real_index >= ctx.ring.len() {
        return Err(format!("real_index {} >= ring size {}", ctx.real_index, ctx.ring.len()));
    }
    if all_nonces.len() < 2 {
        return Err(format!("need at least 2 signers' nonces, got {}", all_nonces.len()));
    }

    let commitment_image_hex =
        ctx.commitment_image.as_deref().ok_or("commitment_image is required for CLSAG signing")?;

    if ctx.fake_responses.len() != ctx.ring.len() {
        return Err(format!(
            "fake_responses size {} != ring size {}",
            ctx.fake_responses.len(),
            ctx.ring.len()
        ));
    }

    // Decode all hex fields
    let ring: Vec<[u8; 32]> =
        ctx.ring.iter().map(|s| hex_to_32(s, "ring member")).collect::<Result<_, _>>()?;
    let commitments: Vec<[u8; 32]> =
        ctx.commitments.iter().map(|s| hex_to_32(s, "commitment")).collect::<Result<_, _>>()?;
    let key_image = hex_to_32(&ctx.key_image, "key_image")?;
    let pseudo_output = hex_to_32(&ctx.pseudo_output_commitment, "pseudo_output")?;
    let message = hex_to_32(&ctx.message, "message")?;
    let commitment_image_d8 = hex_to_32(commitment_image_hex, "commitment_image")?;
    let fake_responses: Vec<[u8; 32]> = ctx
        .fake_responses
        .iter()
        .map(|s| hex_to_32(s, "fake_response"))
        .collect::<Result<_, _>>()?;

    // Create ClsagContext and perform ring traversal
    let clsag_ctx = ClsagContext::init(
        &ring,
        &commitments,
        &pseudo_output,
        &message,
        &key_image,
        &commitment_image_d8,
        ctx.real_index,
        &fake_responses,
    )?;

    // Aggregate all signers' public nonces
    let (total_alpha_g, total_alpha_hp) = aggregate_nonces(all_nonces)?;

    // Compute combined alpha and challenge via ring traversal
    let my_alpha = [nonces.secret_nonces[0], nonces.secret_nonces[1]];
    let (alpha_combined, c_0, c, _b) = clsag_ctx.combine_alpha_and_compute_challenge(
        &total_alpha_g,
        &total_alpha_hp,
        &my_alpha,
        None,
        None,
    )?;

    // Compute weighted signing key: w = mu_P * privkey_share + mu_C * z_share
    let privkey = hex_to_32(privkey_share_hex, "privkey_share")?;
    let z_share = hex_to_32(commitment_mask_share_hex, "commitment_mask_share")?;
    let mu_p_priv = to_arr32(&salvium_crypto::sc_mul(&clsag_ctx.mu_p, &privkey));
    let mu_c_z = to_arr32(&salvium_crypto::sc_mul(&clsag_ctx.mu_c, &z_share));
    let w = to_arr32(&salvium_crypto::sc_add(&mu_p_priv, &mu_c_z));

    // s_partial = alpha_combined - c * w
    // sc_mul_sub(c, w, alpha_combined) = alpha_combined - c*w
    let s_partial = to_arr32(&salvium_crypto::sc_mul_sub(&c, &w, &alpha_combined));

    Ok(PartialClsag {
        signer_index: nonces.signer_index,
        s_partial: hex::encode(s_partial),
        c_0: hex::encode(c_0),
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
    commitment_mask_share_hex: &str,
    all_nonces: &[SignerNonces],
) -> Result<PartialClsag, String> {
    // Input validation
    if ctx.ring.is_empty() {
        return Err("ring is empty".to_string());
    }
    if ctx.real_index >= ctx.ring.len() {
        return Err(format!("real_index {} >= ring size {}", ctx.real_index, ctx.ring.len()));
    }
    if all_nonces.len() < 2 {
        return Err(format!("need at least 2 signers' nonces, got {}", all_nonces.len()));
    }

    let commitment_image_hex =
        ctx.commitment_image.as_deref().ok_or("commitment_image is required for TCLSAG signing")?;

    if ctx.fake_responses.len() != ctx.ring.len() {
        return Err(format!(
            "fake_responses size {} != ring size {}",
            ctx.fake_responses.len(),
            ctx.ring.len()
        ));
    }

    // Decode all hex fields
    let ring: Vec<[u8; 32]> =
        ctx.ring.iter().map(|s| hex_to_32(s, "ring member")).collect::<Result<_, _>>()?;
    let commitments: Vec<[u8; 32]> =
        ctx.commitments.iter().map(|s| hex_to_32(s, "commitment")).collect::<Result<_, _>>()?;
    let key_image = hex_to_32(&ctx.key_image, "key_image")?;
    let pseudo_output = hex_to_32(&ctx.pseudo_output_commitment, "pseudo_output")?;
    let message = hex_to_32(&ctx.message, "message")?;
    let commitment_image_d8 = hex_to_32(commitment_image_hex, "commitment_image")?;
    let fake_responses: Vec<[u8; 32]> = ctx
        .fake_responses
        .iter()
        .map(|s| hex_to_32(s, "fake_response"))
        .collect::<Result<_, _>>()?;

    // Create ClsagContext
    let clsag_ctx = ClsagContext::init(
        &ring,
        &commitments,
        &pseudo_output,
        &message,
        &key_image,
        &commitment_image_d8,
        ctx.real_index,
        &fake_responses,
    )?;

    // Aggregate all signers' public nonces (X and Y dimensions)
    let (total_alpha_g, total_alpha_hp) = aggregate_nonces(all_nonces)?;
    let y_agg = aggregate_nonces_y(all_nonces)?;
    let (y_g_ref, y_hp_ref) = match y_agg {
        Some((ref g, ref hp)) => (Some(g), Some(hp)),
        None => (None, None),
    };

    // Compute combined alpha, challenge, and binding factor via ring traversal
    // Y-nonces are included in the binding factor data
    let my_alpha = [nonces.secret_nonces[0], nonces.secret_nonces[1]];
    let (alpha_combined, c_0, c, b) = clsag_ctx.combine_alpha_and_compute_challenge(
        &total_alpha_g,
        &total_alpha_hp,
        &my_alpha,
        y_g_ref,
        y_hp_ref,
    )?;

    // Compute weighted signing key: w = mu_P * privkey_share + mu_C * z_share
    let privkey = hex_to_32(privkey_share_hex, "privkey_share")?;
    let z_share = hex_to_32(commitment_mask_share_hex, "commitment_mask_share")?;
    let mu_p_priv = to_arr32(&salvium_crypto::sc_mul(&clsag_ctx.mu_p, &privkey));
    let mu_c_z = to_arr32(&salvium_crypto::sc_mul(&clsag_ctx.mu_c, &z_share));
    let w = to_arr32(&salvium_crypto::sc_add(&mu_p_priv, &mu_c_z));

    // s_partial = alpha_combined - c * w
    let s_partial = to_arr32(&salvium_crypto::sc_mul_sub(&c, &w, &alpha_combined));

    // TCLSAG Y-dimension: compute sy_partial using the same binding factor b
    let sy_partial = if nonces.secret_nonces_y.len() >= 2 {
        // combined_alpha_y = alpha_y[0] + b * alpha_y[1]
        let b_ay1 = to_arr32(&salvium_crypto::sc_mul(&b, &nonces.secret_nonces_y[1]));
        let combined_alpha_y =
            to_arr32(&salvium_crypto::sc_add(&nonces.secret_nonces_y[0], &b_ay1));

        // sy_partial = combined_alpha_y - c * mu_P * privkey_y_share
        let privkey_y = hex_to_32(privkey_y_share_hex, "privkey_y_share")?;
        let mu_p_y = to_arr32(&salvium_crypto::sc_mul(clsag_ctx.mu_p(), &privkey_y));
        let sy = to_arr32(&salvium_crypto::sc_mul_sub(&c, &mu_p_y, &combined_alpha_y));
        Some(hex::encode(sy))
    } else {
        None
    };

    Ok(PartialClsag {
        signer_index: nonces.signer_index,
        s_partial: hex::encode(s_partial),
        c_0: hex::encode(c_0),
        sy_partial,
    })
}

// ─── Signature Combination ──────────────────────────────────────────────────

/// Add two scalars: a + b (mod l).
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    to_arr32(&salvium_crypto::sc_add(a, b))
}

/// Combined CLSAG result with optional TCLSAG `sy` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedClsag {
    /// Combined `s` response scalar (hex-encoded).
    pub s: String,
    /// Challenge `c_0` at ring position 0 (hex-encoded).
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
        sy: if has_sy { Some(hex::encode(sy_sum)) } else { None },
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a random valid scalar. Returns (hex, bytes).
    fn random_scalar() -> (String, [u8; 32]) {
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let reduced = salvium_crypto::sc_reduce32(&buf);
        let mut s = [0u8; 32];
        s.copy_from_slice(&reduced[..32]);
        (hex::encode(s), s)
    }

    /// Generate a valid public key from a scalar.
    fn scalar_to_point(s: &[u8; 32]) -> [u8; 32] {
        to_arr32(&salvium_crypto::scalar_mult_base(s))
    }

    /// Create a test signing context with valid EC points and commitment image.
    fn make_test_context(ring_size: usize) -> (MultisigClsagContext, [u8; 32], [u8; 32]) {
        // Real key
        let (_, sk) = random_scalar();
        let pk = scalar_to_point(&sk);

        // Decoy ring members
        let mut ring = Vec::with_capacity(ring_size);
        let mut commitments = Vec::with_capacity(ring_size);
        let real_index = 0;

        for i in 0..ring_size {
            if i == real_index {
                ring.push(hex::encode(pk));
            } else {
                let (_, dk) = random_scalar();
                ring.push(hex::encode(scalar_to_point(&dk)));
            }
            let (_, ck) = random_scalar();
            commitments.push(hex::encode(scalar_to_point(&ck)));
        }

        // Commitment mask
        let (_, z) = random_scalar();
        let pseudo_output = scalar_to_point(&{
            let (_, pm) = random_scalar();
            pm
        });

        // Key image I = sk * H_p(pk)
        let hp_pk = to_arr32(&salvium_crypto::hash_to_point(&pk));
        let key_image = to_arr32(&salvium_crypto::scalar_mult_point(&sk, &hp_pk));

        // Commitment image D = z * H_p(pk), D/8 = inv(8) * D
        let d_full = to_arr32(&salvium_crypto::scalar_mult_point(&z, &hp_pk));
        let inv8 = to_arr32(&salvium_crypto::inv_eight_scalar());
        let d8 = to_arr32(&salvium_crypto::scalar_mult_point(&inv8, &d_full));

        // Fake responses
        let mut fake_responses = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            if i == real_index {
                fake_responses.push("00".repeat(32));
            } else {
                let (hex, _) = random_scalar();
                fake_responses.push(hex);
            }
        }

        let (_, message) = random_scalar();

        let ctx = MultisigClsagContext {
            ring,
            commitments,
            key_image: hex::encode(key_image),
            pseudo_output_commitment: hex::encode(pseudo_output),
            message: hex::encode(message),
            real_index,
            use_tclsag: false,
            key_image_y: None,
            commitment_image: Some(hex::encode(d8)),
            fake_responses,
        };

        (ctx, sk, z)
    }

    #[test]
    fn test_generate_nonces() {
        // Use a valid point as the public key.
        let (_, sk) = random_scalar();
        let pk = hex::encode(scalar_to_point(&sk));
        let nonces = generate_nonces(0, &pk).unwrap();
        assert_eq!(nonces.signer_index, 0);
        assert_eq!(nonces.secret_nonces.len(), 2);
        assert_eq!(nonces.pub_nonces_g.len(), 2);
        assert_eq!(nonces.pub_nonces_hp.len(), 2);
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
    fn test_clsag_context_init() {
        let (ctx, _, _) = make_test_context(4);
        let ring: Vec<[u8; 32]> = ctx.ring.iter().map(|s| hex_to_32(s, "r").unwrap()).collect();
        let comms: Vec<[u8; 32]> =
            ctx.commitments.iter().map(|s| hex_to_32(s, "c").unwrap()).collect();
        let ki = hex_to_32(&ctx.key_image, "ki").unwrap();
        let po = hex_to_32(&ctx.pseudo_output_commitment, "po").unwrap();
        let msg = hex_to_32(&ctx.message, "msg").unwrap();
        let d8 = hex_to_32(ctx.commitment_image.as_deref().unwrap(), "d8").unwrap();
        let fakes: Vec<[u8; 32]> =
            ctx.fake_responses.iter().map(|s| hex_to_32(s, "f").unwrap()).collect();

        let clsag_ctx = ClsagContext::init(&ring, &comms, &po, &msg, &ki, &d8, 0, &fakes).unwrap();
        assert_eq!(clsag_ctx.n, 4);
        // mu_P and mu_C should be non-zero
        assert_ne!(clsag_ctx.mu_p, [0u8; 32]);
        assert_ne!(clsag_ctx.mu_c, [0u8; 32]);
    }

    #[test]
    fn test_partial_sign_produces_valid_output() {
        let (ctx, sk, z) = make_test_context(4);
        let pk_hex = &ctx.ring[ctx.real_index].clone();

        // Split key into two shares
        let (_, sk_share_0) = random_scalar();
        let _sk_share_1 = to_arr32(&salvium_crypto::sc_sub(&sk, &sk_share_0));

        // Split commitment mask
        let (_, z_share_0) = random_scalar();
        let _z_share_1 = to_arr32(&salvium_crypto::sc_sub(&z, &z_share_0));

        let nonces0 = generate_nonces(0, pk_hex).unwrap();
        let nonces1 = generate_nonces(1, pk_hex).unwrap();
        let all_nonces = [nonces0.clone(), nonces1.clone()];

        let partial = partial_sign(
            &ctx,
            &nonces0,
            &hex::encode(sk_share_0),
            &hex::encode(z_share_0),
            &all_nonces,
        )
        .unwrap();
        assert_eq!(partial.signer_index, 0);
        assert_eq!(partial.s_partial.len(), 64);
        assert_eq!(partial.c_0.len(), 64);
    }

    #[test]
    fn test_partial_sign_rejects_empty_ring() {
        let (_, sk) = random_scalar();
        let pk = scalar_to_point(&sk);
        let pk_hex = hex::encode(pk);

        let ctx = MultisigClsagContext {
            ring: vec![],
            commitments: vec![],
            key_image: pk_hex.clone(),
            pseudo_output_commitment: pk_hex.clone(),
            message: "ff".repeat(32),
            real_index: 0,
            use_tclsag: false,
            key_image_y: None,
            commitment_image: Some(pk_hex.clone()),
            fake_responses: vec![],
        };
        let nonces0 = generate_nonces(0, &pk_hex).unwrap();
        let nonces1 = generate_nonces(1, &pk_hex).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            &"22".repeat(32),
            &[nonces0.clone(), nonces1],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_sign_rejects_bad_real_index() {
        let (_, sk) = random_scalar();
        let pk = scalar_to_point(&sk);
        let pk_hex = hex::encode(pk);

        let ctx = MultisigClsagContext {
            ring: vec![pk_hex.clone()],
            commitments: vec![pk_hex.clone()],
            key_image: pk_hex.clone(),
            pseudo_output_commitment: pk_hex.clone(),
            message: "ff".repeat(32),
            real_index: 5,
            use_tclsag: false,
            key_image_y: None,
            commitment_image: Some(pk_hex.clone()),
            fake_responses: vec!["00".repeat(32)],
        };
        let nonces0 = generate_nonces(0, &pk_hex).unwrap();
        let nonces1 = generate_nonces(1, &pk_hex).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            &"22".repeat(32),
            &[nonces0.clone(), nonces1],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("real_index"));
    }

    #[test]
    fn test_partial_sign_rejects_single_nonce() {
        let (ctx, _, _) = make_test_context(2);
        let pk_hex = &ctx.ring[0].clone();
        let nonces0 = generate_nonces(0, pk_hex).unwrap();
        let result = partial_sign(
            &ctx,
            &nonces0,
            &"11".repeat(32),
            &"22".repeat(32),
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
        assert_eq!(c, "aa".repeat(32));
    }

    #[test]
    fn test_aggregate_nonces() {
        let (_, sk) = random_scalar();
        let pk_hex = hex::encode(scalar_to_point(&sk));
        let nonces0 = generate_nonces(0, &pk_hex).unwrap();
        let nonces1 = generate_nonces(1, &pk_hex).unwrap();
        let (total_g, total_hp) = aggregate_nonces(&[nonces0, nonces1]).unwrap();
        // Both components should be non-zero
        assert_ne!(total_g[0], [0u8; 32]);
        assert_ne!(total_g[1], [0u8; 32]);
        assert_ne!(total_hp[0], [0u8; 32]);
        assert_ne!(total_hp[1], [0u8; 32]);
    }
}
