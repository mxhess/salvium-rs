//! Bulletproofs+ range proofs.
//!
//! Implements prove and verify matching the JS in bulletproofs_plus.js
//! and Salvium C++ bulletproofs_plus.cc.
//!
//! Reference: https://eprint.iacr.org/2020/735.pdf

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use wasm_bindgen::prelude::*;

use crate::{keccak256_internal, to32, H_POINT_BYTES};
use crate::clsag::{hash_to_point as clsag_hash_to_point, random_scalar};

// ─── Constants ──────────────────────────────────────────────────────────────

const N: usize = 64;    // Bit-length of range proof
const LOG_N: usize = 6;
const MAX_M: usize = 16; // Max aggregation

/// 8^(-1) mod L
fn inv_eight() -> Scalar {
    Scalar::from(8u64).invert()
}

fn h_point() -> EdwardsPoint {
    CompressedEdwardsY(H_POINT_BYTES).decompress().expect("invalid H")
}

// ─── Generator computation ──────────────────────────────────────────────────

/// Hash to point matching C++ get_exponent / hash_to_p3 exactly.
///
/// C++ flow:
///   1. cn_fast_hash(data) -> hash1
///   2. hash_to_p3(hash1) internally does:
///      a. cn_fast_hash(hash1) -> hash2 (DOUBLE HASH!)
///      b. ge_fromfe_frombytes_vartime(hash2) -> elligator2
///      c. ge_mul8 -> cofactor clear
///
/// Our hash_to_point does: keccak256(input) -> elligator2 -> *8
/// So we pre-hash: hash_to_point(keccak256(data))
fn hash_to_point_monero(data: &[u8]) -> EdwardsPoint {
    let hash1 = keccak256_internal(data);
    // clsag_hash_to_point does keccak256 internally then elligator2 + *8
    clsag_hash_to_point(&hash1)
}

fn encode_varint(mut val: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
    bytes
}

struct Generators {
    gi: Vec<EdwardsPoint>,
    hi: Vec<EdwardsPoint>,
}

fn compute_generators(max_mn: usize) -> Generators {
    let prefix = b"bulletproof_plus";

    let mut gi = Vec::with_capacity(max_mn);
    let mut hi = Vec::with_capacity(max_mn);

    for i in 0..max_mn {
        // Hi uses even indices (2*i)
        let hi_varint = encode_varint(2 * i as u32);
        let mut hi_data = Vec::with_capacity(32 + prefix.len() + hi_varint.len());
        hi_data.extend_from_slice(&H_POINT_BYTES);
        hi_data.extend_from_slice(prefix);
        hi_data.extend_from_slice(&hi_varint);
        hi.push(hash_to_point_monero(&hi_data));

        // Gi uses odd indices (2*i + 1)
        let gi_varint = encode_varint(2 * i as u32 + 1);
        let mut gi_data = Vec::with_capacity(32 + prefix.len() + gi_varint.len());
        gi_data.extend_from_slice(&H_POINT_BYTES);
        gi_data.extend_from_slice(prefix);
        gi_data.extend_from_slice(&gi_varint);
        gi.push(hash_to_point_monero(&gi_data));
    }

    Generators { gi, hi }
}

fn compute_transcript_init() -> [u8; 32] {
    let domain = b"bulletproof_plus_transcript";
    let hash1 = keccak256_internal(domain);
    // hash_to_point does keccak256(hash1) -> elligator2 -> *8
    let p = crate::elligator2::ge_fromfe_frombytes_vartime(&keccak256_internal(&hash1));
    let p8 = { let t = p + p; let t = t + t; t + t };
    p8.compress().to_bytes()
}

// ─── Transcript helpers ─────────────────────────────────────────────────────

fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// hash_to_scalar(transcript || element) -> reduced scalar bytes
fn transcript_update(transcript: &[u8; 32], element: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(transcript);
    data[32..].copy_from_slice(element);
    let hash = keccak256_internal(&data);
    Scalar::from_bytes_mod_order(hash).to_bytes()
}

/// hash_to_scalar(transcript || element1 || element2) -> reduced scalar bytes
fn transcript_update2(transcript: &[u8; 32], e1: &[u8; 32], e2: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(transcript);
    data[32..64].copy_from_slice(e1);
    data[64..].copy_from_slice(e2);
    let hash = keccak256_internal(&data);
    Scalar::from_bytes_mod_order(hash).to_bytes()
}

/// Hash keys (points) to scalar: concat all 32-byte representations and keccak256
fn hash_keys_to_scalar(keys: &[EdwardsPoint]) -> Scalar {
    let mut data = Vec::with_capacity(keys.len() * 32);
    for k in keys {
        data.extend_from_slice(&k.compress().to_bytes());
    }
    let hash = keccak256_internal(&data);
    Scalar::from_bytes_mod_order(hash)
}

// ─── Proof structure ────────────────────────────────────────────────────────

pub struct BulletproofPlusProof {
    pub v: Vec<EdwardsPoint>,        // Commitments (not serialized in wire format)
    pub capital_a: EdwardsPoint,     // A
    pub capital_a1: EdwardsPoint,    // A1
    pub capital_b: EdwardsPoint,     // B
    pub r1: Scalar,
    pub s1: Scalar,
    pub d1: Scalar,
    pub l_vec: Vec<EdwardsPoint>,    // L points
    pub r_vec: Vec<EdwardsPoint>,    // R points
}

// ─── Prove ──────────────────────────────────────────────────────────────────

pub fn bulletproof_plus_prove(
    amounts: &[u64],
    masks: &[Scalar],
) -> BulletproofPlusProof {
    assert!(!amounts.is_empty() && amounts.len() == masks.len());
    assert!(amounts.len() <= MAX_M);

    // Compute M (smallest power of 2 >= amounts.len())
    let mut m_val = 1usize;
    let mut log_m = 0usize;
    while m_val < amounts.len() {
        m_val *= 2;
        log_m += 1;
    }
    let mn = m_val * N;
    let log_mn = log_m + LOG_N;

    let inv8 = inv_eight();
    let g_pt = ED25519_BASEPOINT_POINT;
    let h_pt = h_point();

    let gens = compute_generators(mn);
    let gi = &gens.gi[..mn];
    let hi = &gens.hi[..mn];

    let mut transcript = compute_transcript_init();

    // Step 1: Create output commitments V
    let mut v_points = Vec::with_capacity(amounts.len());
    for j in 0..amounts.len() {
        let mask_scaled = masks[j] * inv8;
        let amount_scalar = Scalar::from(amounts[j]) * inv8;
        let commitment = EdwardsPoint::vartime_multiscalar_mul(
            &[mask_scaled, amount_scalar],
            &[g_pt, h_pt],
        );
        v_points.push(commitment);
    }

    // Update transcript with hash of V
    let hash_v = hash_keys_to_scalar(&v_points);
    transcript = transcript_update(&transcript, &hash_v.to_bytes());

    // Step 2: Decompose amounts to bits
    let mut a_l = vec![Scalar::ZERO; mn];
    let mut a_r = vec![Scalar::ZERO; mn];
    let minus_one = -Scalar::ONE;

    for j in 0..amounts.len() {
        let amount = amounts[j];
        for i in 0..N {
            if (amount >> i) & 1 == 1 {
                a_l[j * N + i] = Scalar::ONE;
                a_r[j * N + i] = Scalar::ZERO;
            } else {
                a_l[j * N + i] = Scalar::ZERO;
                a_r[j * N + i] = minus_one;
            }
        }
    }
    // Padding
    for i in amounts.len() * N..mn {
        a_l[i] = Scalar::ZERO;
        a_r[i] = minus_one;
    }

    // Step 3: Initial commitment A
    let alpha = random_scalar();

    // A = sum(aL8[i] * Gi[i] + aR8[i] * Hi[i]) + alpha*inv8 * G
    let mut a_scalars = Vec::with_capacity(2 * mn + 1);
    let mut a_points = Vec::with_capacity(2 * mn + 1);
    for i in 0..mn {
        a_scalars.push(a_l[i] * inv8);
        a_points.push(gi[i]);
        a_scalars.push(a_r[i] * inv8);
        a_points.push(hi[i]);
    }
    a_scalars.push(alpha * inv8);
    a_points.push(g_pt);
    let capital_a = EdwardsPoint::vartime_multiscalar_mul(&a_scalars, &a_points);

    // Step 4: Challenge y
    transcript = transcript_update(&transcript, &capital_a.compress().to_bytes());
    let y = bytes_to_scalar(&transcript);
    assert!(y != Scalar::ZERO);

    // Challenge z = hash(y_bytes)
    let y_bytes = y.to_bytes();
    let z = bytes_to_scalar(&to32(&keccak256_internal(&y_bytes)));
    assert!(z != Scalar::ZERO);
    transcript = z.to_bytes();

    let z2 = z * z;

    // Step 5: Compute windowed vector d
    let mut d = vec![Scalar::ZERO; mn];
    let mut z_pow = z2;
    for j in 0..m_val {
        let mut two_pow = Scalar::ONE;
        for i in 0..N {
            d[j * N + i] = z_pow * two_pow;
            two_pow = two_pow + two_pow; // *= 2
        }
        z_pow = z_pow * z2;
    }

    // Step 6: Compute y powers
    let mut y_powers = Vec::with_capacity(mn + 2);
    y_powers.push(Scalar::ONE); // y^0
    let mut y_pow = y;
    for _ in 1..=mn + 1 {
        y_powers.push(y_pow);
        y_pow = y_pow * y;
    }

    let y_inv = y.invert();
    let mut y_inv_powers = Vec::with_capacity(mn);
    y_inv_powers.push(Scalar::ONE);
    let mut yi = y_inv;
    for _ in 1..mn {
        y_inv_powers.push(yi);
        yi = yi * y_inv;
    }

    // Step 7: Prepare inner product inputs
    let mut a_l1 = vec![Scalar::ZERO; mn];
    let mut a_r1 = vec![Scalar::ZERO; mn];
    for i in 0..mn {
        a_l1[i] = a_l[i] - z;
        a_r1[i] = a_r[i] + z + d[i] * y_powers[mn - i];
    }

    // Update alpha with gamma terms
    let mut alpha1 = alpha;
    let mut temp = Scalar::ONE;
    for j in 0..amounts.len() {
        temp = temp * z2;
        alpha1 = alpha1 + temp * y_powers[mn + 1] * masks[j];
    }

    // Step 8: Inner product argument
    let mut nprime = mn;
    let mut gprime: Vec<EdwardsPoint> = gi.to_vec();
    let mut hprime: Vec<EdwardsPoint> = hi.to_vec();
    let mut aprime = a_l1;
    let mut bprime = a_r1;

    let mut l_points = Vec::with_capacity(log_mn);
    let mut r_points = Vec::with_capacity(log_mn);

    while nprime > 1 {
        nprime /= 2;

        // Compute cL and cR
        let mut c_l = Scalar::ZERO;
        let mut c_r = Scalar::ZERO;
        let mut y_pow_local = y;
        for i in 0..nprime {
            c_l = c_l + aprime[i] * bprime[nprime + i] * y_pow_local;
            c_r = c_r + aprime[nprime + i] * y_powers[nprime] * bprime[i] * y_pow_local;
            y_pow_local = y_pow_local * y;
        }

        let d_l = random_scalar();
        let d_r = random_scalar();

        // Compute L
        let mut l_scalars = Vec::with_capacity(2 * nprime + 2);
        let mut l_pts = Vec::with_capacity(2 * nprime + 2);
        for i in 0..nprime {
            l_scalars.push(aprime[i] * y_inv_powers[nprime] * inv8);
            l_pts.push(gprime[nprime + i]);
            l_scalars.push(bprime[nprime + i] * inv8);
            l_pts.push(hprime[i]);
        }
        l_scalars.push(c_l * inv8);
        l_pts.push(h_pt);
        l_scalars.push(d_l * inv8);
        l_pts.push(g_pt);
        let l_point = EdwardsPoint::vartime_multiscalar_mul(&l_scalars, &l_pts);
        l_points.push(l_point);

        // Compute R
        let mut r_scalars = Vec::with_capacity(2 * nprime + 2);
        let mut r_pts = Vec::with_capacity(2 * nprime + 2);
        for i in 0..nprime {
            r_scalars.push(aprime[nprime + i] * y_powers[nprime] * inv8);
            r_pts.push(gprime[i]);
            r_scalars.push(bprime[i] * inv8);
            r_pts.push(hprime[nprime + i]);
        }
        r_scalars.push(c_r * inv8);
        r_pts.push(h_pt);
        r_scalars.push(d_r * inv8);
        r_pts.push(g_pt);
        let r_point = EdwardsPoint::vartime_multiscalar_mul(&r_scalars, &r_pts);
        r_points.push(r_point);

        // Challenge x
        transcript = transcript_update2(
            &transcript,
            &l_point.compress().to_bytes(),
            &r_point.compress().to_bytes(),
        );
        let x = bytes_to_scalar(&transcript);
        assert!(x != Scalar::ZERO);

        let x_inv = x.invert();

        // Fold generators
        let temp1 = y_inv_powers[nprime] * x;
        let temp2 = x_inv * y_powers[nprime];
        let mut new_gprime = Vec::with_capacity(nprime);
        let mut new_hprime = Vec::with_capacity(nprime);
        for i in 0..nprime {
            new_gprime.push(EdwardsPoint::vartime_multiscalar_mul(
                &[x_inv, temp1],
                &[gprime[i], gprime[nprime + i]],
            ));
            new_hprime.push(EdwardsPoint::vartime_multiscalar_mul(
                &[x, x_inv],
                &[hprime[i], hprime[nprime + i]],
            ));
        }
        gprime = new_gprime;
        hprime = new_hprime;

        // Fold scalars
        let mut new_aprime = Vec::with_capacity(nprime);
        let mut new_bprime = Vec::with_capacity(nprime);
        for i in 0..nprime {
            new_aprime.push(aprime[i] * x + aprime[nprime + i] * temp2);
            new_bprime.push(bprime[i] * x_inv + bprime[nprime + i] * x);
        }
        aprime = new_aprime;
        bprime = new_bprime;

        // Update alpha1
        alpha1 = alpha1 + d_l * x * x + d_r * x_inv * x_inv;
    }

    // Step 9: Final round
    let r = random_scalar();
    let s = random_scalar();
    let d_ = random_scalar();
    let eta = random_scalar();

    // A1 = r*Gprime[0] + s*Hprime[0] + d_*G + (r*y*bprime[0] + s*y*aprime[0])*H
    // All scaled by INV_EIGHT
    let h_coeff = r * y * bprime[0] + s * y * aprime[0];
    let capital_a1 = EdwardsPoint::vartime_multiscalar_mul(
        &[r * inv8, s * inv8, d_ * inv8, h_coeff * inv8],
        &[gprime[0], hprime[0], g_pt, h_pt],
    );

    // B = eta*inv8 * G + r*y*s*inv8 * H
    let capital_b = EdwardsPoint::vartime_multiscalar_mul(
        &[eta * inv8, r * y * s * inv8],
        &[g_pt, h_pt],
    );

    // Final challenge e
    transcript = transcript_update2(
        &transcript,
        &capital_a1.compress().to_bytes(),
        &capital_b.compress().to_bytes(),
    );
    let e = bytes_to_scalar(&transcript);
    assert!(e != Scalar::ZERO);

    // Step 10: Final scalars
    let r1 = r + aprime[0] * e;
    let s1 = s + bprime[0] * e;
    let d1 = eta + d_ * e + alpha1 * e * e;

    BulletproofPlusProof {
        v: v_points,
        capital_a,
        capital_a1,
        capital_b,
        r1, s1, d1,
        l_vec: l_points,
        r_vec: r_points,
    }
}

// ─── Verify ─────────────────────────────────────────────────────────────────

pub fn bulletproof_plus_verify(
    v: &[EdwardsPoint],
    proof: &BulletproofPlusProof,
) -> bool {
    bulletproof_plus_verify_batch(&[(v, proof)])
}

pub fn bulletproof_plus_verify_batch(
    proofs: &[(&[EdwardsPoint], &BulletproofPlusProof)],
) -> bool {
    if proofs.is_empty() { return true; }

    let transcript_init = compute_transcript_init();
    let g_pt = ED25519_BASEPOINT_POINT;
    let h_pt = h_point();

    // Collect challenges for batch inversion
    let mut to_invert: Vec<Scalar> = Vec::new();

    struct ProofData {
        v: Vec<EdwardsPoint>,
        capital_a: EdwardsPoint,
        capital_a1: EdwardsPoint,
        capital_b: EdwardsPoint,
        r1: Scalar, s1: Scalar, d1: Scalar,
        l_vec: Vec<EdwardsPoint>,
        r_vec: Vec<EdwardsPoint>,
        m: usize, m_val: usize, mn: usize, rounds: usize,
        y: Scalar, z: Scalar, e: Scalar,
        challenges: Vec<Scalar>,
        challenge_inverses: Vec<Scalar>,
        y_inv: Scalar,
    }

    let mut proof_data_vec: Vec<ProofData> = Vec::new();

    // Phase 1: Reconstruct challenges
    for (v, proof) in proofs {
        let m = v.len();
        if m == 0 || m > MAX_M { return false; }

        let mut m_val = 1usize;
        let mut log_m = 0usize;
        while m_val < m { m_val *= 2; log_m += 1; }
        let mn = m_val * N;
        let rounds = proof.l_vec.len();
        if rounds != LOG_N + log_m { return false; }
        if proof.r_vec.len() != rounds { return false; }

        let mut proof_transcript = transcript_init;
        let hash_v = hash_keys_to_scalar(v);
        proof_transcript = transcript_update(&proof_transcript, &hash_v.to_bytes());

        proof_transcript = transcript_update(&proof_transcript, &proof.capital_a.compress().to_bytes());
        let y = bytes_to_scalar(&proof_transcript);

        let y_bytes = y.to_bytes();
        let z = bytes_to_scalar(&to32(&keccak256_internal(&y_bytes)));
        proof_transcript = z.to_bytes();

        let mut challenges = Vec::with_capacity(rounds);
        for j in 0..rounds {
            proof_transcript = transcript_update2(
                &proof_transcript,
                &proof.l_vec[j].compress().to_bytes(),
                &proof.r_vec[j].compress().to_bytes(),
            );
            let ch = bytes_to_scalar(&proof_transcript);
            challenges.push(ch);
            to_invert.push(ch);
        }

        proof_transcript = transcript_update2(
            &proof_transcript,
            &proof.capital_a1.compress().to_bytes(),
            &proof.capital_b.compress().to_bytes(),
        );
        let e = bytes_to_scalar(&proof_transcript);
        to_invert.push(y);

        proof_data_vec.push(ProofData {
            v: v.to_vec(),
            capital_a: proof.capital_a,
            capital_a1: proof.capital_a1,
            capital_b: proof.capital_b,
            r1: proof.r1, s1: proof.s1, d1: proof.d1,
            l_vec: proof.l_vec.clone(),
            r_vec: proof.r_vec.clone(),
            m, m_val, mn, rounds, y, z, e,
            challenges,
            challenge_inverses: Vec::new(),
            y_inv: Scalar::ZERO,
        });
    }

    // Phase 2: Batch inversion
    let inverses = batch_invert(&to_invert);
    let mut inv_idx = 0;
    for data in &mut proof_data_vec {
        data.challenge_inverses = Vec::with_capacity(data.rounds);
        for _ in 0..data.rounds {
            data.challenge_inverses.push(inverses[inv_idx]);
            inv_idx += 1;
        }
        data.y_inv = inverses[inv_idx];
        inv_idx += 1;
    }

    // Phase 3: Build weighted batch equation
    let mut all_scalars: Vec<Scalar> = Vec::new();
    let mut all_points: Vec<EdwardsPoint> = Vec::new();
    let mut g_scalar = Scalar::ZERO;
    let mut h_scalar = Scalar::ZERO;

    // We need generators for the maximum MN
    let max_mn = proof_data_vec.iter().map(|d| d.mn).max().unwrap_or(0);
    let gens = compute_generators(max_mn);

    for data in &proof_data_vec {
        let w = if proofs.len() == 1 { Scalar::ONE } else { random_scalar() };

        let e2 = data.e * data.e;

        // y^MN via squaring
        let y_mn = scalar_pow(&data.y, data.mn);
        let y_mn_p1 = y_mn * data.y;

        // z powers
        let z2 = data.z * data.z;
        let mut z_powers = Vec::with_capacity(data.m_val);
        z_powers.push(z2);
        for j in 1..data.m_val {
            z_powers.push(z_powers[j - 1] * z2);
        }

        // sum_d = (2^64 - 1) * sum(z_powers)
        let two_64_minus_1 = Scalar::from(u64::MAX);
        let sum_z = z_powers.iter().fold(Scalar::ZERO, |acc, zp| acc + zp);
        let sum_d = two_64_minus_1 * sum_z;

        // sum_y = y + y^2 + ... + y^MN
        let mut sum_y = Scalar::ZERO;
        let mut yp = data.y;
        for _ in 0..data.mn {
            sum_y = sum_y + yp;
            yp = yp * data.y;
        }

        // V commitments
        for j in 0..data.m {
            let scalar = -(w * e2 * z_powers[j] * y_mn_p1);
            all_scalars.push(scalar);
            all_points.push(mul8(&data.v[j]));
        }

        // A, A1, B
        all_scalars.push(-(w * e2));
        all_points.push(mul8(&data.capital_a));

        all_scalars.push(-(w * data.e));
        all_points.push(mul8(&data.capital_a1));

        all_scalars.push(-w);
        all_points.push(mul8(&data.capital_b));

        // G scalar
        g_scalar = g_scalar + w * data.d1;

        // H scalar
        let h_term1 = data.r1 * data.y * data.s1;
        let h_term2 = y_mn_p1 * data.z * sum_d;
        let h_term3 = (z2 - data.z) * sum_y;
        h_scalar = h_scalar + w * (h_term1 + e2 * (h_term2 + h_term3));

        // Challenge cache
        let challenge_cache = build_challenge_cache(
            &data.challenges, &data.challenge_inverses, data.mn,
        );

        // Gi and Hi scalars
        let mut e_r1_w = data.e * data.r1 * w;
        let e_s1_w = data.e * data.s1 * w;
        let e2_z_w = e2 * data.z * w;
        let minus_e2_z_w = -e2_z_w;
        let mut minus_e2_w_y = -(e2 * w * y_mn);

        for i in 0..data.mn {
            let d_idx = i / N;
            let bit_pos = i % N;
            let d_val = z_powers[d_idx] * Scalar::from(1u64 << bit_pos);

            let g_scalar_i = e_r1_w * challenge_cache[i] + e2_z_w;

            let inv_index = (!i) & (data.mn - 1);
            let h_scalar_i = e_s1_w * challenge_cache[inv_index] + minus_e2_z_w + minus_e2_w_y * d_val;

            all_scalars.push(g_scalar_i);
            all_points.push(gens.gi[i]);

            all_scalars.push(h_scalar_i);
            all_points.push(gens.hi[i]);

            e_r1_w = e_r1_w * data.y_inv;
            minus_e2_w_y = minus_e2_w_y * data.y_inv;
        }

        // L and R terms
        for j in 0..data.rounds {
            let x2 = data.challenges[j] * data.challenges[j];
            let x_inv2 = data.challenge_inverses[j] * data.challenge_inverses[j];

            all_scalars.push(-(w * e2 * x2));
            all_points.push(mul8(&data.l_vec[j]));

            all_scalars.push(-(w * e2 * x_inv2));
            all_points.push(mul8(&data.r_vec[j]));
        }
    }

    // Add G and H
    if g_scalar != Scalar::ZERO {
        all_scalars.push(g_scalar);
        all_points.push(g_pt);
    }
    if h_scalar != Scalar::ZERO {
        all_scalars.push(h_scalar);
        all_points.push(h_pt);
    }

    // Final check: result should be identity
    let result = EdwardsPoint::vartime_multiscalar_mul(&all_scalars, &all_points);
    result == EdwardsPoint::default() // Identity point
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn mul8(p: &EdwardsPoint) -> EdwardsPoint {
    let t = p + p;
    let t = t + t;
    t + t
}

fn scalar_pow(base: &Scalar, exp: usize) -> Scalar {
    let mut result = Scalar::ONE;
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result * b;
        }
        b = b * b;
        e >>= 1;
    }
    result
}

fn batch_invert(scalars: &[Scalar]) -> Vec<Scalar> {
    if scalars.is_empty() { return vec![]; }

    // Montgomery's trick
    let n = scalars.len();
    let mut products = Vec::with_capacity(n);
    let mut acc = scalars[0];
    products.push(acc);
    for i in 1..n {
        acc = acc * scalars[i];
        products.push(acc);
    }

    let mut inv = acc.invert();
    let mut result = vec![Scalar::ZERO; n];
    for i in (1..n).rev() {
        result[i] = products[i - 1] * inv;
        inv = inv * scalars[i];
    }
    result[0] = inv;

    result
}

fn build_challenge_cache(
    challenges: &[Scalar],
    challenge_inverses: &[Scalar],
    mn: usize,
) -> Vec<Scalar> {
    let rounds = challenges.len();
    let mut cache = vec![Scalar::ZERO; mn];

    cache[0] = challenge_inverses[0];
    cache[1] = challenges[0];

    for j in 1..rounds {
        let slots = 1 << (j + 1);
        let mut s = slots as i64 - 1;
        while s >= 0 {
            let su = s as usize;
            if su % 2 == 1 {
                cache[su] = cache[su / 2] * challenges[j];
            } else {
                cache[su] = cache[su / 2] * challenge_inverses[j];
            }
            s -= 1;
        }
    }

    cache
}

// ─── Serialization ──────────────────────────────────────────────────────────

pub fn serialize_proof(proof: &BulletproofPlusProof) -> Vec<u8> {
    let mut out = Vec::new();

    // A, A1, B
    out.extend_from_slice(&proof.capital_a.compress().to_bytes());
    out.extend_from_slice(&proof.capital_a1.compress().to_bytes());
    out.extend_from_slice(&proof.capital_b.compress().to_bytes());

    // r1, s1, d1
    out.extend_from_slice(&proof.r1.to_bytes());
    out.extend_from_slice(&proof.s1.to_bytes());
    out.extend_from_slice(&proof.d1.to_bytes());

    // L
    out.extend_from_slice(&encode_varint(proof.l_vec.len() as u32));
    for l in &proof.l_vec {
        out.extend_from_slice(&l.compress().to_bytes());
    }

    // R
    out.extend_from_slice(&encode_varint(proof.r_vec.len() as u32));
    for r in &proof.r_vec {
        out.extend_from_slice(&r.compress().to_bytes());
    }

    out
}

fn decode_varint(bytes: &[u8], offset: usize) -> (usize, usize) {
    let mut value = 0usize;
    let mut shift = 0;
    let mut bytes_read = 0;
    while offset + bytes_read < bytes.len() {
        let byte = bytes[offset + bytes_read];
        bytes_read += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
    }
    (value, bytes_read)
}

pub fn parse_proof(bytes: &[u8]) -> Option<BulletproofPlusProof> {
    if bytes.len() < 32 * 6 { return None; }

    let mut offset = 0;

    let capital_a = CompressedEdwardsY(to32(&bytes[offset..offset + 32])).decompress()?;
    offset += 32;
    let capital_a1 = CompressedEdwardsY(to32(&bytes[offset..offset + 32])).decompress()?;
    offset += 32;
    let capital_b = CompressedEdwardsY(to32(&bytes[offset..offset + 32])).decompress()?;
    offset += 32;

    let r1 = Scalar::from_bytes_mod_order(to32(&bytes[offset..offset + 32]));
    offset += 32;
    let s1 = Scalar::from_bytes_mod_order(to32(&bytes[offset..offset + 32]));
    offset += 32;
    let d1 = Scalar::from_bytes_mod_order(to32(&bytes[offset..offset + 32]));
    offset += 32;

    let (l_count, l_bytes) = decode_varint(bytes, offset);
    offset += l_bytes;
    let mut l_vec = Vec::with_capacity(l_count);
    for _ in 0..l_count {
        if offset + 32 > bytes.len() { return None; }
        l_vec.push(CompressedEdwardsY(to32(&bytes[offset..offset + 32])).decompress()?);
        offset += 32;
    }

    let (r_count, r_bytes) = decode_varint(bytes, offset);
    offset += r_bytes;
    let mut r_vec = Vec::with_capacity(r_count);
    for _ in 0..r_count {
        if offset + 32 > bytes.len() { return None; }
        r_vec.push(CompressedEdwardsY(to32(&bytes[offset..offset + 32])).decompress()?);
        offset += 32;
    }

    Some(BulletproofPlusProof {
        v: Vec::new(),
        capital_a, capital_a1, capital_b,
        r1, s1, d1,
        l_vec, r_vec,
    })
}

// ─── WASM Bindings ──────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn bulletproof_plus_prove_wasm(
    amounts_bytes: &[u8],
    masks_flat: &[u8],
) -> Vec<u8> {
    let n = amounts_bytes.len() / 8;
    let amounts: Vec<u64> = (0..n).map(|i| {
        u64::from_le_bytes([
            amounts_bytes[i*8], amounts_bytes[i*8+1], amounts_bytes[i*8+2], amounts_bytes[i*8+3],
            amounts_bytes[i*8+4], amounts_bytes[i*8+5], amounts_bytes[i*8+6], amounts_bytes[i*8+7],
        ])
    }).collect();
    let masks: Vec<Scalar> = (0..n).map(|i| {
        Scalar::from_bytes_mod_order(to32(&masks_flat[i*32..(i+1)*32]))
    }).collect();

    let proof = bulletproof_plus_prove(&amounts, &masks);

    // Serialize: proof_bytes + V commitments
    let proof_bytes = serialize_proof(&proof);
    let v_count = proof.v.len() as u32;

    let mut out = Vec::with_capacity(4 + proof.v.len() * 32 + proof_bytes.len());
    out.extend_from_slice(&v_count.to_le_bytes());
    for v in &proof.v {
        out.extend_from_slice(&v.compress().to_bytes());
    }
    out.extend_from_slice(&proof_bytes);
    out
}

#[wasm_bindgen]
pub fn bulletproof_plus_verify_wasm(
    proof_data: &[u8],
    commitments_flat: &[u8],
) -> bool {
    let n = commitments_flat.len() / 32;
    let v: Vec<EdwardsPoint> = (0..n).map(|i| {
        match CompressedEdwardsY(to32(&commitments_flat[i*32..(i+1)*32])).decompress() {
            Some(p) => p,
            None => return EdwardsPoint::default(),
        }
    }).collect();

    let proof = match parse_proof(proof_data) {
        Some(p) => p,
        None => return false,
    };

    bulletproof_plus_verify(&v, &proof)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bp_plus_prove_verify_single() {
        let amount = 1000000u64;
        let mask = random_scalar();

        let proof = bulletproof_plus_prove(&[amount], &[mask]);

        assert!(bulletproof_plus_verify(&proof.v, &proof));
    }

    #[test]
    fn test_bp_plus_prove_verify_two_outputs() {
        let amounts = [1000000u64, 5000000u64];
        let masks = [random_scalar(), random_scalar()];

        let proof = bulletproof_plus_prove(&amounts, &masks);

        assert!(bulletproof_plus_verify(&proof.v, &proof));
    }

    #[test]
    fn test_bp_plus_prove_verify_zero_amount() {
        let proof = bulletproof_plus_prove(&[0u64], &[random_scalar()]);
        assert!(bulletproof_plus_verify(&proof.v, &proof));
    }

    #[test]
    fn test_bp_plus_prove_verify_max_amount() {
        let proof = bulletproof_plus_prove(&[u64::MAX], &[random_scalar()]);
        assert!(bulletproof_plus_verify(&proof.v, &proof));
    }

    #[test]
    fn test_bp_plus_serialize_roundtrip() {
        let proof = bulletproof_plus_prove(&[42u64], &[random_scalar()]);
        let bytes = serialize_proof(&proof);
        let parsed = parse_proof(&bytes).expect("parse failed");

        // Verify the parsed proof with original V
        assert!(bulletproof_plus_verify(&proof.v, &parsed));
    }

    #[test]
    fn test_bp_plus_batch_verify() {
        let proof1 = bulletproof_plus_prove(&[100u64], &[random_scalar()]);
        let proof2 = bulletproof_plus_prove(&[200u64, 300u64], &[random_scalar(), random_scalar()]);

        let batch = vec![
            (proof1.v.as_slice(), &proof1),
            (proof2.v.as_slice(), &proof2),
        ];
        assert!(bulletproof_plus_verify_batch(&batch));
    }
}
