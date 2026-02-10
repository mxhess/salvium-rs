/**
 * salvium_crypto.h — C FFI for the salvium-crypto Rust crate.
 *
 * All functions return i32: 0 = ok, -1 = error.
 * All output buffers are 32 bytes unless noted otherwise.
 * Caller owns all buffers.
 */

#ifndef SALVIUM_CRYPTO_H
#define SALVIUM_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Hashing ────────────────────────────────────────────────────────────── */

int32_t salvium_keccak256(
    const uint8_t *data, size_t data_len,
    uint8_t *out /* 32 bytes */);

int32_t salvium_blake2b(
    const uint8_t *data, size_t data_len,
    size_t out_len,
    uint8_t *out /* out_len bytes */);

int32_t salvium_blake2b_keyed(
    const uint8_t *data, size_t data_len,
    size_t out_len,
    const uint8_t *key, size_t key_len,
    uint8_t *out /* out_len bytes */);

/* ─── Scalar Operations (mod L) ──────────────────────────────────────────── */

int32_t salvium_sc_add(
    const uint8_t *a /* 32 */, const uint8_t *b /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_sc_sub(
    const uint8_t *a /* 32 */, const uint8_t *b /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_sc_mul(
    const uint8_t *a /* 32 */, const uint8_t *b /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_sc_mul_add(
    const uint8_t *a /* 32 */, const uint8_t *b /* 32 */,
    const uint8_t *c /* 32 */, uint8_t *out /* 32 */);

int32_t salvium_sc_mul_sub(
    const uint8_t *a /* 32 */, const uint8_t *b /* 32 */,
    const uint8_t *c /* 32 */, uint8_t *out /* 32 */);

int32_t salvium_sc_reduce32(
    const uint8_t *s /* 32 */, uint8_t *out /* 32 */);

int32_t salvium_sc_reduce64(
    const uint8_t *s /* 64 */, uint8_t *out /* 32 */);

int32_t salvium_sc_invert(
    const uint8_t *a /* 32 */, uint8_t *out /* 32 */);

/** Returns 1 if s is a canonical scalar, 0 otherwise. */
int32_t salvium_sc_check(const uint8_t *s /* 32 */);

/** Returns 1 if s == 0 mod L, 0 otherwise. */
int32_t salvium_sc_is_zero(const uint8_t *s /* 32 */);

/* ─── Point Operations (compressed Edwards Y) ───────────────────────────── */

int32_t salvium_scalar_mult_base(
    const uint8_t *s /* 32 */, uint8_t *out /* 32 */);

int32_t salvium_scalar_mult_point(
    const uint8_t *s /* 32 */, const uint8_t *p /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_point_add(
    const uint8_t *p /* 32 */, const uint8_t *q /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_point_sub(
    const uint8_t *p /* 32 */, const uint8_t *q /* 32 */,
    uint8_t *out /* 32 */);

int32_t salvium_point_negate(
    const uint8_t *p /* 32 */, uint8_t *out /* 32 */);

int32_t salvium_double_scalar_mult_base(
    const uint8_t *a /* 32 */, const uint8_t *p /* 32 */,
    const uint8_t *b /* 32 */, uint8_t *out /* 32 */);

/* ─── Hash-to-Point & Key Derivation ─────────────────────────────────────── */

int32_t salvium_hash_to_point(
    const uint8_t *data, size_t data_len,
    uint8_t *out /* 32 */);

/** Hot path: D = 8 * (sec * pub) */
int32_t salvium_generate_key_derivation(
    const uint8_t *pub_key /* 32 */, const uint8_t *sec_key /* 32 */,
    uint8_t *out /* 32 */);

/** Hot path: KI = sec * H_p(pub) */
int32_t salvium_generate_key_image(
    const uint8_t *pub_key /* 32 */, const uint8_t *sec_key /* 32 */,
    uint8_t *out /* 32 */);

/** Hot path: base + H(derivation || index) * G */
int32_t salvium_derive_public_key(
    const uint8_t *derivation /* 32 */, uint32_t output_index,
    const uint8_t *base_pub /* 32 */, uint8_t *out /* 32 */);

/** Hot path: base + H(derivation || index) mod L */
int32_t salvium_derive_secret_key(
    const uint8_t *derivation /* 32 */, uint32_t output_index,
    const uint8_t *base_sec /* 32 */, uint8_t *out /* 32 */);

/* ─── Pedersen Commitments ───────────────────────────────────────────────── */

/** C = mask*G + amount*H */
int32_t salvium_pedersen_commit(
    const uint8_t *amount /* 32 */, const uint8_t *mask /* 32 */,
    uint8_t *out /* 32 */);

/** C = 1*G + amount*H */
int32_t salvium_zero_commit(
    const uint8_t *amount /* 32 */, uint8_t *out /* 32 */);

/** mask = scReduce32(keccak256("commitment_mask" || secret)) */
int32_t salvium_gen_commitment_mask(
    const uint8_t *secret /* 32 */, uint8_t *out /* 32 */);

/* ─── Oracle Signature Verification ───────────────────────────────────────── */

/** SHA-256 hash */
int32_t salvium_sha256(
    const uint8_t *data, size_t data_len,
    uint8_t *out /* 32 */);

/**
 * Verify signature against DER-encoded SPKI public key.
 * Supports ECDSA P-256 (testnet) and DSA (mainnet).
 * Message is hashed with SHA-256 internally.
 * Returns 1 for valid, 0 for invalid/error.
 */
int32_t salvium_verify_signature(
    const uint8_t *message, size_t msg_len,
    const uint8_t *signature, size_t sig_len,
    const uint8_t *pubkey_der, size_t key_len);

/* ─── Key Derivation ───────────────────────────────────────────────────────── */

/**
 * Argon2id key derivation.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_argon2id(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost,      /* time cost (iterations/passes) */
    uint32_t m_cost,      /* memory cost in KiB */
    uint32_t parallelism, /* number of lanes */
    size_t out_len,       /* desired output length in bytes (typically 32) */
    uint8_t *out);

/* ─── CLSAG Ring Signatures ──────────────────────────────────────────────── */

/**
 * CLSAG sign. Output: s[0..n] || c1 || I || D (each 32 bytes).
 * out must be ring_count*32 + 96 bytes.
 */
int32_t salvium_clsag_sign(
    const uint8_t *message /* 32 */,
    const uint8_t *ring /* ring_count * 32 */, uint32_t ring_count,
    const uint8_t *secret_key /* 32 */,
    const uint8_t *commitments /* ring_count * 32 */,
    const uint8_t *commitment_mask /* 32 */,
    const uint8_t *pseudo_output /* 32 */,
    uint32_t secret_index,
    uint8_t *out /* ring_count*32 + 96 */);

/**
 * CLSAG verify.
 * sig format: s[0..n] || c1 || I || D (each 32 bytes, no length prefix).
 * Returns 1 for valid, 0 for invalid.
 */
int32_t salvium_clsag_verify(
    const uint8_t *message /* 32 */,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *ring /* ring_count * 32 */, uint32_t ring_count,
    const uint8_t *commitments /* ring_count * 32 */,
    const uint8_t *pseudo_output /* 32 */);

/* ─── TCLSAG Ring Signatures ────────────────────────────────────────────── */

/**
 * TCLSAG sign. Output: sx[0..n] || sy[0..n] || c1 || I || D (each 32 bytes).
 * out must be 2*ring_count*32 + 96 bytes.
 */
int32_t salvium_tclsag_sign(
    const uint8_t *message /* 32 */,
    const uint8_t *ring /* ring_count * 32 */, uint32_t ring_count,
    const uint8_t *secret_key_x /* 32 */,
    const uint8_t *secret_key_y /* 32 */,
    const uint8_t *commitments /* ring_count * 32 */,
    const uint8_t *commitment_mask /* 32 */,
    const uint8_t *pseudo_output /* 32 */,
    uint32_t secret_index,
    uint8_t *out /* 2*ring_count*32 + 96 */);

/**
 * TCLSAG verify.
 * sig format: sx[0..n] || sy[0..n] || c1 || I || D (each 32 bytes).
 * Returns 1 for valid, 0 for invalid.
 */
int32_t salvium_tclsag_verify(
    const uint8_t *message /* 32 */,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *ring /* ring_count * 32 */, uint32_t ring_count,
    const uint8_t *commitments /* ring_count * 32 */,
    const uint8_t *pseudo_output /* 32 */);

/* ─── Bulletproofs+ Range Proofs ─────────────────────────────────────────── */

/**
 * Bulletproof+ prove.
 * amounts: count * 8 bytes (u64 LE), masks: count * 32 bytes (scalars).
 * Output: [v_count u32 LE][V_0..V_n 32B each][proof_bytes]
 * out_len receives actual output length.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_bulletproof_plus_prove(
    const uint8_t *amounts /* count * 8 */,
    const uint8_t *masks /* count * 32 */,
    uint32_t count,
    uint8_t *out,
    size_t out_max,
    size_t *out_len);

/**
 * Bulletproof+ verify.
 * proof_bytes: serialized proof, commitments: commitment_count * 32 bytes.
 * Returns 1 for valid, 0 for invalid.
 */
int32_t salvium_bulletproof_plus_verify(
    const uint8_t *proof_bytes, size_t proof_len,
    const uint8_t *commitments /* commitment_count * 32 */,
    uint32_t commitment_count);

#ifdef __cplusplus
}
#endif

#endif /* SALVIUM_CRYPTO_H */
