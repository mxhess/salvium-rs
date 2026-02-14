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

/* ─── X25519 Montgomery-curve Scalar Multiplication ──────────────────────── */

/**
 * X25519 scalar multiplication with Salvium's non-standard clamping.
 * Only clears bit 255 (scalar[31] &= 0x7F). Does NOT clear bits 0-2
 * or set bit 254 (unlike RFC 7748).
 * scalar: 32-byte LE scalar, u_coord: 32-byte LE u-coordinate.
 * out: 32-byte result u-coordinate.
 * Returns 0 on success.
 */
int32_t salvium_x25519_scalar_mult(
    const uint8_t *scalar /* 32 */, const uint8_t *u_coord /* 32 */,
    uint8_t *out /* 32 */);

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

/* ─── RCT Batch Signature Verification ──────────────────────────────────── */

/**
 * Verify all RCT signatures in a transaction in one call.
 * Sig flat format (no I field — key images passed separately):
 *   TCLSAG (type 9): [sx_0..sx_n][sy_0..sy_n][c1][D] per input
 *   CLSAG (types 5-8): [s_0..s_n][c1][D] per input
 *
 * result_buf receives: [0x01] valid, [0x00,idx_LE] invalid, [0xFF] error.
 * result_buf must be at least 5 bytes.
 * Returns bytes written to result_buf, or -1 on error.
 */
int32_t salvium_verify_rct_signatures(
    uint8_t rct_type, uint32_t input_count, uint32_t ring_size,
    const uint8_t *tx_prefix_hash, uint32_t tx_prefix_hash_len,
    const uint8_t *rct_base, uint32_t rct_base_len,
    const uint8_t *bp_components, uint32_t bp_components_len,
    const uint8_t *key_images, uint32_t key_images_len,
    const uint8_t *pseudo_outs, uint32_t pseudo_outs_len,
    const uint8_t *sigs, uint32_t sigs_len,
    const uint8_t *ring_pubkeys, uint32_t ring_pubkeys_len,
    const uint8_t *ring_commitments, uint32_t ring_commitments_len,
    uint8_t *result_buf, uint32_t result_buf_len);

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

/* ─── AES-256-GCM Encryption ───────────────────────────────────────────── */

/**
 * AES-256-GCM encrypt.
 * Rust generates a random 12-byte nonce internally.
 * Output: nonce(12) || ciphertext || tag(16).  Size = plaintext_len + 28.
 * out must be at least plaintext_len + 28 bytes.
 * out_len receives actual output length.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_aes256gcm_encrypt(
    const uint8_t *key /* 32 */,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out,
    size_t *out_len);

/**
 * AES-256-GCM decrypt.
 * Input: nonce(12) || ciphertext || tag(16).
 * out must be at least ciphertext_len - 28 bytes.
 * out_len receives actual output length (plaintext size).
 * Returns 0 on success, -1 on error (authentication failure or bad input).
 */
int32_t salvium_aes256gcm_decrypt(
    const uint8_t *key /* 32 */,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *out,
    size_t *out_len);

/* ─── SQLCipher Storage ─────────────────────────────────────────────────── */

/**
 * Open/create an encrypted SQLite database.
 * path: UTF-8 path string (path_len bytes, not null-terminated).
 * key: 32-byte encryption key for SQLCipher PRAGMA key.
 * Returns handle_id >= 1 on success, -1 on error.
 */
int32_t salvium_storage_open(
    const uint8_t *path, size_t path_len,
    const uint8_t *key, size_t key_len);

/** Close a storage handle and release resources. Returns 0 on success. */
int32_t salvium_storage_close(uint32_t handle);

/** Clear all data in the database. Returns 0 on success. */
int32_t salvium_storage_clear(uint32_t handle);

/**
 * Insert/update output. json is UTF-8 JSON blob of WalletOutput.toJSON() format.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_put_output(uint32_t handle,
    const uint8_t *json, size_t json_len);

/**
 * Get single output by key image. Rust allocates result buffer.
 * out_ptr receives pointer, out_len receives length.
 * Caller must call salvium_storage_free_buf to free.
 * Returns 0 on success, -1 if not found or error.
 */
int32_t salvium_storage_get_output(uint32_t handle,
    const uint8_t *key_image, size_t ki_len,
    uint8_t **out_ptr, size_t *out_len);

/**
 * Get filtered outputs. query_json is JSON: {isSpent, assetType, accountIndex, ...}
 * Returns JSON array. Rust allocates result buffer.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_get_outputs(uint32_t handle,
    const uint8_t *query_json, size_t query_len,
    uint8_t **out_ptr, size_t *out_len);

/**
 * Mark an output as spent.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_mark_spent(uint32_t handle,
    const uint8_t *key_image, size_t ki_len,
    const uint8_t *spending_tx, size_t tx_len,
    int64_t spent_height);

/**
 * Insert/update a transaction. json is UTF-8 JSON blob.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_put_tx(uint32_t handle,
    const uint8_t *json, size_t json_len);

/**
 * Get single transaction by hash.
 * Returns 0 on success, -1 if not found or error.
 */
int32_t salvium_storage_get_tx(uint32_t handle,
    const uint8_t *tx_hash, size_t th_len,
    uint8_t **out_ptr, size_t *out_len);

/**
 * Get filtered transactions. query_json is JSON with filter criteria.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_get_txs(uint32_t handle,
    const uint8_t *query_json, size_t query_len,
    uint8_t **out_ptr, size_t *out_len);

/**
 * Get sync height. Returns height >= 0 on success, -1 on error.
 */
int64_t salvium_storage_get_sync_height(uint32_t handle);

/**
 * Set sync height. Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_set_sync_height(uint32_t handle, int64_t height);

/**
 * Store a block hash for a given height.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_put_block_hash(uint32_t handle, int64_t height,
    const uint8_t *hash, size_t hash_len);

/**
 * Get a block hash for a given height.
 * Returns 0 on success, -1 if not found or error.
 */
int32_t salvium_storage_get_block_hash(uint32_t handle, int64_t height,
    uint8_t **out_ptr, size_t *out_len);

/**
 * Atomic rollback: deletes outputs/txs/block_hashes above height,
 * unspends outputs spent above height. All in one SQLite transaction.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_rollback(uint32_t handle, int64_t height);

/**
 * Compute balance in Rust. Avoids round-tripping all outputs to JS/Dart.
 * Returns JSON: {"balance":"...","unlockedBalance":"...","lockedBalance":"..."}
 * account_index: -1 for all accounts.
 * Returns 0 on success, -1 on error.
 */
int32_t salvium_storage_get_balance(uint32_t handle,
    int64_t current_height,
    const uint8_t *asset_type, size_t at_len,
    int32_t account_index,
    uint8_t **out_ptr, size_t *out_len);

/* ─── CryptoNote Output Scanning ─────────────────────────────────────────── */

/**
 * CryptoNote (pre-CARROT) output scan — single native call.
 * view_tag: -1 = no view tag, 0-255 = expected tag.
 * rct_type: 0 = coinbase, else RCT.
 * clear_text_amount: UINT64_MAX = not provided.
 * spend_secret_key: nullable (view-only wallet).
 * subaddr_data: n_sub * 40 bytes (32-byte key + u32 major LE + u32 minor LE).
 * out_ptr/out_len: Rust-allocated JSON result buffer.
 * Returns: 1 = owned, 0 = not owned, -1 = error.
 */
int32_t salvium_cn_scan_output(
    const uint8_t *output_pubkey /* 32 */,
    const uint8_t *derivation /* 32 */,
    uint32_t output_index,
    int32_t view_tag,
    uint8_t rct_type,
    uint64_t clear_text_amount,
    const uint8_t *ecdh_encrypted_amount /* 8 */,
    const uint8_t *spend_secret_key /* 32, nullable */,
    const uint8_t *view_secret_key /* 32 */,
    const uint8_t *subaddr_data,
    uint32_t n_sub,
    uint8_t **out_ptr,
    size_t *out_len);

/** Free Rust-allocated result buffer. */
void salvium_storage_free_buf(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SALVIUM_CRYPTO_H */
