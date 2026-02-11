/* tslint:disable */
/* eslint-disable */

/**
 * Argon2id key derivation (WASM-accessible).
 * password, salt: arbitrary-length byte slices.
 * t_cost: number of iterations, m_cost: memory in KiB, parallelism: threads.
 * dk_len: desired output length in bytes.
 * Returns the derived key bytes, or empty vec on error.
 */
export function argon2id_hash(password: Uint8Array, salt: Uint8Array, t_cost: number, m_cost: number, parallelism: number, dk_len: number): Uint8Array;

/**
 * Blake2b with variable output length (unkeyed)
 * Matches Salvium C++ blake2b(out, outLen, data, dataLen, NULL, 0)
 */
export function blake2b_hash(data: Uint8Array, out_len: number): Uint8Array;

/**
 * Blake2b with key (keyed variant per RFC 7693)
 * Matches Salvium C++ blake2b(out, outLen, data, dataLen, key, keyLen)
 * Used by CARROT protocol for domain-separated hashing
 */
export function blake2b_keyed(data: Uint8Array, out_len: number, key: Uint8Array): Uint8Array;

export function bulletproof_plus_prove_wasm(amounts_bytes: Uint8Array, masks_flat: Uint8Array): Uint8Array;

export function bulletproof_plus_verify_wasm(proof_data: Uint8Array, commitments_flat: Uint8Array): boolean;

export function clsag_sign_wasm(message: Uint8Array, ring_flat: Uint8Array, secret_key: Uint8Array, commitments_flat: Uint8Array, commitment_mask: Uint8Array, pseudo_output: Uint8Array, secret_index: number): Uint8Array;

export function clsag_verify_wasm(message: Uint8Array, sig_bytes: Uint8Array, ring_flat: Uint8Array, commitments_flat: Uint8Array, pseudo_output: Uint8Array): boolean;

/**
 * Derive public key: base + H(derivation || index) * G
 */
export function derive_public_key(derivation: Uint8Array, output_index: number, base_pub: Uint8Array): Uint8Array;

/**
 * Derive secret key: base + H(derivation || index) mod L
 */
export function derive_secret_key(derivation: Uint8Array, output_index: number, base_sec: Uint8Array): Uint8Array;

export function double_scalar_mult_base(a: Uint8Array, p: Uint8Array, b: Uint8Array): Uint8Array;

/**
 * Generate commitment mask from shared secret
 * mask = scReduce32(keccak256("commitment_mask" || sharedSecret))
 */
export function gen_commitment_mask(shared_secret: Uint8Array): Uint8Array;

/**
 * Generate key derivation: D = 8 * (sec * pub)
 */
export function generate_key_derivation(pub_key: Uint8Array, sec_key: Uint8Array): Uint8Array;

/**
 * Generate key image: KI = sec * H_p(pub)
 */
export function generate_key_image(pub_key: Uint8Array, sec_key: Uint8Array): Uint8Array;

/**
 * Hash-to-point: H_p(data) = cofactor * elligator2(keccak256(data))
 * Matches Salvium C++ hash_to_ec / ge_fromfe_frombytes_vartime
 */
export function hash_to_point(data: Uint8Array): Uint8Array;

/**
 * Keccak-256 hash (CryptoNote variant with 0x01 padding, NOT SHA3)
 * Matches Salvium C++ cn_fast_hash / keccak()
 */
export function keccak256(data: Uint8Array): Uint8Array;

/**
 * Pedersen commitment: C = mask*G + amount*H
 */
export function pedersen_commit(amount: Uint8Array, mask: Uint8Array): Uint8Array;

export function point_add_compressed(p: Uint8Array, q: Uint8Array): Uint8Array;

export function point_negate(p: Uint8Array): Uint8Array;

export function point_sub_compressed(p: Uint8Array, q: Uint8Array): Uint8Array;

export function sc_add(a: Uint8Array, b: Uint8Array): Uint8Array;

export function sc_check(s: Uint8Array): boolean;

export function sc_invert(a: Uint8Array): Uint8Array;

export function sc_is_zero(s: Uint8Array): boolean;

export function sc_mul(a: Uint8Array, b: Uint8Array): Uint8Array;

export function sc_mul_add(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array;

export function sc_mul_sub(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array;

export function sc_reduce32(s: Uint8Array): Uint8Array;

export function sc_reduce64(s: Uint8Array): Uint8Array;

export function sc_sub(a: Uint8Array, b: Uint8Array): Uint8Array;

export function scalar_mult_base(s: Uint8Array): Uint8Array;

export function scalar_mult_point(s: Uint8Array, p: Uint8Array): Uint8Array;

/**
 * SHA-256 hash
 */
export function sha256(data: Uint8Array): Uint8Array;

export function tclsag_sign_wasm(message: Uint8Array, ring_flat: Uint8Array, secret_key_x: Uint8Array, secret_key_y: Uint8Array, commitments_flat: Uint8Array, commitment_mask: Uint8Array, pseudo_output: Uint8Array, secret_index: number): Uint8Array;

export function tclsag_verify_wasm(message: Uint8Array, sig_bytes: Uint8Array, ring_flat: Uint8Array, commitments_flat: Uint8Array, pseudo_output: Uint8Array): boolean;

/**
 * X25519 scalar multiplication with Salvium's non-standard clamping.
 *
 * Salvium clamping only clears bit 255 (scalar[31] &= 0x7F).
 * Unlike RFC 7748, bits 0-2 are NOT cleared and bit 254 is NOT set.
 *
 * Uses a Montgomery ladder on Curve25519 (a24 = 121666, p = 2^255 - 19).
 * scalar and u_coord must each be 32 bytes (little-endian).
 * Returns the 32-byte u-coordinate of the result point.
 */
export function x25519_scalar_mult(scalar: Uint8Array, u_coord: Uint8Array): Uint8Array;

/**
 * Zero commitment: C = 1*G + amount*H (blinding factor = 1)
 * Matches C++ rct::zeroCommit() used for coinbase outputs and fee commitments.
 */
export function zero_commit(amount: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly argon2id_hash: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly blake2b_hash: (a: number, b: number, c: number) => [number, number];
    readonly blake2b_keyed: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly bulletproof_plus_prove_wasm: (a: number, b: number, c: number, d: number) => [number, number];
    readonly bulletproof_plus_verify_wasm: (a: number, b: number, c: number, d: number) => number;
    readonly clsag_sign_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number) => [number, number];
    readonly clsag_verify_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly derive_public_key: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly derive_secret_key: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly double_scalar_mult_base: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly gen_commitment_mask: (a: number, b: number) => [number, number];
    readonly generate_key_derivation: (a: number, b: number, c: number, d: number) => [number, number];
    readonly generate_key_image: (a: number, b: number, c: number, d: number) => [number, number];
    readonly hash_to_point: (a: number, b: number) => [number, number];
    readonly keccak256: (a: number, b: number) => [number, number];
    readonly pedersen_commit: (a: number, b: number, c: number, d: number) => [number, number];
    readonly point_add_compressed: (a: number, b: number, c: number, d: number) => [number, number];
    readonly point_negate: (a: number, b: number) => [number, number];
    readonly point_sub_compressed: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sc_add: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sc_check: (a: number, b: number) => number;
    readonly sc_invert: (a: number, b: number) => [number, number];
    readonly sc_is_zero: (a: number, b: number) => number;
    readonly sc_mul: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sc_mul_add: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly sc_mul_sub: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly sc_reduce32: (a: number, b: number) => [number, number];
    readonly sc_reduce64: (a: number, b: number) => [number, number];
    readonly sc_sub: (a: number, b: number, c: number, d: number) => [number, number];
    readonly scalar_mult_base: (a: number, b: number) => [number, number];
    readonly scalar_mult_point: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sha256: (a: number, b: number) => [number, number];
    readonly tclsag_sign_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number];
    readonly tclsag_verify_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => number;
    readonly x25519_scalar_mult: (a: number, b: number, c: number, d: number) => [number, number];
    readonly zero_commit: (a: number, b: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
