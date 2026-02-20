/*
 * GhostRider hash — C-compatible FFI wrapper.
 *
 * Full GhostRider PoW: 3-part pipeline of SPH-512 core hashes
 * interleaved with CryptoNight memory-hard rounds.
 */

#ifndef GHOSTRIDER_FFI_H
#define GHOSTRIDER_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocate a per-thread GhostRider context (holds 2MB scratchpad).
 * Returns opaque pointer, or NULL on allocation failure.
 */
void *ghostrider_alloc_ctx(void);

/**
 * Free a GhostRider context previously allocated with ghostrider_alloc_ctx().
 */
void ghostrider_free_ctx(void *ctx);

/**
 * Compute the full GhostRider PoW hash.
 *
 * @param input     Input blob to hash.
 * @param input_len Length of input in bytes (must be >= 43 for CN V1).
 * @param output    32-byte output buffer for the final hash.
 * @param ctx       Context from ghostrider_alloc_ctx().
 * @return          0 on success, non-zero on error.
 */
int ghostrider_hash(const uint8_t *input, size_t input_len,
                    uint8_t *output, void *ctx);

/**
 * Compute individual SPH-512 hash (for testing/verification).
 *
 * @param algo_index Hash algorithm index (0=blake, 1=bmw, ... 14=whirlpool)
 * @param input      Input data.
 * @param input_len  Length of input in bytes.
 * @param output     64-byte output buffer for the full hash.
 * @return           0 on success, non-zero on error.
 */
int ghostrider_sph_hash(int algo_index, const uint8_t *input,
                        size_t input_len, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* GHOSTRIDER_FFI_H */
