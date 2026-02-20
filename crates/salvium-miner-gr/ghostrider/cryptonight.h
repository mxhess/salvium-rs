/*
 * CryptoNight hash — standalone portable C implementation for GhostRider.
 *
 * Implements the 6 CN GR variants (all based on CN_1 / Monero V7).
 * Software AES only (T-table), no SSE/AES-NI intrinsics.
 *
 * Reference: XMRig CryptoNight_x86.h, CnAlgo.h
 */

#ifndef GHOSTRIDER_CRYPTONIGHT_H
#define GHOSTRIDER_CRYPTONIGHT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum scratchpad size across all GR variants (2 MB for CN_GR_2) */
#define CN_MAX_MEMORY  0x200000

/* Per-thread context: holds 200-byte Keccak state + 2MB scratchpad */
typedef struct {
    uint8_t state[200]   __attribute__((aligned(16)));
    uint8_t save_state[128] __attribute__((aligned(16)));
    uint8_t *memory;     /* scratchpad, CN_MAX_MEMORY bytes, 16-byte aligned */
    int first_half;
} cn_ctx;

cn_ctx *cn_alloc_ctx(void);
void    cn_free_ctx(cn_ctx *ctx);

/*
 * Compute CryptoNight hash for a GhostRider variant.
 *
 * variant: 0=cn/dark, 1=cn/dark-lite, 2=cn/fast, 3=cn/lite,
 *          4=cn/turtle, 5=cn/turtle-lite
 * input:   64 bytes (the SPH-512 hash output)
 * output:  32-byte hash result
 */
void cryptonight_hash(const uint8_t *input, size_t size,
                      uint8_t *output, cn_ctx *ctx, int variant);

#ifdef __cplusplus
}
#endif

#endif /* GHOSTRIDER_CRYPTONIGHT_H */
