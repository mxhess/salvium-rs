/*
 * Keccak-f[1600] and keccak hash — pure C port from XMRig.
 *
 * Original: xmrig/src/base/crypto/keccak.cpp
 * Stripped of C++ / namespace, converted to plain C.
 */

#ifndef GHOSTRIDER_KECCAK_H
#define GHOSTRIDER_KECCAK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute keccak hash: md must be >= mdlen bytes.
 * For CryptoNight, call with mdlen=200 to get the full 1600-bit state. */
void gr_keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);

/* Keccak-f[1600] permutation, norounds rounds (typically 24). */
void gr_keccakf(uint64_t st[25], int norounds);

#ifdef __cplusplus
}
#endif

#endif /* GHOSTRIDER_KECCAK_H */
