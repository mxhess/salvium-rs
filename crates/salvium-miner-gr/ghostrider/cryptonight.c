/*
 * CryptoNight hash — standalone portable C implementation for GhostRider.
 *
 * Implements CN_1 (Monero V7) base with the 6 GhostRider variant parameters.
 * Software AES only (T-table approach, no hardware AES-NI).
 *
 * Reference: XMRig CryptoNight_x86.h, soft_aes.h, CryptoNight_monero.h
 * License: GPL-3.0+
 */

#include "cryptonight.h"
#include "keccak.h"
#include "c_blake256.h"
#include "c_groestl.h"
#include "c_jh.h"
#include "c_skein.h"

#include <stdlib.h>
#include <string.h>

/* ── AES T-tables (generated from S-box via macros, same as XMRig soft_aes.h) ── */

#define SAES_WPOLY 0x011b

#define saes_f2(x)  ((uint32_t)((x) << 1) ^ ((((x) >> 7) & 1) * SAES_WPOLY))
#define saes_f3(x)  (saes_f2(x) ^ (x))

#define saes_b2w(b0, b1, b2, b3) \
    (((uint32_t)(b3) << 24) | ((uint32_t)(b2) << 16) | ((uint32_t)(b1) << 8) | (uint32_t)(b0))

#define saes_u0(p) saes_b2w(saes_f2(p),       (p),       (p), saes_f3(p))
#define saes_u1(p) saes_b2w(saes_f3(p), saes_f2(p),       (p),       (p))
#define saes_u2(p) saes_b2w(      (p), saes_f3(p), saes_f2(p),       (p))
#define saes_u3(p) saes_b2w(      (p),       (p), saes_f3(p), saes_f2(p))

#define saes_data(w) { \
    w(0x63),w(0x7c),w(0x77),w(0x7b),w(0xf2),w(0x6b),w(0x6f),w(0xc5), \
    w(0x30),w(0x01),w(0x67),w(0x2b),w(0xfe),w(0xd7),w(0xab),w(0x76), \
    w(0xca),w(0x82),w(0xc9),w(0x7d),w(0xfa),w(0x59),w(0x47),w(0xf0), \
    w(0xad),w(0xd4),w(0xa2),w(0xaf),w(0x9c),w(0xa4),w(0x72),w(0xc0), \
    w(0xb7),w(0xfd),w(0x93),w(0x26),w(0x36),w(0x3f),w(0xf7),w(0xcc), \
    w(0x34),w(0xa5),w(0xe5),w(0xf1),w(0x71),w(0xd8),w(0x31),w(0x15), \
    w(0x04),w(0xc7),w(0x23),w(0xc3),w(0x18),w(0x96),w(0x05),w(0x9a), \
    w(0x07),w(0x12),w(0x80),w(0xe2),w(0xeb),w(0x27),w(0xb2),w(0x75), \
    w(0x09),w(0x83),w(0x2c),w(0x1a),w(0x1b),w(0x6e),w(0x5a),w(0xa0), \
    w(0x52),w(0x3b),w(0xd6),w(0xb3),w(0x29),w(0xe3),w(0x2f),w(0x84), \
    w(0x53),w(0xd1),w(0x00),w(0xed),w(0x20),w(0xfc),w(0xb1),w(0x5b), \
    w(0x6a),w(0xcb),w(0xbe),w(0x39),w(0x4a),w(0x4c),w(0x58),w(0xcf), \
    w(0xd0),w(0xef),w(0xaa),w(0xfb),w(0x43),w(0x4d),w(0x33),w(0x85), \
    w(0x45),w(0xf9),w(0x02),w(0x7f),w(0x50),w(0x3c),w(0x9f),w(0xa8), \
    w(0x51),w(0xa3),w(0x40),w(0x8f),w(0x92),w(0x9d),w(0x38),w(0xf5), \
    w(0xbc),w(0xb6),w(0xda),w(0x21),w(0x10),w(0xff),w(0xf3),w(0xd2), \
    w(0xcd),w(0x0c),w(0x13),w(0xec),w(0x5f),w(0x97),w(0x44),w(0x17), \
    w(0xc4),w(0xa7),w(0x7e),w(0x3d),w(0x64),w(0x5d),w(0x19),w(0x73), \
    w(0x60),w(0x81),w(0x4f),w(0xdc),w(0x22),w(0x2a),w(0x90),w(0x88), \
    w(0x46),w(0xee),w(0xb8),w(0x14),w(0xde),w(0x5e),w(0x0b),w(0xdb), \
    w(0xe0),w(0x32),w(0x3a),w(0x0a),w(0x49),w(0x06),w(0x24),w(0x5c), \
    w(0xc2),w(0xd3),w(0xac),w(0x62),w(0x91),w(0x95),w(0xe4),w(0x79), \
    w(0xe7),w(0xc8),w(0x37),w(0x6d),w(0x8d),w(0xd5),w(0x4e),w(0xa9), \
    w(0x6c),w(0x56),w(0xf4),w(0xea),w(0x65),w(0x7a),w(0xae),w(0x08), \
    w(0xba),w(0x78),w(0x25),w(0x2e),w(0x1c),w(0xa6),w(0xb4),w(0xc6), \
    w(0xe8),w(0xdd),w(0x74),w(0x1f),w(0x4b),w(0xbd),w(0x8b),w(0x8a), \
    w(0x70),w(0x3e),w(0xb5),w(0x66),w(0x48),w(0x03),w(0xf6),w(0x0e), \
    w(0x61),w(0x35),w(0x57),w(0xb9),w(0x86),w(0xc1),w(0x1d),w(0x9e), \
    w(0xe1),w(0xf8),w(0x98),w(0x11),w(0x69),w(0xd9),w(0x8e),w(0x94), \
    w(0x9b),w(0x1e),w(0x87),w(0xe9),w(0xce),w(0x55),w(0x28),w(0xdf), \
    w(0x8c),w(0xa1),w(0x89),w(0x0d),w(0xbf),w(0xe6),w(0x42),w(0x68), \
    w(0x41),w(0x99),w(0x2d),w(0x0f),w(0xb0),w(0x54),w(0xbb),w(0x16) }

#define saes_h0(x) (x)

static const uint32_t saes_table[4][256] = {
    saes_data(saes_u0), saes_data(saes_u1),
    saes_data(saes_u2), saes_data(saes_u3)
};
static const uint8_t saes_sbox[256] = saes_data(saes_h0);

/* ── GR variant parameters ─────────────────────────────────────── */

typedef struct {
    uint32_t memory;      /* scratchpad size in bytes */
    uint32_t iterations;  /* main loop iterations */
    uint32_t mask;        /* address mask */
    int      half_mem;    /* use half-memory optimization */
} cn_variant;

#define CN_ITER 0x80000   /* 524288 */

static const cn_variant gr_variants[6] = {
    /* 0: cn/dark       */ { 0x80000,  CN_ITER / 4, 0x7FFF0,  0 },
    /* 1: cn/dark-lite  */ { 0x80000,  CN_ITER / 4, 0x3FFF0,  1 },
    /* 2: cn/fast       */ { 0x200000, CN_ITER / 2, 0x1FFFF0, 0 },
    /* 3: cn/lite       */ { 0x100000, CN_ITER / 2, 0xFFFF0,  0 },
    /* 4: cn/turtle     */ { 0x40000,  CN_ITER / 8, 0x3FFF0,  0 },
    /* 5: cn/turtle-lite*/ { 0x40000,  CN_ITER / 8, 0x1FFF0,  1 },
};

/* ── AES helpers ───────────────────────────────────────────────── */

static inline uint32_t cn_sub_word(uint32_t w)
{
    return (uint32_t)saes_sbox[w & 0xff]
        | ((uint32_t)saes_sbox[(w >>  8) & 0xff] <<  8)
        | ((uint32_t)saes_sbox[(w >> 16) & 0xff] << 16)
        | ((uint32_t)saes_sbox[(w >> 24)]        << 24);
}

static inline uint32_t cn_rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

/* sl_xor: {a, b, c, d} -> {a, a^b, a^b^c, a^b^c^d} */
static inline void sl_xor(uint32_t x[4])
{
    x[1] ^= x[0];
    x[2] ^= x[1];
    x[3] ^= x[2];
}

/*
 * AES-256 key expansion: 32 bytes -> 10 round keys (each 16 bytes).
 * Matches XMRig's aes_genkey<true>() (soft AES path).
 */
static void cn_aes_genkey(const uint8_t key[32], uint32_t rk[10][4])
{
    uint32_t xout0[4], xout2[4];
    memcpy(xout0, key,      16);
    memcpy(xout2, key + 16, 16);
    memcpy(rk[0], xout0, 16);
    memcpy(rk[1], xout2, 16);

    static const uint8_t rcons[4] = { 0x01, 0x02, 0x04, 0x08 };
    for (int r = 0; r < 4; r++) {
        /* Even key: RotWord(SubWord(xout2[3])) ^ rcon */
        uint32_t assist = cn_rotr32(cn_sub_word(xout2[3]), 8) ^ rcons[r];
        sl_xor(xout0);
        xout0[0] ^= assist;
        xout0[1] ^= assist;
        xout0[2] ^= assist;
        xout0[3] ^= assist;
        memcpy(rk[2 + r * 2], xout0, 16);

        /* Odd key: SubWord(xout0[3]) */
        uint32_t assist2 = cn_sub_word(xout0[3]);
        sl_xor(xout2);
        xout2[0] ^= assist2;
        xout2[1] ^= assist2;
        xout2[2] ^= assist2;
        xout2[3] ^= assist2;
        memcpy(rk[3 + r * 2], xout2, 16);
    }
}

/*
 * Single AES encryption round using T-tables (in-place on 16-byte block).
 * Matches XMRig's soft_aesenc(void* ptr, const void* key, const uint32_t* t).
 */
static inline void cn_aes_round(uint8_t block[16], const uint32_t key[4])
{
    const uint32_t *t = (const uint32_t *)saes_table;
    uint32_t x0 = ((uint32_t *)block)[0];
    uint32_t x1 = ((uint32_t *)block)[1];
    uint32_t x2 = ((uint32_t *)block)[2];
    uint32_t x3 = ((uint32_t *)block)[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;
    t += 256;

    y0 ^= t[x3];
    y1 ^= t[x0];
    y2 ^= t[x1];
    y3 ^= t[x2];

    ((uint32_t *)block)[0] = y0 ^ key[0];
    ((uint32_t *)block)[1] = y1 ^ key[1];
    ((uint32_t *)block)[2] = y2 ^ key[2];
    ((uint32_t *)block)[3] = y3 ^ key[3];
}

/*
 * Single AES round returning result (reads from src, returns in dst).
 * Used in the main loop where cx = aesenc(scratchpad[idx], key).
 */
static inline void cn_aes_round_to(const uint8_t src[16], const uint32_t key[4],
                                   uint8_t dst[16])
{
    const uint32_t *t = (const uint32_t *)saes_table;
    uint32_t x0 = ((const uint32_t *)src)[0];
    uint32_t x1 = ((const uint32_t *)src)[1];
    uint32_t x2 = ((const uint32_t *)src)[2];
    uint32_t x3 = ((const uint32_t *)src)[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;
    t += 256;

    y0 ^= t[x3];
    y1 ^= t[x0];
    y2 ^= t[x1];
    y3 ^= t[x2];

    ((uint32_t *)dst)[0] = y0 ^ key[0];
    ((uint32_t *)dst)[1] = y1 ^ key[1];
    ((uint32_t *)dst)[2] = y2 ^ key[2];
    ((uint32_t *)dst)[3] = y3 ^ key[3];
}

/* Apply 10 AES rounds (in-place) to a single 16-byte block */
static inline void cn_aes_10rounds(uint8_t block[16], const uint32_t rk[10][4])
{
    for (int i = 0; i < 10; i++) {
        cn_aes_round(block, rk[i]);
    }
}

/* ── Explode scratchpad ────────────────────────────────────────── */

/*
 * Fill the scratchpad by encrypting state[64:191] with AES key from state[0:31].
 * 8 blocks (128 bytes) at a time, each getting 10 AES rounds.
 *
 * For half_mem: only fill half the scratchpad (memory/2 bytes).
 * If first_half: save AES state after filling for use in second pass.
 * If !first_half: restore saved AES state before filling.
 */
static void cn_explode_scratchpad(cn_ctx *ctx, const cn_variant *v)
{
    uint32_t rk[10][4];
    cn_aes_genkey(ctx->state, rk);  /* key from state[0:31] */

    size_t N = v->memory / 16;  /* number of 16-byte blocks */
    if (v->half_mem) N /= 2;

    uint8_t blocks[8][16];  /* 8 working blocks */

    if (v->half_mem && !ctx->first_half) {
        /* Restore saved state from first pass */
        memcpy(blocks, ctx->save_state, 128);
    } else {
        /* Initialize from state[64:191] */
        memcpy(blocks, ctx->state + 64, 128);
    }

    uint8_t *out = ctx->memory;
    for (size_t i = 0; i < N; i += 8) {
        for (int b = 0; b < 8; b++) {
            cn_aes_10rounds(blocks[b], rk);
        }
        /* Store blocks 0-3 at offset, blocks 4-7 at offset+64 */
        memcpy(out,      blocks[0], 16);
        memcpy(out + 16, blocks[1], 16);
        memcpy(out + 32, blocks[2], 16);
        memcpy(out + 48, blocks[3], 16);
        memcpy(out + 64, blocks[4], 16);
        memcpy(out + 80, blocks[5], 16);
        memcpy(out + 96, blocks[6], 16);
        memcpy(out +112, blocks[7], 16);
        out += 128;
    }

    if (v->half_mem && ctx->first_half) {
        /* Save AES state for second pass during implode */
        memcpy(ctx->save_state, blocks, 128);
    }
}

/* ── Implode scratchpad ────────────────────────────────────────── */

/*
 * Compress scratchpad back into state[64:191].
 * XOR scratchpad blocks into working state, apply 10 AES rounds.
 * AES key comes from state[32:63].
 *
 * For half_mem: process first half, then re-explode second half and process that.
 */
static void cn_implode_scratchpad(cn_ctx *ctx, const cn_variant *v)
{
    uint32_t rk[10][4];
    cn_aes_genkey(ctx->state + 32, rk);  /* key from state[32:63] */

    size_t N = v->memory / 16;
    if (v->half_mem) N /= 2;

    /* Initialize xout from state[64:191] */
    uint8_t xout[8][16];
    memcpy(xout, ctx->state + 64, 128);

    const uint8_t *inp = ctx->memory;

    int num_passes = v->half_mem ? 2 : 1;
    for (int pass = 0; pass < num_passes; pass++) {
        if (v->half_mem && pass == 1) {
            /* Re-explode the second half of the scratchpad */
            inp = ctx->memory;  /* reset to beginning */
            ctx->first_half = 0;
            cn_explode_scratchpad(ctx, v);
        }

        for (size_t i = 0; i < N; i += 8) {
            /* XOR scratchpad blocks into working blocks */
            for (int b = 0; b < 8; b++) {
                uint64_t *xp = (uint64_t *)xout[b];
                const uint64_t *ip = (const uint64_t *)(inp + b * 16);
                xp[0] ^= ip[0];
                xp[1] ^= ip[1];
            }
            inp += 128;

            /* Apply 10 AES rounds */
            for (int b = 0; b < 8; b++) {
                cn_aes_10rounds(xout[b], rk);
            }
        }
    }

    /* Store result back to state[64:191] */
    memcpy(ctx->state + 64, xout, 128);
}

/* ── 128-bit multiply ──────────────────────────────────────────── */

static inline uint64_t cn_umul128(uint64_t a, uint64_t b, uint64_t *hi)
{
#ifdef __SIZEOF_INT128__
    __uint128_t r = (__uint128_t)a * b;
    *hi = (uint64_t)(r >> 64);
    return (uint64_t)r;
#else
    /* Portable 64×64 → 128 multiply */
    uint64_t a_lo = (uint32_t)a, a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b, b_hi = b >> 32;
    uint64_t p0 = a_lo * b_lo;
    uint64_t p1 = a_lo * b_hi;
    uint64_t p2 = a_hi * b_lo;
    uint64_t p3 = a_hi * b_hi;
    uint64_t mid = p1 + (p0 >> 32);
    uint64_t carry = (uint64_t)((uint32_t)mid < (uint32_t)p1);
    mid += p2;
    carry += (mid < p2);
    *hi = p3 + (mid >> 32) + (carry << 32);
    return (p0 & 0xFFFFFFFF) | (mid << 32);
#endif
}

/* ── Extra hashes (final step: blake256 / groestl / jh256 / skein256) ── */

static void cn_extra_blake(const uint8_t *input, size_t len, uint8_t *output)
{
    (void)len;
    blake256_hash(output, input, len);
}

static void cn_extra_groestl(const uint8_t *input, size_t len, uint8_t *output)
{
    groestl(input, len * 8, output);
}

static void cn_extra_jh(const uint8_t *input, size_t len, uint8_t *output)
{
    (void)len;
    jh_hash(32 * 8, input, 8 * len, output);
}

static void cn_extra_skein(const uint8_t *input, size_t len, uint8_t *output)
{
    (void)len;
    xmr_skein(input, output);
}

typedef void (*extra_hash_fn)(const uint8_t *, size_t, uint8_t *);
static const extra_hash_fn extra_hashes[4] = {
    cn_extra_blake, cn_extra_groestl, cn_extra_jh, cn_extra_skein
};

/* ── Context allocation ────────────────────────────────────────── */

cn_ctx *cn_alloc_ctx(void)
{
    cn_ctx *ctx = (cn_ctx *)calloc(1, sizeof(cn_ctx));
    if (!ctx) return NULL;

    /* Allocate 2MB scratchpad, 16-byte aligned */
#if defined(_WIN32)
    ctx->memory = (uint8_t *)_aligned_malloc(CN_MAX_MEMORY, 16);
#else
    if (posix_memalign((void **)&ctx->memory, 16, CN_MAX_MEMORY) != 0) {
        free(ctx);
        return NULL;
    }
#endif
    return ctx;
}

void cn_free_ctx(cn_ctx *ctx)
{
    if (!ctx) return;
#if defined(_WIN32)
    _aligned_free(ctx->memory);
#else
    free(ctx->memory);
#endif
    free(ctx);
}

/* ── Main CryptoNight hash function ────────────────────────────── */

void cryptonight_hash(const uint8_t *input, size_t size,
                      uint8_t *output, cn_ctx *ctx, int variant)
{
    if (variant < 0 || variant > 5) {
        memset(output, 0, 32);
        return;
    }

    const cn_variant *v = &gr_variants[variant];

    /* Step 1: Keccak-1600 → 200-byte state */
    gr_keccak(input, (int)size, ctx->state, 200);

    /* Step 2: Monero V7 tweak init */
    /* tweak1_2 = *(uint64_t*)(input+35) ^ state_u64[24] */
    uint64_t tweak1_2;
    memcpy(&tweak1_2, input + 35, 8);
    tweak1_2 ^= ((uint64_t *)ctx->state)[24];

    /* Step 3: Explode scratchpad */
    if (v->half_mem) {
        ctx->first_half = 1;
    }
    cn_explode_scratchpad(ctx, v);

    /* Step 4: Main loop */
    uint64_t *h = (uint64_t *)ctx->state;
    uint8_t *l = ctx->memory;
    const uint32_t mask = v->mask;

    uint64_t al0 = h[0] ^ h[4];
    uint64_t ah0 = h[1] ^ h[5];
    uint64_t idx0 = al0;

    /* bx0 = (h[2]^h[6], h[3]^h[7]) as 128-bit value */
    uint64_t bx0_lo = h[2] ^ h[6];
    uint64_t bx0_hi = h[3] ^ h[7];

    for (uint32_t i = 0; i < v->iterations; i++) {
        /* cx = aesenc(scratchpad[idx0 & mask], key=(al0, ah0)) */
        uint8_t cx[16];
        uint32_t aes_key[4];
        memcpy(aes_key, &al0, 8);
        memcpy(aes_key + 2, &ah0, 8);
        cn_aes_round_to(&l[idx0 & mask], aes_key, cx);

        /* Store bx0 ^ cx at old address, with V1 tweak */
        {
            uint64_t cx_lo, cx_hi;
            memcpy(&cx_lo, cx, 8);
            memcpy(&cx_hi, cx + 8, 8);
            uint64_t store_lo = bx0_lo ^ cx_lo;
            uint64_t store_hi = bx0_hi ^ cx_hi;

            /* VARIANT1_1: tweak byte 11 of the stored block */
            /* Byte 11 = byte 3 of store_hi (little-endian uint64_t) */
            {
                uint8_t *store_bytes = (uint8_t *)&store_hi;
                uint8_t tmp = store_bytes[3];  /* byte 11 of 16-byte block */
                uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1;
                store_bytes[3] = tmp ^ ((0x75310 >> index) & 0x30);
            }

            memcpy(&l[idx0 & mask], &store_lo, 8);
            memcpy(&l[(idx0 & mask) + 8], &store_hi, 8);
        }

        /* idx0 = low 64 bits of cx */
        memcpy(&idx0, cx, 8);

        /* Read (cl, ch) from new address */
        uint64_t cl, ch;
        memcpy(&cl, &l[idx0 & mask], 8);
        memcpy(&ch, &l[(idx0 & mask) + 8], 8);

        /* 128-bit multiply: (hi, lo) = idx0 * cl */
        uint64_t hi_mul, lo_mul;
        lo_mul = cn_umul128(idx0, cl, &hi_mul);

        /* Update a registers */
        al0 += hi_mul;
        ah0 += lo_mul;

        /* Store (al0, ah0 ^ tweak1_2) at new address */
        memcpy(&l[idx0 & mask], &al0, 8);
        uint64_t store_ah = ah0 ^ tweak1_2;
        memcpy(&l[(idx0 & mask) + 8], &store_ah, 8);

        /* XOR and update */
        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        /* Update bx0 = cx */
        memcpy(&bx0_lo, cx, 8);
        memcpy(&bx0_hi, cx + 8, 8);
    }

    /* Step 5: Implode scratchpad */
    cn_implode_scratchpad(ctx, v);

    /* Step 6: Keccak-f[1600] permutation */
    gr_keccakf((uint64_t *)ctx->state, 24);

    /* Step 7: Final hash (blake256/groestl/jh256/skein256) */
    extra_hashes[ctx->state[0] & 3](ctx->state, 200, output);
}
