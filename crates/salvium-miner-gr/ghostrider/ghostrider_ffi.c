/*
 * GhostRider hash — full C implementation with CryptoNight integration.
 *
 * 3-part pipeline: each part chains 5 SPH-512 core hashes followed by
 * 1 CryptoNight memory-hard round.  Algorithm selection order is determined
 * by the seed (input[4:36] = PrevBlockHash).
 *
 * Reference: XMRig src/crypto/ghostrider/ghostrider.cpp
 */

#include "ghostrider_ffi.h"
#include "cryptonight.h"

#include "sph_blake.h"
#include "sph_bmw.h"
#include "sph_groestl.h"
#include "sph_jh.h"
#include "sph_keccak.h"
#include "sph_skein.h"
#include "sph_luffa.h"
#include "sph_cubehash.h"
#include "sph_shavite.h"
#include "sph_simd.h"
#include "sph_echo.h"
#include "sph_hamsi.h"
#include "sph_fugue.h"
#include "sph_shabal.h"
#include "sph_whirlpool.h"

#include <string.h>
#include <stdlib.h>

/* 15 core hash functions, matching XMRig's GhostRider order */
#define NUM_CORE_HASHES 15

/* Number of CryptoNight variants used in GhostRider */
#define NUM_CN_VARIANTS 6

/* 64-byte intermediate hash buffer (all SPH-512 hashes produce 64 bytes) */
#define HASH_BUF_SIZE 64

/* ---- SPH-512 core hash wrappers ---- */

static void hash_blake512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_blake512_context ctx;
    sph_blake512_init(&ctx);
    sph_blake512(&ctx, data, len);
    sph_blake512_close(&ctx, out);
}

static void hash_bmw512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_bmw512_context ctx;
    sph_bmw512_init(&ctx);
    sph_bmw512(&ctx, data, len);
    sph_bmw512_close(&ctx, out);
}

static void hash_groestl512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_groestl512_context ctx;
    sph_groestl512_init(&ctx);
    sph_groestl512(&ctx, data, len);
    sph_groestl512_close(&ctx, out);
}

static void hash_jh512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_jh512_context ctx;
    sph_jh512_init(&ctx);
    sph_jh512(&ctx, data, len);
    sph_jh512_close(&ctx, out);
}

static void hash_keccak512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_keccak512_context ctx;
    sph_keccak512_init(&ctx);
    sph_keccak512(&ctx, data, len);
    sph_keccak512_close(&ctx, out);
}

static void hash_skein512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_skein512_context ctx;
    sph_skein512_init(&ctx);
    sph_skein512(&ctx, data, len);
    sph_skein512_close(&ctx, out);
}

static void hash_luffa512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_luffa512_context ctx;
    sph_luffa512_init(&ctx);
    sph_luffa512(&ctx, data, len);
    sph_luffa512_close(&ctx, out);
}

static void hash_cubehash512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_cubehash512_context ctx;
    sph_cubehash512_init(&ctx);
    sph_cubehash512(&ctx, data, len);
    sph_cubehash512_close(&ctx, out);
}

static void hash_shavite512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_shavite512_context ctx;
    sph_shavite512_init(&ctx);
    sph_shavite512(&ctx, data, len);
    sph_shavite512_close(&ctx, out);
}

static void hash_simd512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_simd512_context ctx;
    sph_simd512_init(&ctx);
    sph_simd512(&ctx, data, len);
    sph_simd512_close(&ctx, out);
}

static void hash_echo512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_echo512_context ctx;
    sph_echo512_init(&ctx);
    sph_echo512(&ctx, data, len);
    sph_echo512_close(&ctx, out);
}

static void hash_hamsi512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_hamsi512_context ctx;
    sph_hamsi512_init(&ctx);
    sph_hamsi512(&ctx, data, len);
    sph_hamsi512_close(&ctx, out);
}

static void hash_fugue512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_fugue512_context ctx;
    sph_fugue512_init(&ctx);
    sph_fugue512(&ctx, data, len);
    sph_fugue512_close(&ctx, out);
}

static void hash_shabal512(const uint8_t* data, size_t len, uint8_t* out) {
    sph_shabal512_context ctx;
    sph_shabal512_init(&ctx);
    sph_shabal512(&ctx, data, len);
    sph_shabal512_close(&ctx, out);
}

static void hash_whirlpool(const uint8_t* data, size_t len, uint8_t* out) {
    sph_whirlpool_context ctx;
    sph_whirlpool_init(&ctx);
    sph_whirlpool(&ctx, data, len);
    sph_whirlpool_close(&ctx, out);
}

typedef void (*core_hash_fn)(const uint8_t*, size_t, uint8_t*);

static const core_hash_fn core_hashes[NUM_CORE_HASHES] = {
    hash_blake512,     /*  0 */
    hash_bmw512,       /*  1 */
    hash_groestl512,   /*  2 */
    hash_jh512,        /*  3 */
    hash_keccak512,    /*  4 */
    hash_skein512,     /*  5 */
    hash_luffa512,     /*  6 */
    hash_cubehash512,  /*  7 */
    hash_shavite512,   /*  8 */
    hash_simd512,      /*  9 */
    hash_echo512,      /* 10 */
    hash_hamsi512,     /* 11 */
    hash_fugue512,     /* 12 */
    hash_shabal512,    /* 13 */
    hash_whirlpool,    /* 14 */
};

/* ---- Index selection (matching XMRig ghostrider.cpp select_indices) ---- */

/*
 * Select a permutation of N indices from 32-byte seed.
 * Iterates through 64 nibbles of the seed; each nibble % N gives a
 * candidate index.  First occurrence of each index is kept.  Any
 * indices not selected after 64 nibbles are appended in order.
 */
static void select_indices(uint32_t *indices, uint32_t n, const uint8_t *seed)
{
    uint8_t selected[16] = {0};  /* max N is 15 */
    uint32_t k = 0;

    for (uint32_t i = 0; i < 64 && k < n; i++) {
        const uint8_t nibble = (seed[i / 2] >> ((i & 1) * 4)) & 0x0F;
        const uint8_t index = nibble % n;
        if (!selected[index]) {
            selected[index] = 1;
            indices[k++] = index;
        }
    }

    /* Fill any remaining unselected indices in order */
    for (uint32_t i = 0; i < n && k < n; i++) {
        if (!selected[i]) {
            indices[k++] = i;
        }
    }
}

/* ---- Context management ---- */

void *ghostrider_alloc_ctx(void)
{
    return cn_alloc_ctx();
}

void ghostrider_free_ctx(void *ctx)
{
    cn_free_ctx((cn_ctx *)ctx);
}

/* ---- Full GhostRider hash ---- */

int ghostrider_hash(const uint8_t *input, size_t input_len,
                    uint8_t *output, void *ctx)
{
    if (!input || !output || !ctx || input_len < 43) {
        return -1;
    }

    /* Seed is the PrevBlockHash at input[4..36] */
    const uint8_t *seed = input + 4;

    /* Select permutation for 15 core hashes and 6 CN variants */
    uint32_t core_indices[NUM_CORE_HASHES];
    uint32_t cn_indices[NUM_CN_VARIANTS];
    select_indices(core_indices, NUM_CORE_HASHES, seed);
    select_indices(cn_indices, NUM_CN_VARIANTS, seed);

    uint8_t tmp[HASH_BUF_SIZE];
    const uint8_t *data = input;
    size_t data_size = input_len;

    /* 3-part pipeline: each part = 5 SPH core hashes + 1 CryptoNight hash */
    for (int part = 0; part < 3; part++) {
        /* Chain 5 SPH-512 core hashes */
        for (int i = 0; i < 5; i++) {
            uint8_t next[HASH_BUF_SIZE];
            core_hashes[core_indices[part * 5 + i]](data, data_size, next);
            memcpy(tmp, next, HASH_BUF_SIZE);
            data = tmp;
            data_size = HASH_BUF_SIZE;
        }

        /* 1 CryptoNight hash: 64 bytes in → 32 bytes out */
        cryptonight_hash(tmp, HASH_BUF_SIZE, output, (cn_ctx *)ctx,
                         (int)cn_indices[part]);

        /* Prepare input for next part: 32 bytes of CN output + 32 zero bytes */
        memcpy(tmp, output, 32);
        memset(tmp + 32, 0, 32);
        data = tmp;
        data_size = HASH_BUF_SIZE;
    }

    return 0;
}

/* ---- Individual SPH hash (for testing) ---- */

int ghostrider_sph_hash(int algo_index, const uint8_t *input,
                        size_t input_len, uint8_t *output)
{
    if (algo_index < 0 || algo_index >= NUM_CORE_HASHES || !input || !output) {
        return -1;
    }
    core_hashes[algo_index](input, input_len, output);
    return 0;
}
