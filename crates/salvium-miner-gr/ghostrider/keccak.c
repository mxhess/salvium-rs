/*
 * Keccak-f[1600] and keccak hash — pure C port from XMRig.
 *
 * Original: xmrig/src/base/crypto/keccak.cpp
 * Authors: Jeff Garzik, Markku-Juhani O. Saarinen, pooler, XMRig team.
 * License: GPL-3.0+
 */

#include "keccak.h"
#include <string.h>

#define HASH_DATA_AREA 136
#define KECCAK_ROUNDS  24

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

void gr_keccakf(uint64_t st[25], int rounds)
{
    for (int round = 0; round < rounds; ++round) {
        uint64_t bc[5];

        /* Theta */
        bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

#define X(i) do { \
            const uint64_t t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1); \
            st[i     ] ^= t; \
            st[i +  5] ^= t; \
            st[i + 10] ^= t; \
            st[i + 15] ^= t; \
            st[i + 20] ^= t; \
        } while(0)

        X(0); X(1); X(2); X(3); X(4);
#undef X

        /* Rho Pi */
        {
            const uint64_t t = st[1];
            st[ 1] = ROTL64(st[ 6], 44);
            st[ 6] = ROTL64(st[ 9], 20);
            st[ 9] = ROTL64(st[22], 61);
            st[22] = ROTL64(st[14], 39);
            st[14] = ROTL64(st[20], 18);
            st[20] = ROTL64(st[ 2], 62);
            st[ 2] = ROTL64(st[12], 43);
            st[12] = ROTL64(st[13], 25);
            st[13] = ROTL64(st[19],  8);
            st[19] = ROTL64(st[23], 56);
            st[23] = ROTL64(st[15], 41);
            st[15] = ROTL64(st[ 4], 27);
            st[ 4] = ROTL64(st[24], 14);
            st[24] = ROTL64(st[21],  2);
            st[21] = ROTL64(st[ 8], 55);
            st[ 8] = ROTL64(st[16], 45);
            st[16] = ROTL64(st[ 5], 36);
            st[ 5] = ROTL64(st[ 3], 28);
            st[ 3] = ROTL64(st[18], 21);
            st[18] = ROTL64(st[17], 15);
            st[17] = ROTL64(st[11], 10);
            st[11] = ROTL64(st[ 7],  6);
            st[ 7] = ROTL64(st[10],  3);
            st[10] = ROTL64(t, 1);
        }

        /* Chi — unrolled 5 groups */
        {
            int j;

            j = 0;
            bc[0] = st[j]; bc[1] = st[j+1];
            st[j  ] ^= (~st[j+1]) & st[j+2];
            st[j+1] ^= (~st[j+2]) & st[j+3];
            st[j+2] ^= (~st[j+3]) & st[j+4];
            st[j+3] ^= (~st[j+4]) & bc[0];
            st[j+4] ^= (~bc[0])   & bc[1];

            j = 5;
            bc[0] = st[j]; bc[1] = st[j+1];
            st[j  ] ^= (~st[j+1]) & st[j+2];
            st[j+1] ^= (~st[j+2]) & st[j+3];
            st[j+2] ^= (~st[j+3]) & st[j+4];
            st[j+3] ^= (~st[j+4]) & bc[0];
            st[j+4] ^= (~bc[0])   & bc[1];

            j = 10;
            bc[0] = st[j]; bc[1] = st[j+1];
            st[j  ] ^= (~st[j+1]) & st[j+2];
            st[j+1] ^= (~st[j+2]) & st[j+3];
            st[j+2] ^= (~st[j+3]) & st[j+4];
            st[j+3] ^= (~st[j+4]) & bc[0];
            st[j+4] ^= (~bc[0])   & bc[1];

            j = 15;
            bc[0] = st[j]; bc[1] = st[j+1];
            st[j  ] ^= (~st[j+1]) & st[j+2];
            st[j+1] ^= (~st[j+2]) & st[j+3];
            st[j+2] ^= (~st[j+3]) & st[j+4];
            st[j+3] ^= (~st[j+4]) & bc[0];
            st[j+4] ^= (~bc[0])   & bc[1];

            j = 20;
            bc[0] = st[j]; bc[1] = st[j+1]; bc[2] = st[j+2];
            bc[3] = st[j+3]; bc[4] = st[j+4];
            st[j  ] ^= (~bc[1]) & bc[2];
            st[j+1] ^= (~bc[2]) & bc[3];
            st[j+2] ^= (~bc[3]) & bc[4];
            st[j+3] ^= (~bc[4]) & bc[0];
            st[j+4] ^= (~bc[0]) & bc[1];
        }

        /* Iota */
        st[0] ^= keccakf_rndc[round];
    }
}

typedef uint64_t state_t[25];

void gr_keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen)
{
    state_t st;
    uint8_t temp[144] __attribute__((aligned(8)));
    int i, rsiz, rsizw;

    rsiz = (int)sizeof(state_t) == mdlen ? HASH_DATA_AREA : 200 - 2 * mdlen;
    rsizw = rsiz / 8;

    memset(st, 0, sizeof(st));

    for ( ; inlen >= rsiz; inlen -= rsiz, in += rsiz) {
        for (i = 0; i < rsizw; i++) {
            st[i] ^= ((const uint64_t *)in)[i];
        }
        gr_keccakf(st, KECCAK_ROUNDS);
    }

    /* last block and padding */
    memcpy(temp, in, (size_t)inlen);
    temp[inlen++] = 1;
    memset(temp + inlen, 0, (size_t)(rsiz - inlen));
    temp[rsiz - 1] |= 0x80;

    for (i = 0; i < rsizw; i++) {
        st[i] ^= ((uint64_t *)temp)[i];
    }

    gr_keccakf(st, KECCAK_ROUNDS);

    memcpy(md, st, (size_t)mdlen);
}
