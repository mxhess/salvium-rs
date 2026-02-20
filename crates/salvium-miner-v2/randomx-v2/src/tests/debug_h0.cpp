/**
 * Debug H0 computation for RandomX Argon2
 */

#include <cstdio>
#include <cstring>
#include "../argon2.h"
#include "../argon2_core.h"
#include "../blake2/blake2.h"
#include "../blake2/endian.h"
#include "../configuration.h"
#include "../common.hpp"

void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    const char* key = "test key 000";
    size_t keySize = strlen(key);

    printf("=== Debug RandomX H0 computation ===\n\n");
    printf("Key: %s (%zu bytes)\n", key, keySize);
    printf("Salt: RandomX\\x03 (%d bytes)\n", (int)randomx::ArgonSaltSize);
    printf("\n");

    // Set up Argon2 context exactly as RandomX does
    argon2_context context;
    context.out = nullptr;
    context.outlen = 0;
    context.pwd = (uint8_t*)key;
    context.pwdlen = (uint32_t)keySize;
    context.salt = (uint8_t*)RANDOMX_ARGON_SALT;
    context.saltlen = (uint32_t)randomx::ArgonSaltSize;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = RANDOMX_ARGON_ITERATIONS;
    context.m_cost = RANDOMX_ARGON_MEMORY;
    context.lanes = RANDOMX_ARGON_LANES;
    context.threads = 1;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = ARGON2_VERSION_NUMBER;

    printf("Parameters:\n");
    printf("  lanes: %u\n", context.lanes);
    printf("  outlen: %u\n", context.outlen);
    printf("  m_cost: %u\n", context.m_cost);
    printf("  t_cost: %u\n", context.t_cost);
    printf("  version: 0x%x\n", context.version);
    printf("  type: 0 (Argon2d)\n");
    printf("  pwdlen: %u\n", context.pwdlen);
    printf("  saltlen: %u\n", context.saltlen);
    printf("\n");

    // Manually compute H0 input
    printf("=== Manual H0 input construction ===\n");
    uint8_t h0Input[256];
    size_t offset = 0;

    // Store parameters in little-endian
    store32(h0Input + offset, context.lanes); offset += 4;
    store32(h0Input + offset, context.outlen); offset += 4;
    store32(h0Input + offset, context.m_cost); offset += 4;
    store32(h0Input + offset, context.t_cost); offset += 4;
    store32(h0Input + offset, context.version); offset += 4;
    store32(h0Input + offset, 0); offset += 4;  // type = Argon2d = 0
    store32(h0Input + offset, context.pwdlen); offset += 4;
    memcpy(h0Input + offset, context.pwd, context.pwdlen); offset += context.pwdlen;
    store32(h0Input + offset, context.saltlen); offset += 4;
    memcpy(h0Input + offset, context.salt, context.saltlen); offset += context.saltlen;
    store32(h0Input + offset, context.secretlen); offset += 4;
    store32(h0Input + offset, context.adlen); offset += 4;

    printf("H0 input (%zu bytes):\n", offset);
    printHex(h0Input, offset);
    printf("\n");

    // Compute H0 using blake2b
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    blake2b(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, h0Input, offset, NULL, 0);

    printf("H0 (64 bytes):\n");
    printHex(blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
    printf("\n");

    // Compute block 0
    printf("\n=== Block 0 computation ===\n");
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);  // position = 0
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, 0);  // lane = 0

    printf("Seed (72 bytes):\n");
    printHex(blockhash, ARGON2_PREHASH_SEED_LENGTH);
    printf("\n");

    uint8_t block0[ARGON2_BLOCK_SIZE];
    blake2b_long(block0, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);

    printf("Block 0 first 64 bytes:\n");
    printHex(block0, 64);
    printf("\n");

    // Read first qword
    uint64_t firstQword = load64(block0);
    printf("cacheMemory[0]: 0x%016lx\n", firstQword);
    printf("Expected:       0x191e0e1d23c02186\n");
    printf("Match: %s\n", firstQword == 0x191e0e1d23c02186ULL ? "YES" : "NO");

    return 0;
}
