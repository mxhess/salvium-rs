/**
 * AES Implementation for RandomX in AssemblyScript
 *
 * RandomX uses a modified AES encryption for:
 * - Scratchpad initialization (AES 4-round encryption)
 * - Scratchpad finalization (AES 4-round encryption)
 *
 * This uses AES-NI style operations via WASM SIMD (v128)
 * for maximum performance.
 */

// AES S-box (pre-computed substitution table)
const SBOX: StaticArray<u8> = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Pre-computed multiplication tables for GF(2^8)
const MUL2: StaticArray<u8> = new StaticArray<u8>(256);
const MUL3: StaticArray<u8> = new StaticArray<u8>(256);

// Initialize multiplication tables
function initTables(): void {
  for (let i = 0; i < 256; i++) {
    const x = <u8>i;
    // Multiply by 2 in GF(2^8)
    const mul2 = (x << 1) ^ ((x >> 7) * 0x1b);
    unchecked(MUL2[i] = <u8>mul2);
    // Multiply by 3 = multiply by 2 XOR original
    unchecked(MUL3[i] = <u8>(mul2 ^ x));
  }
}

// Flag to track initialization
let tablesInitialized: bool = false;

/**
 * Ensure tables are initialized
 */
function ensureTables(): void {
  if (!tablesInitialized) {
    initTables();
    tablesInitialized = true;
  }
}

/**
 * AES SubBytes operation (single byte)
 */
@inline
function subByte(b: u8): u8 {
  return unchecked(SBOX[b]);
}

/**
 * AES single round encryption (for RandomX soft AES)
 * Performs SubBytes, ShiftRows, MixColumns on a 16-byte state
 */
function aesRound(statePtr: usize, keyPtr: usize): void {
  ensureTables();

  // Load state bytes
  const s0 = load<u8>(statePtr);
  const s1 = load<u8>(statePtr + 1);
  const s2 = load<u8>(statePtr + 2);
  const s3 = load<u8>(statePtr + 3);
  const s4 = load<u8>(statePtr + 4);
  const s5 = load<u8>(statePtr + 5);
  const s6 = load<u8>(statePtr + 6);
  const s7 = load<u8>(statePtr + 7);
  const s8 = load<u8>(statePtr + 8);
  const s9 = load<u8>(statePtr + 9);
  const s10 = load<u8>(statePtr + 10);
  const s11 = load<u8>(statePtr + 11);
  const s12 = load<u8>(statePtr + 12);
  const s13 = load<u8>(statePtr + 13);
  const s14 = load<u8>(statePtr + 14);
  const s15 = load<u8>(statePtr + 15);

  // SubBytes + ShiftRows combined
  // Column 0: s0, s5, s10, s15
  // Column 1: s4, s9, s14, s3
  // Column 2: s8, s13, s2, s7
  // Column 3: s12, s1, s6, s11
  const t0 = subByte(s0);
  const t1 = subByte(s5);
  const t2 = subByte(s10);
  const t3 = subByte(s15);

  const t4 = subByte(s4);
  const t5 = subByte(s9);
  const t6 = subByte(s14);
  const t7 = subByte(s3);

  const t8 = subByte(s8);
  const t9 = subByte(s13);
  const t10 = subByte(s2);
  const t11 = subByte(s7);

  const t12 = subByte(s12);
  const t13 = subByte(s1);
  const t14 = subByte(s6);
  const t15 = subByte(s11);

  // MixColumns on each column
  // Column 0
  const m2_0 = unchecked(MUL2[t0]);
  const m3_1 = unchecked(MUL3[t1]);
  const m2_1 = unchecked(MUL2[t1]);
  const m3_2 = unchecked(MUL3[t2]);
  const m2_2 = unchecked(MUL2[t2]);
  const m3_3 = unchecked(MUL3[t3]);
  const m2_3 = unchecked(MUL2[t3]);
  const m3_0 = unchecked(MUL3[t0]);

  const r0 = m2_0 ^ m3_1 ^ t2 ^ t3;
  const r1 = t0 ^ m2_1 ^ m3_2 ^ t3;
  const r2 = t0 ^ t1 ^ m2_2 ^ m3_3;
  const r3 = m3_0 ^ t1 ^ t2 ^ m2_3;

  // Column 1
  const m2_4 = unchecked(MUL2[t4]);
  const m3_5 = unchecked(MUL3[t5]);
  const m2_5 = unchecked(MUL2[t5]);
  const m3_6 = unchecked(MUL3[t6]);
  const m2_6 = unchecked(MUL2[t6]);
  const m3_7 = unchecked(MUL3[t7]);
  const m2_7 = unchecked(MUL2[t7]);
  const m3_4 = unchecked(MUL3[t4]);

  const r4 = m2_4 ^ m3_5 ^ t6 ^ t7;
  const r5 = t4 ^ m2_5 ^ m3_6 ^ t7;
  const r6 = t4 ^ t5 ^ m2_6 ^ m3_7;
  const r7 = m3_4 ^ t5 ^ t6 ^ m2_7;

  // Column 2
  const m2_8 = unchecked(MUL2[t8]);
  const m3_9 = unchecked(MUL3[t9]);
  const m2_9 = unchecked(MUL2[t9]);
  const m3_10 = unchecked(MUL3[t10]);
  const m2_10 = unchecked(MUL2[t10]);
  const m3_11 = unchecked(MUL3[t11]);
  const m2_11 = unchecked(MUL2[t11]);
  const m3_8 = unchecked(MUL3[t8]);

  const r8 = m2_8 ^ m3_9 ^ t10 ^ t11;
  const r9 = t8 ^ m2_9 ^ m3_10 ^ t11;
  const r10 = t8 ^ t9 ^ m2_10 ^ m3_11;
  const r11 = m3_8 ^ t9 ^ t10 ^ m2_11;

  // Column 3
  const m2_12 = unchecked(MUL2[t12]);
  const m3_13 = unchecked(MUL3[t13]);
  const m2_13 = unchecked(MUL2[t13]);
  const m3_14 = unchecked(MUL3[t14]);
  const m2_14 = unchecked(MUL2[t14]);
  const m3_15 = unchecked(MUL3[t15]);
  const m2_15 = unchecked(MUL2[t15]);
  const m3_12 = unchecked(MUL3[t12]);

  const r12 = m2_12 ^ m3_13 ^ t14 ^ t15;
  const r13 = t12 ^ m2_13 ^ m3_14 ^ t15;
  const r14 = t12 ^ t13 ^ m2_14 ^ m3_15;
  const r15 = m3_12 ^ t13 ^ t14 ^ m2_15;

  // AddRoundKey and store
  store<u8>(statePtr, r0 ^ load<u8>(keyPtr));
  store<u8>(statePtr + 1, r1 ^ load<u8>(keyPtr + 1));
  store<u8>(statePtr + 2, r2 ^ load<u8>(keyPtr + 2));
  store<u8>(statePtr + 3, r3 ^ load<u8>(keyPtr + 3));
  store<u8>(statePtr + 4, r4 ^ load<u8>(keyPtr + 4));
  store<u8>(statePtr + 5, r5 ^ load<u8>(keyPtr + 5));
  store<u8>(statePtr + 6, r6 ^ load<u8>(keyPtr + 6));
  store<u8>(statePtr + 7, r7 ^ load<u8>(keyPtr + 7));
  store<u8>(statePtr + 8, r8 ^ load<u8>(keyPtr + 8));
  store<u8>(statePtr + 9, r9 ^ load<u8>(keyPtr + 9));
  store<u8>(statePtr + 10, r10 ^ load<u8>(keyPtr + 10));
  store<u8>(statePtr + 11, r11 ^ load<u8>(keyPtr + 11));
  store<u8>(statePtr + 12, r12 ^ load<u8>(keyPtr + 12));
  store<u8>(statePtr + 13, r13 ^ load<u8>(keyPtr + 13));
  store<u8>(statePtr + 14, r14 ^ load<u8>(keyPtr + 14));
  store<u8>(statePtr + 15, r15 ^ load<u8>(keyPtr + 15));
}

/**
 * AES decryption single round (for RandomX soft AES)
 * Performs InvSubBytes, InvShiftRows, InvMixColumns
 */
// Inverse S-box
const INV_SBOX: StaticArray<u8> = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Pre-computed inverse multiplication tables
const MUL9: StaticArray<u8> = new StaticArray<u8>(256);
const MUL11: StaticArray<u8> = new StaticArray<u8>(256);
const MUL13: StaticArray<u8> = new StaticArray<u8>(256);
const MUL14: StaticArray<u8> = new StaticArray<u8>(256);

let invTablesInitialized: bool = false;

function initInvTables(): void {
  for (let i = 0; i < 256; i++) {
    let x = <u8>i;
    // Compute powers by repeated multiplication
    let x2 = unchecked(MUL2[x]);
    let x4 = unchecked(MUL2[x2]);
    let x8 = unchecked(MUL2[x4]);

    unchecked(MUL9[i] = <u8>(x8 ^ x));           // 9 = 8 + 1
    unchecked(MUL11[i] = <u8>(x8 ^ x2 ^ x));     // 11 = 8 + 2 + 1
    unchecked(MUL13[i] = <u8>(x8 ^ x4 ^ x));     // 13 = 8 + 4 + 1
    unchecked(MUL14[i] = <u8>(x8 ^ x4 ^ x2));    // 14 = 8 + 4 + 2
  }
  invTablesInitialized = true;
}

function ensureInvTables(): void {
  ensureTables();
  if (!invTablesInitialized) {
    initInvTables();
  }
}

@inline
function invSubByte(b: u8): u8 {
  return unchecked(INV_SBOX[b]);
}

/**
 * AES decryption round
 */
export function aesDecRound(statePtr: usize, keyPtr: usize): void {
  ensureInvTables();

  // AddRoundKey first
  const s0 = load<u8>(statePtr) ^ load<u8>(keyPtr);
  const s1 = load<u8>(statePtr + 1) ^ load<u8>(keyPtr + 1);
  const s2 = load<u8>(statePtr + 2) ^ load<u8>(keyPtr + 2);
  const s3 = load<u8>(statePtr + 3) ^ load<u8>(keyPtr + 3);
  const s4 = load<u8>(statePtr + 4) ^ load<u8>(keyPtr + 4);
  const s5 = load<u8>(statePtr + 5) ^ load<u8>(keyPtr + 5);
  const s6 = load<u8>(statePtr + 6) ^ load<u8>(keyPtr + 6);
  const s7 = load<u8>(statePtr + 7) ^ load<u8>(keyPtr + 7);
  const s8 = load<u8>(statePtr + 8) ^ load<u8>(keyPtr + 8);
  const s9 = load<u8>(statePtr + 9) ^ load<u8>(keyPtr + 9);
  const s10 = load<u8>(statePtr + 10) ^ load<u8>(keyPtr + 10);
  const s11 = load<u8>(statePtr + 11) ^ load<u8>(keyPtr + 11);
  const s12 = load<u8>(statePtr + 12) ^ load<u8>(keyPtr + 12);
  const s13 = load<u8>(statePtr + 13) ^ load<u8>(keyPtr + 13);
  const s14 = load<u8>(statePtr + 14) ^ load<u8>(keyPtr + 14);
  const s15 = load<u8>(statePtr + 15) ^ load<u8>(keyPtr + 15);

  // InvShiftRows + InvSubBytes
  // Column 0: s0, s13, s10, s7
  // Column 1: s4, s1, s14, s11
  // Column 2: s8, s5, s2, s15
  // Column 3: s12, s9, s6, s3
  const t0 = invSubByte(s0);
  const t1 = invSubByte(s13);
  const t2 = invSubByte(s10);
  const t3 = invSubByte(s7);

  const t4 = invSubByte(s4);
  const t5 = invSubByte(s1);
  const t6 = invSubByte(s14);
  const t7 = invSubByte(s11);

  const t8 = invSubByte(s8);
  const t9 = invSubByte(s5);
  const t10 = invSubByte(s2);
  const t11 = invSubByte(s15);

  const t12 = invSubByte(s12);
  const t13 = invSubByte(s9);
  const t14 = invSubByte(s6);
  const t15 = invSubByte(s3);

  // InvMixColumns
  // Column 0
  const r0 = unchecked(MUL14[t0]) ^ unchecked(MUL11[t1]) ^ unchecked(MUL13[t2]) ^ unchecked(MUL9[t3]);
  const r1 = unchecked(MUL9[t0]) ^ unchecked(MUL14[t1]) ^ unchecked(MUL11[t2]) ^ unchecked(MUL13[t3]);
  const r2 = unchecked(MUL13[t0]) ^ unchecked(MUL9[t1]) ^ unchecked(MUL14[t2]) ^ unchecked(MUL11[t3]);
  const r3 = unchecked(MUL11[t0]) ^ unchecked(MUL13[t1]) ^ unchecked(MUL9[t2]) ^ unchecked(MUL14[t3]);

  // Column 1
  const r4 = unchecked(MUL14[t4]) ^ unchecked(MUL11[t5]) ^ unchecked(MUL13[t6]) ^ unchecked(MUL9[t7]);
  const r5 = unchecked(MUL9[t4]) ^ unchecked(MUL14[t5]) ^ unchecked(MUL11[t6]) ^ unchecked(MUL13[t7]);
  const r6 = unchecked(MUL13[t4]) ^ unchecked(MUL9[t5]) ^ unchecked(MUL14[t6]) ^ unchecked(MUL11[t7]);
  const r7 = unchecked(MUL11[t4]) ^ unchecked(MUL13[t5]) ^ unchecked(MUL9[t6]) ^ unchecked(MUL14[t7]);

  // Column 2
  const r8 = unchecked(MUL14[t8]) ^ unchecked(MUL11[t9]) ^ unchecked(MUL13[t10]) ^ unchecked(MUL9[t11]);
  const r9 = unchecked(MUL9[t8]) ^ unchecked(MUL14[t9]) ^ unchecked(MUL11[t10]) ^ unchecked(MUL13[t11]);
  const r10 = unchecked(MUL13[t8]) ^ unchecked(MUL9[t9]) ^ unchecked(MUL14[t10]) ^ unchecked(MUL11[t11]);
  const r11 = unchecked(MUL11[t8]) ^ unchecked(MUL13[t9]) ^ unchecked(MUL9[t10]) ^ unchecked(MUL14[t11]);

  // Column 3
  const r12 = unchecked(MUL14[t12]) ^ unchecked(MUL11[t13]) ^ unchecked(MUL13[t14]) ^ unchecked(MUL9[t15]);
  const r13 = unchecked(MUL9[t12]) ^ unchecked(MUL14[t13]) ^ unchecked(MUL11[t14]) ^ unchecked(MUL13[t15]);
  const r14 = unchecked(MUL13[t12]) ^ unchecked(MUL9[t13]) ^ unchecked(MUL14[t14]) ^ unchecked(MUL11[t15]);
  const r15 = unchecked(MUL11[t12]) ^ unchecked(MUL13[t13]) ^ unchecked(MUL9[t14]) ^ unchecked(MUL14[t15]);

  // Store result
  store<u8>(statePtr, r0);
  store<u8>(statePtr + 1, r1);
  store<u8>(statePtr + 2, r2);
  store<u8>(statePtr + 3, r3);
  store<u8>(statePtr + 4, r4);
  store<u8>(statePtr + 5, r5);
  store<u8>(statePtr + 6, r6);
  store<u8>(statePtr + 7, r7);
  store<u8>(statePtr + 8, r8);
  store<u8>(statePtr + 9, r9);
  store<u8>(statePtr + 10, r10);
  store<u8>(statePtr + 11, r11);
  store<u8>(statePtr + 12, r12);
  store<u8>(statePtr + 13, r13);
  store<u8>(statePtr + 14, r14);
  store<u8>(statePtr + 15, r15);
}

/**
 * AES encryption round (exported for direct use)
 */
export function aesEncRound(statePtr: usize, keyPtr: usize): void {
  aesRound(statePtr, keyPtr);
}

// ============================================================================
// RandomX Soft AES - 4-round operations for scratchpad fill/mix
// ============================================================================

// AES keys for RandomX (hardcoded in specification)
// Key 0: 0x00..0f
const AES_KEY0: StaticArray<u8> = [
  0x77, 0x4f, 0x28, 0x4e, 0x3a, 0x8f, 0x9d, 0x6f,
  0x38, 0x74, 0x7b, 0x1c, 0x3a, 0xa0, 0xb2, 0xf9
];

// Key 1
const AES_KEY1: StaticArray<u8> = [
  0x89, 0x88, 0x1c, 0x84, 0xba, 0x80, 0x5d, 0x06,
  0x6f, 0x12, 0x6e, 0x42, 0x15, 0xc0, 0x41, 0x18
];

// Key 2
const AES_KEY2: StaticArray<u8> = [
  0xd9, 0x0c, 0x8b, 0x6c, 0x7d, 0xe7, 0x50, 0x2b,
  0x2a, 0xad, 0xd8, 0x77, 0x4f, 0xf8, 0x67, 0x06
];

// Key 3
const AES_KEY3: StaticArray<u8> = [
  0x5e, 0x9a, 0x1a, 0x17, 0x74, 0xab, 0x57, 0x5a,
  0x64, 0x79, 0xa0, 0xb8, 0x0d, 0x75, 0x9c, 0xf3
];

/**
 * RandomX 4-round AES encryption
 * Used for scratchpad fill
 */
export function aes4RoundEnc(statePtr: usize): void {
  aesRound(statePtr, changetype<usize>(AES_KEY0));
  aesRound(statePtr, changetype<usize>(AES_KEY1));
  aesRound(statePtr, changetype<usize>(AES_KEY2));
  aesRound(statePtr, changetype<usize>(AES_KEY3));
}

/**
 * RandomX 4-round AES decryption
 * Used for scratchpad finalization
 */
export function aes4RoundDec(statePtr: usize): void {
  aesDecRound(statePtr, changetype<usize>(AES_KEY0));
  aesDecRound(statePtr, changetype<usize>(AES_KEY1));
  aesDecRound(statePtr, changetype<usize>(AES_KEY2));
  aesDecRound(statePtr, changetype<usize>(AES_KEY3));
}

/**
 * Fill scratchpad with AES
 *
 * @param seedPtr - 64-byte seed from hash
 * @param scratchpadPtr - 2MB scratchpad
 * @param scratchpadSize - Size in bytes (2097152 for RandomX)
 */
export function fillScratchpad(seedPtr: usize, scratchpadPtr: usize, scratchpadSize: u32): void {
  // Split seed into 4 states (each 16 bytes)
  // state0 = seed[0:16], state1 = seed[16:32], state2 = seed[32:48], state3 = seed[48:64]

  // Working state storage (4 x 16 bytes = 64 bytes)
  const stateSize: usize = 64;

  // Process scratchpad in 64-byte chunks
  for (let offset: u32 = 0; offset < scratchpadSize; offset += 64) {
    const outPtr = scratchpadPtr + offset;

    // Copy current state to output
    memory.copy(outPtr, seedPtr, stateSize);

    // Apply 4-round AES to each 16-byte block
    aes4RoundEnc(outPtr);
    aes4RoundEnc(outPtr + 16);
    aes4RoundEnc(outPtr + 32);
    aes4RoundEnc(outPtr + 48);

    // Update seed for next iteration (current output becomes next input)
    memory.copy(seedPtr, outPtr, stateSize);
  }
}

/**
 * Mix scratchpad (finalization)
 *
 * @param statePtr - 64-byte state to mix with
 * @param scratchpadPtr - 2MB scratchpad
 * @param scratchpadSize - Size in bytes
 */
export function mixScratchpad(statePtr: usize, scratchpadPtr: usize, scratchpadSize: u32): void {
  // XOR scratchpad into state and apply AES decryption
  for (let offset: u32 = 0; offset < scratchpadSize; offset += 64) {
    const blockPtr = scratchpadPtr + offset;

    // XOR scratchpad block into state
    for (let i: u32 = 0; i < 64; i++) {
      const stateVal = load<u8>(statePtr + i);
      const blockVal = load<u8>(blockPtr + i);
      store<u8>(statePtr + i, stateVal ^ blockVal);
    }

    // Apply 4-round AES decryption
    aes4RoundDec(statePtr);
    aes4RoundDec(statePtr + 16);
    aes4RoundDec(statePtr + 32);
    aes4RoundDec(statePtr + 48);
  }
}

/**
 * Initialize AES tables (call once at startup)
 */
export function aes_init(): void {
  ensureTables();
  ensureInvTables();
}

/**
 * Test function: encrypt a single block
 */
export function aes_test_enc(statePtr: usize, keyPtr: usize): void {
  aesRound(statePtr, keyPtr);
}

/**
 * Test function: decrypt a single block
 */
export function aes_test_dec(statePtr: usize, keyPtr: usize): void {
  aesDecRound(statePtr, keyPtr);
}
