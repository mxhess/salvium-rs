/**
 * Blake2b implementation in AssemblyScript
 *
 * Native u64 operations - much faster than JS BigInt!
 */

// Blake2b initialization vectors
const IV: u64[] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

// Sigma permutations for rounds
const SIGMA: u8[][] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];

// Working state
let h: StaticArray<u64> = new StaticArray<u64>(8);
let v: StaticArray<u64> = new StaticArray<u64>(16);
let m: StaticArray<u64> = new StaticArray<u64>(16);

// Buffer for incomplete blocks
let buffer: StaticArray<u8> = new StaticArray<u8>(128);
let bufferLength: u32 = 0;
let totalLength: u64 = 0;
let outLen: u32 = 32;

/**
 * 64-bit rotation right
 */
@inline
function rotr64(x: u64, n: u32): u64 {
  return (x >> n) | (x << (64 - n));
}

/**
 * G mixing function
 */
@inline
function G(a: i32, b: i32, c: i32, d: i32, x: u64, y: u64): void {
  unchecked(v[a] = v[a] + v[b] + x);
  unchecked(v[d] = rotr64(v[d] ^ v[a], 32));
  unchecked(v[c] = v[c] + v[d]);
  unchecked(v[b] = rotr64(v[b] ^ v[c], 24));
  unchecked(v[a] = v[a] + v[b] + y);
  unchecked(v[d] = rotr64(v[d] ^ v[a], 16));
  unchecked(v[c] = v[c] + v[d]);
  unchecked(v[b] = rotr64(v[b] ^ v[c], 63));
}

/**
 * Compress a block
 */
function compress(last: bool): void {
  // Initialize v[0..7] with h[0..7]
  for (let i = 0; i < 8; i++) {
    unchecked(v[i] = h[i]);
  }

  // Initialize v[8..15] with IV
  unchecked(v[8] = IV[0]);
  unchecked(v[9] = IV[1]);
  unchecked(v[10] = IV[2]);
  unchecked(v[11] = IV[3]);
  unchecked(v[12] = IV[4] ^ totalLength);
  unchecked(v[13] = IV[5]);
  unchecked(v[14] = last ? ~IV[6] : IV[6]);
  unchecked(v[15] = IV[7]);

  // 12 rounds
  for (let round = 0; round < 12; round++) {
    const s = SIGMA[round % 10];

    G(0, 4, 8, 12, unchecked(m[s[0]]), unchecked(m[s[1]]));
    G(1, 5, 9, 13, unchecked(m[s[2]]), unchecked(m[s[3]]));
    G(2, 6, 10, 14, unchecked(m[s[4]]), unchecked(m[s[5]]));
    G(3, 7, 11, 15, unchecked(m[s[6]]), unchecked(m[s[7]]));
    G(0, 5, 10, 15, unchecked(m[s[8]]), unchecked(m[s[9]]));
    G(1, 6, 11, 12, unchecked(m[s[10]]), unchecked(m[s[11]]));
    G(2, 7, 8, 13, unchecked(m[s[12]]), unchecked(m[s[13]]));
    G(3, 4, 9, 14, unchecked(m[s[14]]), unchecked(m[s[15]]));
  }

  // Update hash
  for (let i = 0; i < 8; i++) {
    unchecked(h[i] ^= v[i] ^ v[i + 8]);
  }
}

/**
 * Initialize Blake2b state
 */
export function blake2b_init(digestLength: u32): void {
  outLen = digestLength;
  bufferLength = 0;
  totalLength = 0;

  // Initialize hash with IV
  for (let i = 0; i < 8; i++) {
    unchecked(h[i] = IV[i]);
  }

  // Parameter block (simplified)
  unchecked(h[0] ^= 0x01010000 ^ <u64>digestLength);
}

/**
 * Update Blake2b with data
 */
export function blake2b_update(dataPtr: usize, dataLen: u32): void {
  let offset: u32 = 0;

  // If we have buffered data, try to complete a block
  if (bufferLength > 0) {
    const needed: u32 = 128 - bufferLength;
    const toCopy: u32 = min(needed, dataLen);

    for (let i: u32 = 0; i < toCopy; i++) {
      unchecked(buffer[bufferLength + i] = load<u8>(dataPtr + i));
    }
    bufferLength += toCopy;
    offset += toCopy;

    if (bufferLength == 128) {
      // Parse buffer into m
      for (let i = 0; i < 16; i++) {
        unchecked(m[i] =
          <u64>buffer[i * 8] |
          (<u64>buffer[i * 8 + 1] << 8) |
          (<u64>buffer[i * 8 + 2] << 16) |
          (<u64>buffer[i * 8 + 3] << 24) |
          (<u64>buffer[i * 8 + 4] << 32) |
          (<u64>buffer[i * 8 + 5] << 40) |
          (<u64>buffer[i * 8 + 6] << 48) |
          (<u64>buffer[i * 8 + 7] << 56)
        );
      }
      totalLength += 128;
      compress(false);
      bufferLength = 0;
    }
  }

  // Process full blocks directly from input
  while (offset + 128 <= dataLen) {
    for (let i = 0; i < 16; i++) {
      const p = dataPtr + offset + <usize>(i * 8);
      unchecked(m[i] =
        <u64>load<u8>(p) |
        (<u64>load<u8>(p + 1) << 8) |
        (<u64>load<u8>(p + 2) << 16) |
        (<u64>load<u8>(p + 3) << 24) |
        (<u64>load<u8>(p + 4) << 32) |
        (<u64>load<u8>(p + 5) << 40) |
        (<u64>load<u8>(p + 6) << 48) |
        (<u64>load<u8>(p + 7) << 56)
      );
    }
    totalLength += 128;
    compress(false);
    offset += 128;
  }

  // Buffer remaining bytes
  while (offset < dataLen) {
    unchecked(buffer[bufferLength++] = load<u8>(dataPtr + offset));
    offset++;
  }
}

/**
 * Finalize Blake2b and write output
 */
export function blake2b_final(outPtr: usize): void {
  totalLength += bufferLength;

  // Pad buffer with zeros
  for (let i = bufferLength; i < 128; i++) {
    unchecked(buffer[i] = 0);
  }

  // Parse buffer into m
  for (let i = 0; i < 16; i++) {
    unchecked(m[i] =
      <u64>buffer[i * 8] |
      (<u64>buffer[i * 8 + 1] << 8) |
      (<u64>buffer[i * 8 + 2] << 16) |
      (<u64>buffer[i * 8 + 3] << 24) |
      (<u64>buffer[i * 8 + 4] << 32) |
      (<u64>buffer[i * 8 + 5] << 40) |
      (<u64>buffer[i * 8 + 6] << 48) |
      (<u64>buffer[i * 8 + 7] << 56)
    );
  }

  compress(true);

  // Write output
  for (let i: u32 = 0; i < outLen; i++) {
    const hIdx = i >> 3;
    const shift = (i & 7) << 3;
    store<u8>(outPtr + i, <u8>(unchecked(h[hIdx]) >> shift));
  }
}

/**
 * One-shot Blake2b hash
 */
export function blake2b(dataPtr: usize, dataLen: u32, outPtr: usize, digestLen: u32): void {
  blake2b_init(digestLen);
  blake2b_update(dataPtr, dataLen);
  blake2b_final(outPtr);
}
