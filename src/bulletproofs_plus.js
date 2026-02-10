/**
 * Bulletproofs+ Range Proof Generation & Verification
 *
 * Uses the crypto provider for hash-to-point (Monero's ge_fromfe_frombytes_vartime).
 * Based on the Bulletproofs+ paper and Monero/Salvium implementation.
 *
 * Reference: https://eprint.iacr.org/2020/735.pdf
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { mod, invert, Field } from '@noble/curves/abstract/modular.js';
import { keccak256, hashToPoint as cryptoHashToPoint, getCryptoBackend } from './crypto/index.js';

// Ed25519 curve order (L)
const L = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');

// Point class from ed25519
const Point = ed25519.Point;

// Scalar field for batch operations
const Fn = Field(L);

// Fixed H constant from Monero/Salvium (toPoint(cn_fast_hash(G)))
// This is NOT computed at runtime - it's a fixed basepoint
const H_BYTES = new Uint8Array([
  0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
  0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
  0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
  0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94
]);

// Number of bits in range proof
const N = 64;
const LOG_N = 6;

// Maximum aggregation (16 outputs)
const MAX_M = 16;
const MAX_LOG_M = 4;

// 8^(-1) mod L - used for subgroup checks
const INV_EIGHT = mod(invert(8n, L), L);

// 2^64 - 1
const TWO_64_MINUS_1 = (1n << 64n) - 1n;

// Precomputed generators cache
let generatorsCache = null;
let transcriptInitCache = null;

/**
 * Clear cached generators and transcript.
 * Call this after switching crypto backends.
 */
export function clearBulletproofCache() {
  generatorsCache = null;
  transcriptInitCache = null;
}

/**
 * Convert a 32-byte Uint8Array to BigInt (little-endian)
 */
export function bytesToScalar(bytes) {
  let result = 0n;
  for (let i = 0; i < 32; i++) {
    result |= BigInt(bytes[i]) << BigInt(i * 8);
  }
  return mod(result, L);
}

/**
 * Convert BigInt to 32-byte Uint8Array (little-endian)
 */
export function scalarToBytes(scalar) {
  const bytes = new Uint8Array(32);
  let val = mod(scalar, L);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Convert a 32-byte compressed point to Point
 */
export function bytesToPoint(bytes) {
  try {
    return Point.fromBytes(bytes);
  } catch (e) {
    throw new Error(`Invalid point encoding: ${e.message}`);
  }
}

/**
 * Hash to scalar using Keccak-256
 */
export function hashToScalar(...inputs) {
  const totalLength = inputs.reduce((sum, input) => sum + input.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const input of inputs) {
    combined.set(input, offset);
    offset += input.length;
  }
  const hash = keccak256(combined);
  return bytesToScalar(hash);
}

/**
 * Hash to point matching C++ get_exponent / hash_to_p3 exactly.
 *
 * C++ flow:
 *   1. cn_fast_hash(data) -> hash1
 *   2. hash_to_p3(hash1) internally does:
 *      a. cn_fast_hash(hash1) -> hash2 (DOUBLE HASH!)
 *      b. ge_fromfe_frombytes_vartime(hash2) -> elligator2
 *      c. ge_mul8 -> cofactor clear
 *
 * Our WASM hashToPoint does: keccak256(input) -> elligator2 -> *8
 * So we need to pre-hash: hashToPoint(keccak256(data)) = keccak256(keccak256(data)) -> elligator2 -> *8
 */
export function hashToPointMonero(data) {
  // First hash: matches C++'s cn_fast_hash in get_exponent
  const hash1 = keccak256(data);
  // WASM hashToPoint does second hash internally, matching hash_to_p3
  const pointBytes = cryptoHashToPoint(hash1);
  return Point.fromBytes(pointBytes);
}

/**
 * Encode varint for generator construction
 */
function encodeVarint(n) {
  const bytes = [];
  while (n >= 0x80) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return new Uint8Array(bytes);
}

/**
 * Initialize generators Gi and Hi
 *
 * C++ formula (from bulletproofs_plus.cc):
 *   Hi_p3[i] = get_exponent(rct::H, i * 2);
 *   Gi_p3[i] = get_exponent(rct::H, i * 2 + 1);
 *
 * Where get_exponent does:
 *   hashed = H_bytes + "bulletproof_plus" + varint(idx)
 *   generator = hash_to_p3(cn_fast_hash(hashed))
 *
 * Note: H is a FIXED constant, NOT computed from hash-to-point.
 */
export function initGenerators(maxMN = MAX_M * N) {
  if (generatorsCache && generatorsCache.Gi.length >= maxMN) {
    return generatorsCache;
  }

  const G = Point.BASE;
  const H = Point.fromBytes(H_BYTES); // Use fixed H constant

  const prefix = new TextEncoder().encode('bulletproof_plus');

  const Gi = [];
  const Hi = [];

  for (let i = 0; i < maxMN; i++) {
    // Hi uses even indices (2*i) - NOTE: Hi uses even, Gi uses odd (matches C++)
    const hiVarint = encodeVarint(2 * i);
    const hiData = new Uint8Array(H_BYTES.length + prefix.length + hiVarint.length);
    hiData.set(H_BYTES);
    hiData.set(prefix, H_BYTES.length);
    hiData.set(hiVarint, H_BYTES.length + prefix.length);
    Hi.push(hashToPointMonero(hiData));

    // Gi uses odd indices (2*i + 1)
    const giVarint = encodeVarint(2 * i + 1);
    const giData = new Uint8Array(H_BYTES.length + prefix.length + giVarint.length);
    giData.set(H_BYTES);
    giData.set(prefix, H_BYTES.length);
    giData.set(giVarint, H_BYTES.length + prefix.length);
    Gi.push(hashToPointMonero(giData));
  }

  generatorsCache = { G, H, Gi, Hi };
  return generatorsCache;
}

/**
 * Initialize transcript with domain separator
 *
 * C++ formula:
 *   cn_fast_hash(domain_separator) -> hash1
 *   hash_to_p3(hash1) internally does:
 *     cn_fast_hash(hash1) -> hash2
 *     ge_fromfe_frombytes_vartime(hash2) -> elligator2
 *     ge_mul8 -> *8
 *
 * Total: keccak256(keccak256(domain)) -> elligator2 -> *8
 */
export function initTranscript() {
  if (transcriptInitCache) {
    return transcriptInitCache;
  }

  const domain = new TextEncoder().encode('bulletproof_plus_transcript');
  // First hash (matches C++ cn_fast_hash)
  const hash1 = keccak256(domain);
  // WASM hashToPoint does second hash internally
  const pointBytes = cryptoHashToPoint(hash1);
  transcriptInitCache = pointBytes;
  return transcriptInitCache;
}

/**
 * Hash a vector of keys (points) to a scalar
 * Matches Salvium: hash_to_scalar(keyV) - concatenate all and hash
 */
function hashKeysToScalar(keys) {
  if (keys.length === 0) {
    return bytesToScalar(keccak256(new Uint8Array(0)));
  }
  const totalLength = keys.length * 32;
  const data = new Uint8Array(totalLength);
  for (let i = 0; i < keys.length; i++) {
    data.set(keys[i].toBytes(), i * 32);
  }
  return bytesToScalar(keccak256(data));
}

/**
 * Update transcript with one element (Salvium style)
 * Matches Salvium: hash_to_scalar(transcript || element) - returns REDUCED scalar bytes
 */
function transcriptUpdate(transcript, element) {
  const data = new Uint8Array(64);
  data.set(transcript);
  data.set(element, 32);
  // IMPORTANT: C++ hash_to_scalar reduces the result - we must return reduced bytes
  return scalarToBytes(bytesToScalar(keccak256(data)));
}

/**
 * Update transcript with two elements (Salvium style)
 * Matches Salvium: hash_to_scalar(transcript || element1 || element2) - returns REDUCED scalar bytes
 */
function transcriptUpdate2(transcript, element1, element2) {
  const data = new Uint8Array(96);
  data.set(transcript);
  data.set(element1, 32);
  data.set(element2, 64);
  // IMPORTANT: C++ hash_to_scalar reduces the result - we must return reduced bytes
  return scalarToBytes(bytesToScalar(keccak256(data)));
}

/**
 * Parse a Bulletproof+ proof from bytes
 */
export function parseProof(proofBytes) {
  if (proofBytes.length < 32 * 7) {
    throw new Error('Proof too short');
  }

  let offset = 0;

  // Salvium binary format: A, A1, B, r1, s1, d1, varint(L.len), L[], varint(R.len), R[]
  // Note: V (commitments) is NOT in the wire format — restored from outPk.

  // A, A1, B (points)
  const A = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;
  const A1 = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;
  const B = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // r1, s1, d1 (scalars)
  const r1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;
  const s1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;
  const d1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // L
  const { value: lCount, bytesRead: lBytes } = _decodeVarint(proofBytes, offset);
  offset += lBytes;
  const L = [];
  for (let i = 0; i < lCount; i++) {
    L.push(bytesToPoint(proofBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  // R
  const { value: rCount, bytesRead: rBytes } = _decodeVarint(proofBytes, offset);
  offset += rBytes;
  const R = [];
  for (let i = 0; i < rCount; i++) {
    R.push(bytesToPoint(proofBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  return { A, A1, B, r1, s1, d1, L, R };
}

function _decodeVarint(bytes, offset) {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;
  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return { value, bytesRead };
}

/**
 * Compute power of y efficiently
 */
function computeYPowers(y, max) {
  const powers = [1n];
  let current = y;
  for (let i = 1; i <= max; i++) {
    powers.push(current);
    current = mod(current * y, L);
  }
  return powers;
}

/**
 * Compute sum of powers: y + y^2 + ... + y^n
 */
function sumOfPowers(y, n) {
  if (n === 0n) return 0n;

  let sum = 0n;
  let yPow = y;
  for (let i = 0; i < n; i++) {
    sum = mod(sum + yPow, L);
    yPow = mod(yPow * y, L);
  }
  return sum;
}

/**
 * Build challenge cache (Salvium style)
 * This builds a cache where products of challenges and their inverses
 * are computed iteratively for efficient scalar derivation
 */
function buildChallengeCache(challenges, challengeInverses, MN) {
  const rounds = challenges.length;
  const cache = new Array(MN);

  // Initialize first two entries
  cache[0] = challengeInverses[0];  // x0^(-1)
  cache[1] = challenges[0];         // x0

  // Build rest of cache iteratively
  for (let j = 1; j < rounds; j++) {
    const slots = 1 << (j + 1);
    for (let s = slots - 1; s >= 0; s--) {
      if (s % 2 === 1) {
        // Odd index: multiply by challenge
        cache[s] = mod(cache[Math.floor(s / 2)] * challenges[j], L);
      } else {
        // Even index: multiply by inverse
        cache[s] = mod(cache[Math.floor(s / 2)] * challengeInverses[j], L);
      }
    }
  }

  return cache;
}

/**
 * Multiscalar multiplication using @noble/curves
 * Computes sum(scalars[i] * points[i])
 */
export function multiScalarMul(scalars, points) {
  if (scalars.length !== points.length) {
    throw new Error('Scalars and points must have same length');
  }

  if (scalars.length === 0) {
    return Point.ZERO;
  }

  // Use @noble/curves built-in MSM when available
  // For now, use simple accumulation (can be optimized with Pippenger later)
  let result = Point.ZERO;

  for (let i = 0; i < scalars.length; i++) {
    const scalar = mod(scalars[i], L);
    if (scalar !== 0n) {
      result = result.add(points[i].multiply(scalar));
    }
  }

  return result;
}

/**
 * Verify a single Bulletproof+ range proof
 *
 * @param {Point[]} V - Commitments to values
 * @param {Object} proof - Parsed proof object
 * @returns {boolean} - True if proof is valid
 */
export function verifyBulletproofPlus(V, proof) {
  return verifyBulletproofPlusBatch([{ V, proof }]);
}

/**
 * Batch verify multiple Bulletproof+ range proofs
 *
 * @param {Array<{V: Point[], proof: Object}>} proofs - Array of proofs to verify
 * @returns {boolean} - True if all proofs are valid
 */
export function verifyBulletproofPlusBatch(proofs) {
  if (proofs.length === 0) return true;

  // Initialize generators and transcript
  const gens = initGenerators();
  let transcript = initTranscript();

  // Collect all scalars for batch inversion
  const toInvert = [];
  const proofData = [];

  // Phase 1: Reconstruct challenges for all proofs
  for (const { V, proof } of proofs) {
    const { A, A1, B, r1, s1, d1, L, R } = proof;

    // Validate proof structure
    const m = V.length;
    if (m === 0 || m > MAX_M) {
      throw new Error(`Invalid number of commitments: ${m}`);
    }

    // M must be power of 2 >= m
    let M = 1;
    let logM = 0;
    while (M < m) {
      M *= 2;
      logM++;
    }

    const MN = M * N;
    const rounds = L.length;

    if (rounds !== LOG_N + logM) {
      throw new Error(`Invalid number of rounds: expected ${LOG_N + logM}, got ${rounds}`);
    }

    if (R.length !== rounds) {
      throw new Error('L and R must have same length');
    }

    // Update transcript with hash of all V (Salvium style)
    let proofTranscript = transcript;
    const hashV = hashKeysToScalar(V);
    proofTranscript = transcriptUpdate(proofTranscript, scalarToBytes(hashV));

    // Challenge y from A: y = hash_to_scalar(transcript || A)
    proofTranscript = transcriptUpdate(proofTranscript, A.toBytes());
    const y = bytesToScalar(proofTranscript);

    // Challenge z from y: z = hash_to_scalar(y)
    // IMPORTANT: C++ uses the REDUCED y bytes, not the raw transcript hash
    const yBytes = scalarToBytes(y);
    const z = bytesToScalar(keccak256(yBytes));
    proofTranscript = scalarToBytes(z); // transcript = z

    // Challenges for each round: challenge[j] = hash_to_scalar(transcript || L[j] || R[j])
    const challenges = [];
    for (let j = 0; j < rounds; j++) {
      proofTranscript = transcriptUpdate2(proofTranscript, L[j].toBytes(), R[j].toBytes());
      challenges.push(bytesToScalar(proofTranscript));
      toInvert.push(challenges[j]); // Need inverse for R terms
    }

    // Final challenge e: e = hash_to_scalar(transcript || A1 || B)
    proofTranscript = transcriptUpdate2(proofTranscript, A1.toBytes(), B.toBytes());
    const e = bytesToScalar(proofTranscript);

    toInvert.push(y); // Need y^(-1) for folding

    proofData.push({
      V, A, A1, B, r1, s1, d1, L, R,
      m, M, logM, MN, rounds,
      y, z, e, challenges
    });
  }

  // Phase 2: Batch inversion
  const inverses = Fn.invertBatch(toInvert);

  // Map inverses back to proofs
  let invIdx = 0;
  for (const data of proofData) {
    data.challengeInverses = [];
    for (let j = 0; j < data.rounds; j++) {
      data.challengeInverses.push(inverses[invIdx++]);
    }
    data.yInv = inverses[invIdx++];
  }

  // Phase 3: Build weighted batch equation
  const allScalars = [];
  const allPoints = [];

  // G and H base point accumulators
  let gScalar = 0n;
  let hScalar = 0n;

  for (const data of proofData) {
    const { V, A, A1, B, r1, s1, d1, L: Lpoints, R: Rpoints,
            m, M, MN, rounds, y, z, e, challenges, challengeInverses, yInv } = data;

    // Random weight for batch verification (for single proof, use 1)
    // Must use cryptographically secure random to prevent proof forgery
    let w;
    if (proofs.length === 1) {
      w = 1n;
    } else {
      const wBytes = new Uint8Array(32);
      crypto.getRandomValues(wBytes);
      let wBig = 0n;
      for (let i = 0; i < 32; i++) wBig |= BigInt(wBytes[i]) << BigInt(i * 8);
      w = mod(wBig, L);
      if (w === 0n) w = 1n;
    }

    const e2 = mod(e * e, L);

    // Compute y^MN via square-and-multiply
    let yMN = 1n;
    let base = y;
    let exp = BigInt(MN);
    while (exp > 0n) {
      if (exp & 1n) {
        yMN = mod(yMN * base, L);
      }
      base = mod(base * base, L);
      exp >>= 1n;
    }

    const yMNp1 = mod(yMN * y, L);

    // Compute z powers: z^2, z^4, z^6, ..., z^(2M)
    const z2 = mod(z * z, L);
    const zPowers = [z2];
    for (let j = 1; j < M; j++) {
      zPowers.push(mod(zPowers[j-1] * z2, L));
    }

    // sum_d = (2^64 - 1) * sum(z^(2j)) for j = 1..M
    let sumZPowers = 0n;
    for (const zp of zPowers) {
      sumZPowers = mod(sumZPowers + zp, L);
    }
    const sumD = mod(TWO_64_MINUS_1 * sumZPowers, L);

    // sum_y = y + y^2 + ... + y^MN
    const sumY = sumOfPowers(y, BigInt(MN));

    // Add V commitments (multiply by 8 for subgroup check)
    // V[j]: scalar = -e² * y^(MN+1) * w * z^(2(j+1))
    // zPowers = [z², z⁴, z⁶, ...] so zPowers[j] = z^(2(j+1))
    for (let j = 0; j < m; j++) {
      const scalar = mod(-w * e2 * zPowers[j] * yMNp1, L);
      allScalars.push(scalar);
      allPoints.push(V[j].multiply(8n));
    }

    // Add A, A1, B (multiply by 8)
    allScalars.push(mod(-w * e2, L));
    allPoints.push(A.multiply(8n));

    allScalars.push(mod(-w * e, L));
    allPoints.push(A1.multiply(8n));

    allScalars.push(mod(-w, L));
    allPoints.push(B.multiply(8n));

    // Add to G scalar
    gScalar = mod(gScalar + w * d1, L);

    // Add to H scalar: w*[r1*y*s1 + e^2*(y^(MN+1)*z*sum_d + (z^2-z)*sum_y)]
    const hTerm1 = mod(r1 * y * s1, L);
    const hTerm2 = mod(yMNp1 * z * sumD, L);
    const hTerm3 = mod((z2 - z) * sumY, L);
    hScalar = mod(hScalar + w * (hTerm1 + e2 * (hTerm2 + hTerm3)), L);

    // Build challenge products cache (includes both challenges and inverses)
    const challengeCache = buildChallengeCache(challenges, challengeInverses, MN);

    // Compute Gi and Hi scalars (Salvium style with iterative y powers)
    // Initial values
    let e_r1_w = mod(e * r1 * w, L);  // e*r1*w (no y!)
    const e_s1_w = mod(e * s1 * w, L);
    const e2_z_w = mod(e2 * z * w, L);
    const minus_e2_z_w = mod(-e2_z_w, L);
    let minus_e2_w_y = mod(-e2 * w * yMN, L);  // -e²*w*y^MN, decrements each step

    for (let i = 0; i < MN; i++) {
      // d[i] = z^(2*(floor(i/N)+1)) * 2^(i mod N)
      const dIdx = Math.floor(i / N);
      const bitPos = i % N;
      const dVal = mod(zPowers[dIdx] * (1n << BigInt(bitPos)), L);

      // g_scalar[i] = e*r1*w*y^(-i) * challenges_cache[i] + e²*z*w
      const gScalarI = mod(e_r1_w * challengeCache[i] + e2_z_w, L);

      // h_scalar[i] = e*s1*w * challenges_cache[(~i)&(MN-1)] - e²*z*w - e²*w*y^(MN-i)*d[i]
      const invIndex = (~i) & (MN - 1);
      const hScalarI = mod(e_s1_w * challengeCache[invIndex] + minus_e2_z_w + minus_e2_w_y * dVal, L);

      allScalars.push(gScalarI);
      allPoints.push(gens.Gi[i]);

      allScalars.push(hScalarI);
      allPoints.push(gens.Hi[i]);

      // Update for next iteration: multiply by y^(-1)
      e_r1_w = mod(e_r1_w * yInv, L);
      minus_e2_w_y = mod(minus_e2_w_y * yInv, L);
    }

    // Add L and R terms
    for (let j = 0; j < rounds; j++) {
      const x2 = mod(challenges[j] * challenges[j], L);
      const xInv2 = mod(challengeInverses[j] * challengeInverses[j], L);

      // L contribution: -w*e^2*x^2
      allScalars.push(mod(-w * e2 * x2, L));
      allPoints.push(Lpoints[j].multiply(8n));

      // R contribution: -w*e^2*x^(-2)
      allScalars.push(mod(-w * e2 * xInv2, L));
      allPoints.push(Rpoints[j].multiply(8n));
    }
  }

  // Add G and H base points
  if (gScalar !== 0n) {
    allScalars.push(gScalar);
    allPoints.push(gens.G);
  }

  if (hScalar !== 0n) {
    allScalars.push(hScalar);
    allPoints.push(gens.H);
  }

  // Phase 4: Final verification - check if result is identity
  const result = multiScalarMul(allScalars, allPoints);

  return result.equals(Point.ZERO);
}

/**
 * Verify a range proof from raw bytes
 *
 * @param {Uint8Array[]} commitmentBytes - Array of 32-byte commitment encodings
 * @param {Uint8Array} proofBytes - Serialized proof
 * @returns {boolean} - True if proof is valid
 */
export function verifyRangeProof(commitmentBytes, proofBytes) {
  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.bulletproofPlusVerify(commitmentBytes, proofBytes);
  if (nativeResult !== null) return nativeResult;

  const V = commitmentBytes.map(bytesToPoint);
  const proof = parseProof(proofBytes);
  return verifyBulletproofPlus(V, proof);
}

// ============================================================
// BULLETPROOFS+ PROOF GENERATION
// ============================================================

/**
 * Generate a cryptographically secure random scalar
 */
export function randomScalar() {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  // Reduce 64 bytes to get uniform distribution mod L
  let result = 0n;
  for (let i = 0; i < 64; i++) {
    result |= BigInt(bytes[i]) << BigInt(i * 8);
  }
  return mod(result, L);
}

/**
 * Compute vector exponent: sum(aL[i] * Gi[i] + aR[i] * Hi[i])
 */
function vectorExponent(aL, aR, Gi, Hi) {
  if (aL.length !== aR.length || aL.length !== Gi.length || aL.length !== Hi.length) {
    throw new Error('Vector length mismatch');
  }

  let result = Point.ZERO;
  for (let i = 0; i < aL.length; i++) {
    if (aL[i] !== 0n) {
      result = result.add(Gi[i].multiply(mod(aL[i], L)));
    }
    if (aR[i] !== 0n) {
      result = result.add(Hi[i].multiply(mod(aR[i], L)));
    }
  }
  return result;
}

/**
 * Compute weighted inner product: sum(a[i] * b[i] * y^(i+1))
 */
function weightedInnerProduct(a, b, y) {
  if (a.length !== b.length) {
    throw new Error('Vector length mismatch');
  }

  let result = 0n;
  let yPow = y;
  for (let i = 0; i < a.length; i++) {
    result = mod(result + mod(mod(a[i] * b[i], L) * yPow, L), L);
    yPow = mod(yPow * y, L);
  }
  return result;
}

/**
 * Compute powers of y: [1, y, y^2, ..., y^(n-1)]
 */
function computePowersOf(y, n) {
  const powers = new Array(n);
  powers[0] = 1n;
  for (let i = 1; i < n; i++) {
    powers[i] = mod(powers[i - 1] * y, L);
  }
  return powers;
}

/**
 * Decompose amounts into bit vectors
 * Returns { aL, aR } where aL[i] ∈ {0,1}, aR[i] = aL[i] - 1 ∈ {0,-1}
 */
function decomposeToBits(amounts, MN) {
  const aL = new Array(MN).fill(0n);
  const aR = new Array(MN).fill(0n);

  for (let j = 0; j < amounts.length; j++) {
    let amount = amounts[j];
    for (let i = 0; i < N; i++) {
      if ((amount >> BigInt(i)) & 1n) {
        aL[j * N + i] = 1n;
        aR[j * N + i] = 0n;
      } else {
        aL[j * N + i] = 0n;
        aR[j * N + i] = mod(-1n, L); // -1 mod L
      }
    }
  }

  // Pad remaining with zeros for aL, -1 for aR
  for (let i = amounts.length * N; i < MN; i++) {
    aL[i] = 0n;
    aR[i] = mod(-1n, L);
  }

  return { aL, aR };
}

/**
 * Generate a Bulletproof+ range proof
 *
 * @param {BigInt[]} amounts - Array of amounts to prove (each < 2^64)
 * @param {BigInt[]} masks - Array of blinding factors (one per amount)
 * @returns {Object} - Proof object { V, A, A1, B, r1, s1, d1, L, R }
 */
export function bulletproofPlusProve(amounts, masks) {
  if (amounts.length === 0 || amounts.length !== masks.length) {
    throw new Error('Invalid input: amounts and masks must have equal non-zero length');
  }

  if (amounts.length > MAX_M) {
    throw new Error(`Too many amounts: ${amounts.length} > ${MAX_M}`);
  }

  // Validate amounts are in range
  for (let i = 0; i < amounts.length; i++) {
    if (amounts[i] < 0n || amounts[i] >= (1n << 64n)) {
      throw new Error(`Amount ${i} out of range`);
    }
  }

  // Try accelerated backend (WASM/JSI)
  const backend = getCryptoBackend();
  const nativeResult = backend.bulletproofPlusProve(amounts, masks);
  if (nativeResult !== null) {
    // WASM/JSI returns { V, proofBytes } — parse into full field set
    // so serializeProof and getPreMlsagHash can access A, A1, B, etc.
    if (nativeResult.proofBytes && !nativeResult.A) {
      const parsed = parseProof(nativeResult.proofBytes);
      return { V: nativeResult.V, ...parsed, proofBytes: nativeResult.proofBytes };
    }
    return nativeResult;
  }

  // Compute M (smallest power of 2 >= amounts.length)
  let M = 1;
  let logM = 0;
  while (M < amounts.length) {
    M *= 2;
    logM++;
  }

  const MN = M * N;
  const logMN = logM + LOG_N;

  // Initialize generators (slice to needed size)
  const gens = initGenerators(MN);
  const { G, H } = gens;
  const Gi = gens.Gi.slice(0, MN);
  const Hi = gens.Hi.slice(0, MN);

  // Initialize transcript
  let transcript = initTranscript();

  // ============================================================
  // STEP 1: Create output commitments V
  // V[j] = mask[j] * G + amount[j] * H (scaled by 1/8)
  // ============================================================
  const V = [];
  for (let j = 0; j < amounts.length; j++) {
    const maskScaled = mod(masks[j] * INV_EIGHT, L);
    const amountScaled = mod(amounts[j] * INV_EIGHT, L);
    // Handle zero amount case - can't multiply by 0
    let commitment = G.multiply(maskScaled);
    if (amountScaled !== 0n) {
      commitment = commitment.add(H.multiply(amountScaled));
    }
    V.push(commitment);
  }

  // Update transcript with hash of all V (Salvium style)
  const hashV = hashKeysToScalar(V);
  transcript = transcriptUpdate(transcript, scalarToBytes(hashV));

  // ============================================================
  // STEP 2: Decompose amounts into bit vectors
  // ============================================================
  const { aL, aR } = decomposeToBits(amounts, MN);

  // Scale by 1/8 for commitment
  const aL8 = aL.map(x => mod(x * INV_EIGHT, L));
  const aR8 = aR.map(x => mod(x * INV_EIGHT, L));

  // ============================================================
  // STEP 3: Initial commitment A
  // ============================================================
  const alpha = randomScalar();

  // A = sum(aL8[i] * Gi[i] + aR8[i] * Hi[i]) + alpha*INV_EIGHT * G
  let A = vectorExponent(aL8, aR8, Gi, Hi);
  A = A.add(G.multiply(mod(alpha * INV_EIGHT, L)));

  // ============================================================
  // STEP 4: First challenge y = hash_to_scalar(transcript || A)
  // ============================================================
  transcript = transcriptUpdate(transcript, A.toBytes());
  let y = bytesToScalar(transcript);
  if (y === 0n) {
    throw new Error('Challenge y is zero - retry');
  }

  // Challenge z = hash_to_scalar(y), transcript = z
  // IMPORTANT: C++ uses the REDUCED y bytes, not the raw transcript hash
  const yBytes = scalarToBytes(y);
  let z = bytesToScalar(keccak256(yBytes));
  if (z === 0n) {
    throw new Error('Challenge z is zero - retry');
  }
  transcript = scalarToBytes(z);

  const z2 = mod(z * z, L);

  // ============================================================
  // STEP 5: Compute windowed vector d
  // d[j*N+i] = z^(2*(j+1)) * 2^i
  // ============================================================
  const d = new Array(MN);
  let zPow = z2; // Start with z^2
  for (let j = 0; j < M; j++) {
    let twoPow = 1n;
    for (let i = 0; i < N; i++) {
      d[j * N + i] = mod(zPow * twoPow, L);
      twoPow = mod(twoPow * 2n, L);
    }
    zPow = mod(zPow * z2, L);
  }

  // ============================================================
  // STEP 6: Compute y powers
  // ============================================================
  const yPowers = computePowersOf(y, MN + 2);
  const yInv = invert(y, L);
  const yInvPowers = computePowersOf(yInv, MN);

  // ============================================================
  // STEP 7: Prepare inner product inputs
  // aL1[i] = aL[i] - z
  // aR1[i] = aR[i] + z + d[i] * y^(MN-i)
  // ============================================================
  const aL1 = new Array(MN);
  const aR1 = new Array(MN);

  for (let i = 0; i < MN; i++) {
    aL1[i] = mod(aL[i] - z, L);
    aR1[i] = mod(aR[i] + z + mod(d[i] * yPowers[MN - i], L), L);
  }

  // Update alpha with gamma terms
  let alpha1 = alpha;
  let temp = 1n;
  for (let j = 0; j < amounts.length; j++) {
    temp = mod(temp * z2, L);
    alpha1 = mod(alpha1 + mod(temp * mod(yPowers[MN + 1] * masks[j], L), L), L);
  }

  // ============================================================
  // STEP 8: Inner product argument
  // ============================================================
  let nprime = MN;
  let Gprime = Gi.slice(0, MN);
  let Hprime = Hi.slice(0, MN);
  let aprime = aL1.slice();
  let bprime = aR1.slice();

  const Lpoints = [];
  const Rpoints = [];
  const challenges = [];

  // Run logMN rounds
  while (nprime > 1) {
    nprime = nprime / 2;

    // Compute cL and cR (weighted inner products)
    let cL = 0n;
    let cR = 0n;
    let yPow = y;
    for (let i = 0; i < nprime; i++) {
      cL = mod(cL + mod(mod(aprime[i] * bprime[nprime + i], L) * yPow, L), L);
      cR = mod(cR + mod(mod(mod(aprime[nprime + i] * yPowers[nprime], L) * bprime[i], L) * yPow, L), L);
      yPow = mod(yPow * y, L);
    }

    // Random blinding factors
    const dL = randomScalar();
    const dR = randomScalar();

    // Compute L (Salvium: compute_LR with y = yinvpow[nprime])
    let Lpoint = Point.ZERO;
    for (let i = 0; i < nprime; i++) {
      const aScaled = mod(aprime[i] * yInvPowers[nprime] * INV_EIGHT, L);  // No extra * y!
      const bScaled = mod(bprime[nprime + i] * INV_EIGHT, L);
      Lpoint = Lpoint.add(Gprime[nprime + i].multiply(aScaled));
      Lpoint = Lpoint.add(Hprime[i].multiply(bScaled));
    }
    Lpoint = Lpoint.add(H.multiply(mod(cL * INV_EIGHT, L)));
    Lpoint = Lpoint.add(G.multiply(mod(dL * INV_EIGHT, L)));
    Lpoints.push(Lpoint);

    // Compute R
    let Rpoint = Point.ZERO;
    for (let i = 0; i < nprime; i++) {
      const aScaled = mod(aprime[nprime + i] * yPowers[nprime] * INV_EIGHT, L);
      const bScaled = mod(bprime[i] * INV_EIGHT, L);
      Rpoint = Rpoint.add(Gprime[i].multiply(aScaled));
      Rpoint = Rpoint.add(Hprime[nprime + i].multiply(bScaled));
    }
    Rpoint = Rpoint.add(H.multiply(mod(cR * INV_EIGHT, L)));
    Rpoint = Rpoint.add(G.multiply(mod(dR * INV_EIGHT, L)));
    Rpoints.push(Rpoint);

    // Update transcript and get challenge: x = hash_to_scalar(transcript || L || R)
    transcript = transcriptUpdate2(transcript, Lpoint.toBytes(), Rpoint.toBytes());
    const x = bytesToScalar(transcript);
    if (x === 0n) {
      throw new Error('Challenge x is zero - retry');
    }
    challenges.push(x);

    const xInv = invert(x, L);
    const x2 = mod(x * x, L);
    const xInv2 = mod(xInv * xInv, L);

    // Fold generators
    const newGprime = new Array(nprime);
    const newHprime = new Array(nprime);
    const temp1 = mod(yInvPowers[nprime] * x, L);
    const temp2 = mod(xInv * yPowers[nprime], L);

    for (let i = 0; i < nprime; i++) {
      newGprime[i] = Gprime[i].multiply(xInv).add(Gprime[nprime + i].multiply(temp1));
      newHprime[i] = Hprime[i].multiply(x).add(Hprime[nprime + i].multiply(xInv));
    }
    Gprime = newGprime;
    Hprime = newHprime;

    // Fold scalars
    const newAprime = new Array(nprime);
    const newBprime = new Array(nprime);

    for (let i = 0; i < nprime; i++) {
      newAprime[i] = mod(aprime[i] * x + aprime[nprime + i] * temp2, L);
      newBprime[i] = mod(bprime[i] * xInv + bprime[nprime + i] * x, L);
    }
    aprime = newAprime;
    bprime = newBprime;

    // Update alpha1
    alpha1 = mod(alpha1 + mod(dL * x2, L) + mod(dR * xInv2, L), L);
  }

  // ============================================================
  // STEP 9: Final round
  // ============================================================
  const r = randomScalar();
  const s = randomScalar();
  const d_ = randomScalar();
  const eta = randomScalar();

  // A1 = r*Gprime[0] + s*Hprime[0] + d_*G + (r*y*bprime[0] + s*y*aprime[0])*H
  // All scaled by INV_EIGHT
  const rScaled = mod(r * INV_EIGHT, L);
  const sScaled = mod(s * INV_EIGHT, L);
  const dScaled = mod(d_ * INV_EIGHT, L);
  const hCoeff = mod(mod(r * y * bprime[0], L) + mod(s * y * aprime[0], L), L);
  const hScaled = mod(hCoeff * INV_EIGHT, L);

  let A1 = Gprime[0].multiply(rScaled);
  A1 = A1.add(Hprime[0].multiply(sScaled));
  A1 = A1.add(G.multiply(dScaled));
  A1 = A1.add(H.multiply(hScaled));

  // B = eta*INV_EIGHT * G + r*y*s*INV_EIGHT * H (Salvium style)
  const etaScaled = mod(eta * INV_EIGHT, L);
  const innerProdScaled = mod(r * y * s * INV_EIGHT, L);
  const B = G.multiply(etaScaled).add(H.multiply(innerProdScaled));

  // Update transcript and get final challenge e = hash_to_scalar(transcript || A1 || B)
  transcript = transcriptUpdate2(transcript, A1.toBytes(), B.toBytes());
  const e = bytesToScalar(transcript);
  if (e === 0n) {
    throw new Error('Challenge e is zero - retry');
  }

  const e2 = mod(e * e, L);

  // ============================================================
  // STEP 10: Compute final scalars
  // ============================================================
  const r1 = mod(r + aprime[0] * e, L);
  const s1 = mod(s + bprime[0] * e, L);
  const d1 = mod(eta + d_ * e + alpha1 * e2, L);

  // ============================================================
  // Return proof
  // ============================================================
  return {
    V,
    A,
    A1,
    B,
    r1,
    s1,
    d1,
    L: Lpoints,
    R: Rpoints
  };
}

/**
 * Serialize a Bulletproof+ proof to bytes
 */
export function serializeProof(proof) {
  // Short-circuit: WASM/JSI backend already provides serialized bytes
  if (proof.proofBytes) return proof.proofBytes;

  const { A, A1, B, r1, s1, d1, L, R } = proof;

  // Monero/Salvium binary format for BulletproofPlus:
  //   A (32), A1 (32), B (32)
  //   r1 (32), s1 (32), d1 (32)
  //   varint(L.length), L[0..n] (32 bytes each)
  //   varint(R.length), R[0..n] (32 bytes each)
  // Note: V (commitments) is NOT serialized — restored from outPk.
  // Must match parseProof format for roundtrip compatibility.

  const chunks = [];

  // A, A1, B (points)
  chunks.push(A.toBytes());
  chunks.push(A1.toBytes());
  chunks.push(B.toBytes());

  // r1, s1, d1 (scalars)
  chunks.push(scalarToBytes(r1));
  chunks.push(scalarToBytes(s1));
  chunks.push(scalarToBytes(d1));

  // L
  chunks.push(_encodeVarint(L.length));
  for (const l of L) chunks.push(l.toBytes());

  // R
  chunks.push(_encodeVarint(R.length));
  for (const r of R) chunks.push(r.toBytes());

  // Concatenate
  let totalLen = 0;
  for (const c of chunks) totalLen += c.length;
  const bytes = new Uint8Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.length;
  }
  return bytes;
}

function _encodeVarint(value) {
  const bytes = [];
  let v = value;
  while (v >= 0x80) {
    bytes.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  bytes.push(v);
  return new Uint8Array(bytes);
}

/**
 * Create a range proof for a single amount
 */
export function proveRange(amount, mask) {
  return bulletproofPlusProve([amount], [mask]);
}

/**
 * Create a range proof for multiple amounts (aggregated)
 */
export function proveRangeMultiple(amounts, masks) {
  return bulletproofPlusProve(amounts, masks);
}

// Export the Point for testing
export { Point, L, INV_EIGHT };
