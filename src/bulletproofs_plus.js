/**
 * Bulletproofs+ Range Proof Verification
 *
 * Pure JavaScript implementation using @noble/curves for Ed25519 operations.
 * Based on the Bulletproofs+ paper and Monero/Salvium implementation.
 *
 * Reference: https://eprint.iacr.org/2020/735.pdf
 */

import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js';
import { mod, invert, Field } from '@noble/curves/abstract/modular.js';
import { keccak256 } from './keccak.js';

// Ed25519 curve order (L)
const L = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');

// Point class from ed25519
const Point = ed25519.Point;

// Scalar field for batch operations
const Fn = Field(L);

// Hash-to-curve function (uses elligator2)
const hashToCurve = ed25519_hasher.hashToCurve;

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
 * Hash to point using elligator2 hash-to-curve
 * Note: For production, this should match Monero's hash_to_p3 exactly.
 * This version uses the standard hash-to-curve for Ed25519.
 */
export function hashToPoint(data) {
  // hashToCurve automatically clears cofactor
  return hashToCurve(data);
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
 * Gi[i] = hash_to_p3(H || "bulletproof_plus" || varint(2*i+1))
 * Hi[i] = hash_to_p3(H || "bulletproof_plus" || varint(2*i))
 */
export function initGenerators(maxMN = MAX_M * N) {
  if (generatorsCache && generatorsCache.Gi.length >= maxMN) {
    return generatorsCache;
  }

  // H is the second generator (hash of G)
  const G = Point.BASE;
  const GBytes = G.toBytes();
  const H = hashToPoint(GBytes);

  const prefix = new TextEncoder().encode('bulletproof_plus');
  const HBytes = H.toBytes();

  const Gi = [];
  const Hi = [];

  for (let i = 0; i < maxMN; i++) {
    // Gi uses odd indices (2*i + 1)
    const giVarint = encodeVarint(2 * i + 1);
    const giData = new Uint8Array(HBytes.length + prefix.length + giVarint.length);
    giData.set(HBytes);
    giData.set(prefix, HBytes.length);
    giData.set(giVarint, HBytes.length + prefix.length);
    Gi.push(hashToPoint(giData));

    // Hi uses even indices (2*i)
    const hiVarint = encodeVarint(2 * i);
    const hiData = new Uint8Array(HBytes.length + prefix.length + hiVarint.length);
    hiData.set(HBytes);
    hiData.set(prefix, HBytes.length);
    hiData.set(hiVarint, HBytes.length + prefix.length);
    Hi.push(hashToPoint(hiData));
  }

  generatorsCache = { G, H, Gi, Hi };
  return generatorsCache;
}

/**
 * Initialize transcript with domain separator
 */
export function initTranscript() {
  if (transcriptInitCache) {
    return transcriptInitCache;
  }

  const domain = new TextEncoder().encode('bulletproof_plus_transcript');
  transcriptInitCache = keccak256(domain);
  return transcriptInitCache;
}

/**
 * Update transcript with new data
 */
function updateTranscript(transcript, ...elements) {
  const totalLength = 32 + elements.reduce((sum, el) => sum + el.length, 0);
  const data = new Uint8Array(totalLength);
  data.set(transcript);
  let offset = 32;
  for (const el of elements) {
    data.set(el, offset);
    offset += el.length;
  }
  return keccak256(data);
}

/**
 * Parse a Bulletproof+ proof from bytes
 */
export function parseProof(proofBytes) {
  if (proofBytes.length < 32 * 7) {
    throw new Error('Proof too short');
  }

  let offset = 0;

  // Read number of commitments (first varint or fixed)
  // For simplicity, assume V count is derived from L/R length

  // A - initial commitment
  const A = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // A1 - final round commitment
  const A1 = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // B - final round element
  const B = bytesToPoint(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // r1, s1, d1 - final scalars
  const r1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;

  const s1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;

  const d1 = bytesToScalar(proofBytes.slice(offset, offset + 32));
  offset += 32;

  // Remaining bytes are L and R pairs
  const remaining = proofBytes.length - offset;
  if (remaining % 64 !== 0) {
    throw new Error('Invalid L/R length');
  }

  const rounds = remaining / 64;
  const L = [];
  const R = [];

  for (let i = 0; i < rounds; i++) {
    L.push(bytesToPoint(proofBytes.slice(offset, offset + 32)));
    offset += 32;
    R.push(bytesToPoint(proofBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  return { A, A1, B, r1, s1, d1, L, R };
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
 * Build challenge cache for binary decomposition
 * challenges_cache[i] = product of challenges indexed by binary representation of i
 */
function buildChallengeCache(challenges, MN) {
  const rounds = challenges.length;
  const cache = new Array(MN);

  for (let i = 0; i < MN; i++) {
    let product = 1n;
    for (let j = 0; j < rounds; j++) {
      // If bit j of i is set, use challenge[j], else use its inverse
      if ((i >> (rounds - 1 - j)) & 1) {
        product = mod(product * challenges[j], L);
      }
    }
    cache[i] = product;
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

    // Update transcript with commitments
    let proofTranscript = transcript;
    for (const v of V) {
      proofTranscript = updateTranscript(proofTranscript, v.toBytes());
    }

    // Challenge y from A
    proofTranscript = updateTranscript(proofTranscript, A.toBytes());
    const y = bytesToScalar(proofTranscript);

    // Challenge z from y
    const zTranscript = updateTranscript(proofTranscript);
    const z = bytesToScalar(keccak256(proofTranscript));

    // Challenges for each round
    const challenges = [];
    for (let j = 0; j < rounds; j++) {
      proofTranscript = updateTranscript(proofTranscript, L[j].toBytes(), R[j].toBytes());
      challenges.push(bytesToScalar(proofTranscript));
      toInvert.push(challenges[j]); // Need inverse for R terms
    }

    // Final challenge e
    proofTranscript = updateTranscript(proofTranscript, A1.toBytes(), B.toBytes());
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
    const { V, A, A1, B, r1, s1, d1, L, R,
            m, M, MN, rounds, y, z, e, challenges, challengeInverses, yInv } = data;

    // Random weight for batch verification (for single proof, use 1)
    const w = proofs.length === 1 ? 1n : mod(BigInt(Math.floor(Math.random() * 2**32)), L);

    const e2 = mod(e * e, L);

    // Compute y^MN
    let yMN = 1n;
    let yPow = y;
    for (let i = 0; i < MN; i++) {
      yMN = mod(yMN * yPow, L);
      yPow = mod(yPow * y, L);
    }
    // Actually compute correctly: y^MN via squaring
    yMN = 1n;
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
    for (let j = 0; j < m; j++) {
      const zExp = mod(z * zPowers[j], L); // z^(2j+1) = z * z^(2j)
      const scalar = mod(-w * e2 * zExp * yMNp1, L);
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

    // Build challenge products cache
    const challengeCache = buildChallengeCache(challenges, MN);

    // Build inverse challenge cache for R terms
    const invChallengeCache = buildChallengeCache(challengeInverses, MN);

    // Compute Gi and Hi scalars
    const wey = mod(w * e * r1 * y, L);
    const wes = mod(w * e * s1, L);
    const we2z = mod(w * e2 * z, L);

    for (let i = 0; i < MN; i++) {
      // d[i] = z^(2*(floor(i/N)+1)) * 2^(i mod N)
      const dIdx = Math.floor(i / N);
      const bitPos = i % N;
      const dVal = mod(zPowers[dIdx] * (1n << BigInt(bitPos)), L);

      // g_scalar[i] = e*r1*w*y * challenges_cache[i] + e^2*z*w
      const gScalarI = mod(wey * challengeCache[i] + we2z, L);

      // Compute y^(MN-1-i) for h_scalar
      // h_scalar[i] = e*s1*w * challenges_cache[~i] - e^2*z*w - e^2*w*y^(MN-1-i)*d[i]
      // Actually: h_scalar uses inverted bit pattern
      const invI = (MN - 1 - i) ^ (MN - 1); // Bit reversal for folding

      // Compute y power for this term
      let yPowI = 1n;
      let yBase = y;
      let powExp = BigInt(MN - 1 - i);
      while (powExp > 0n) {
        if (powExp & 1n) yPowI = mod(yPowI * yBase, L);
        yBase = mod(yBase * yBase, L);
        powExp >>= 1n;
      }

      const hScalarI = mod(wes * invChallengeCache[i] - we2z - w * e2 * yPowI * dVal, L);

      allScalars.push(gScalarI);
      allPoints.push(gens.Gi[i]);

      allScalars.push(hScalarI);
      allPoints.push(gens.Hi[i]);
    }

    // Add L and R terms
    for (let j = 0; j < rounds; j++) {
      const x2 = mod(challenges[j] * challenges[j], L);
      const xInv2 = mod(challengeInverses[j] * challengeInverses[j], L);

      // L contribution: -w*e^2*x^2
      allScalars.push(mod(-w * e2 * x2, L));
      allPoints.push(L[j].multiply(8n));

      // R contribution: -w*e^2*x^(-2)
      allScalars.push(mod(-w * e2 * xInv2, L));
      allPoints.push(R[j].multiply(8n));
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
  const V = commitmentBytes.map(bytesToPoint);
  const proof = parseProof(proofBytes);
  return verifyBulletproofPlus(V, proof);
}

// Export the Point for testing
export { Point };
