/**
 * Key Image Generation Module (DEPRECATED)
 *
 * @deprecated Use the Rust crypto backend (WASM/FFI/JSI) instead.
 * hashToPoint() and generateKeyImage() are now implemented in Rust
 * for correctness and performance. This module is kept for reference
 * and as a fallback for direct-import consumers. It will be removed
 * in a future version.
 *
 * Implements key image generation for Salvium transactions.
 * Key images are used to detect double-spending without revealing which output was spent.
 *
 * Key formula: KI = x * H_p(P)
 * Where:
 *   - x is the output secret key
 *   - P is the output public key
 *   - H_p is hash-to-point (maps 32-byte hash to curve point)
 *
 * Reference: crypto/crypto.cpp generate_key_image(), hash_to_ec()
 */

import { keccak256 } from './keccak.js';
import { hexToBytes, bytesToHex } from './address.js';

// Prime field: p = 2^255 - 19
const P = (1n << 255n) - 19n;

// Curve constant d = -121665/121666 mod p
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

// sqrt(-1) mod p
const SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

// Montgomery curve parameter A = 486662
const A = 486662n;

// Group order L
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

// Precomputed constants for Elligator 2 (computed mod p)
// -A mod p
const NEG_A = (P - A) % P;

// A^2 mod p
const A_SQUARED = (A * A) % P;

// -A^2 mod p  (fe_ma2)
const NEG_A_SQUARED = (P - A_SQUARED) % P;

// A + 2
const A_PLUS_2 = A + 2n;

// 2 * A * (A + 2) mod p
const TWO_A_AP2 = (2n * A * A_PLUS_2) % P;

// A * (A + 2) mod p
const A_AP2 = (A * A_PLUS_2) % P;

// ============================================================================
// Field Arithmetic (mod p)
// ============================================================================

function feAdd(a, b) {
  return (a + b) % P;
}

function feSub(a, b) {
  let r = a - b;
  if (r < 0n) r += P;
  return r;
}

function feMul(a, b) {
  return (a * b) % P;
}

function feSq(a) {
  return (a * a) % P;
}

function feNeg(a) {
  if (a === 0n) return 0n;
  return P - a;
}

function feIsZero(a) {
  return a === 0n;
}

function feIsNegative(a) {
  // "Negative" means least significant bit is 1
  return (a & 1n) === 1n;
}

// Modular exponentiation (square-and-multiply)
function fePow(base, exp) {
  let result = 1n;
  base = ((base % P) + P) % P;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % P;
    exp = exp >> 1n;
    base = (base * base) % P;
  }
  return result;
}

// Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
function feInv(a) {
  return fePow(a, P - 2n);
}

// Compute x^((p+3)/8) - used for square roots
// (p+3)/8 = (2^255 - 19 + 3)/8 = (2^255 - 16)/8 = 2^252 - 2
function fePowP3d8(x) {
  const exp = (1n << 252n) - 2n;
  return fePow(x, exp);
}

// Compute x^((p-5)/8) - used for fe_divpowm1
// (p-5)/8 = (2^255 - 19 - 5)/8 = (2^255 - 24)/8 = 2^252 - 3
function fePowPm5d8(x) {
  const exp = (1n << 252n) - 3n;
  return fePow(x, exp);
}

// Square root mod p
// For p ≡ 5 (mod 8), sqrt(a) = a^((p+3)/8) if a^((p-1)/4) = 1
// Otherwise sqrt(a) = sqrt(-1) * a^((p+3)/8)
function feSqrt(a) {
  if (a === 0n) return 0n;

  // Compute candidate = a^((p+3)/8)
  const candidate = fePowP3d8(a);

  // Check if candidate² = a
  if (feSq(candidate) === a) return candidate;

  // Try candidate * sqrt(-1)
  const adjusted = feMul(candidate, SQRT_M1);
  if (feSq(adjusted) === a) return adjusted;

  // No square root exists
  return null;
}

// fe_divpowm1: compute (u/v)^((p+3)/8) using the formula:
// (u/v)^((p+3)/8) = u * v^3 * (u * v^7)^((p-5)/8)
function feDivPowM1(u, v) {
  const v2 = feSq(v);
  const v3 = feMul(v2, v);
  const v4 = feSq(v2);
  const v7 = feMul(v4, v3);
  const uv7 = feMul(u, v7);
  const uv7_pow = fePowPm5d8(uv7);
  return feMul(feMul(u, v3), uv7_pow);
}

// ============================================================================
// Elligator 2: Field Element to Curve Point
// Reference: crypto-ops.c ge_fromfe_frombytes_vartime
// ============================================================================

/**
 * Load 32 bytes as field element (little-endian, reduced mod p)
 */
function feFromBytes(bytes) {
  let result = 0n;
  for (let i = 31; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result % P;
}

/**
 * Convert field element to 32 bytes (little-endian)
 */
function feToBytes(fe) {
  const bytes = new Uint8Array(32);
  let val = ((fe % P) + P) % P;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(val & 0xffn);
    val = val >> 8n;
  }
  return bytes;
}

/**
 * Elligator 2 map: hash bytes -> curve point
 * Implements ge_fromfe_frombytes_vartime from crypto-ops.c
 *
 * @param {Uint8Array} hashBytes - 32-byte hash
 * @returns {Object} Point {x, y} in affine coordinates
 */
function elligator2(hashBytes) {
  // Load hash as field element u
  const u = feFromBytes(hashBytes);

  // v = 2 * u^2
  const u2 = feSq(u);
  const v = feMul(2n, u2);

  // w = 2 * u^2 + 1
  const w = feAdd(v, 1n);

  // x = w^2 - 2 * A^2 * u^2
  //   = w^2 + 2 * (-A^2) * u^2
  const w2 = feSq(w);
  const term = feMul(feMul(2n, NEG_A_SQUARED), u2);
  let x = feAdd(w2, term);

  // r_X = (w / x)^((p+3)/8) via fe_divpowm1
  let r_X = feDivPowM1(w, x);

  // y = r_X^2 * x
  let y = feMul(feSq(r_X), x);

  // z starts as -A
  let z = NEG_A;

  // Determine branch based on whether y == w or y == -w
  let sign;

  // Check w - y == 0
  let diff = feSub(w, y);

  if (feIsZero(diff)) {
    // y == w: use fffb2 = sqrt(2*A*(A+2))
    // r_X = r_X * sqrt(2*A*(A+2))
    const fffb2 = feSqrt(TWO_A_AP2);
    if (fffb2 !== null) {
      r_X = feMul(r_X, fffb2);
    }
    // r_X = u * r_X
    r_X = feMul(r_X, u);
    // z = -A * v = -2Au^2
    z = feMul(z, v);
    sign = false;
  } else {
    // Check w + y == 0
    let sum = feAdd(w, y);
    if (feIsZero(sum)) {
      // y == -w: use fffb1 = sqrt(-2*A*(A+2))
      const neg_two_a_ap2 = feNeg(TWO_A_AP2);
      const fffb1 = feSqrt(neg_two_a_ap2);
      if (fffb1 !== null) {
        r_X = feMul(r_X, fffb1);
      }
      r_X = feMul(r_X, u);
      z = feMul(z, v);
      sign = false;
    } else {
      // Negative branch: multiply x by sqrt(-1)
      x = feMul(x, SQRT_M1);
      y = feMul(feSq(r_X), x);

      diff = feSub(w, y);
      if (feIsZero(diff)) {
        // Use fffb4 = sqrt(sqrt(-1)*A*(A+2))
        const sqrtm1_a_ap2 = feMul(SQRT_M1, A_AP2);
        const fffb4 = feSqrt(sqrtm1_a_ap2);
        if (fffb4 !== null) {
          r_X = feMul(r_X, fffb4);
        }
      } else {
        // Use fffb3 = sqrt(-sqrt(-1)*A*(A+2))
        const neg_sqrtm1_a_ap2 = feNeg(feMul(SQRT_M1, A_AP2));
        const fffb3 = feSqrt(neg_sqrtm1_a_ap2);
        if (fffb3 !== null) {
          r_X = feMul(r_X, fffb3);
        }
      }
      // z remains as -A
      sign = true;
    }
  }

  // Adjust sign of r_X
  if (feIsNegative(r_X) !== sign) {
    r_X = feNeg(r_X);
  }

  // Compute projective coordinates:
  // Z = z + w
  // Y = z - w
  // X = r_X * Z
  const Z = feAdd(z, w);
  const Y = feSub(z, w);
  const X = feMul(r_X, Z);

  // Convert to affine: x = X/Z, y = Y/Z
  const Zinv = feInv(Z);
  const affineX = feMul(X, Zinv);
  const affineY = feMul(Y, Zinv);

  return { x: affineX, y: affineY };
}

// ============================================================================
// Point Operations
// ============================================================================

/**
 * Point doubling on twisted Edwards curve: -x² + y² = 1 + dx²y²
 */
function pointDouble(x, y) {
  // Using unified doubling formula for twisted Edwards (a = -1)
  const x2 = feSq(x);
  const y2 = feSq(y);
  const xy = feMul(x, y);

  // x3 = 2xy / (y² - x²)
  // y3 = (x² + y²) / (2 - (y² - x²)) = (x² + y²) / (2 - y² + x²)
  const y2_minus_x2 = feSub(y2, x2);
  const x2_plus_y2 = feAdd(x2, y2);
  const two_minus = feSub(2n, y2_minus_x2);

  if (feIsZero(y2_minus_x2) || feIsZero(two_minus)) {
    return { x: 0n, y: 1n }; // Identity
  }

  const x3 = feMul(feMul(2n, xy), feInv(y2_minus_x2));
  const y3 = feMul(x2_plus_y2, feInv(two_minus));

  return { x: x3, y: y3 };
}

/**
 * Multiply point by 8 (cofactor clearing)
 * Done by doubling 3 times
 */
function pointMul8(x, y) {
  let p = { x, y };
  for (let i = 0; i < 3; i++) {
    p = pointDouble(p.x, p.y);
  }
  return p;
}

/**
 * Compress affine point to 32 bytes
 * Ed25519 encoding: y with sign bit of x in high bit
 */
function pointCompress(x, y) {
  const bytes = feToBytes(y);
  if (feIsNegative(x)) {
    bytes[31] |= 0x80;
  }
  return bytes;
}

/**
 * Decompress 32 bytes to affine point
 */
function pointDecompress(bytes) {
  // Extract y (clear high bit)
  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(bytes[i]);
  }
  const xSign = (y >> 255n) & 1n;
  y = y & ((1n << 255n) - 1n);

  if (y >= P) return null;

  // Recover x from curve equation: -x² + y² = 1 + dx²y²
  // x² = (y² - 1) / (dy² + 1)
  const y2 = feSq(y);
  const num = feSub(y2, 1n);
  const den = feAdd(feMul(D, y2), 1n);
  const x2 = feMul(num, feInv(den));

  let x = feSqrt(x2);
  if (x === null) return null;

  // Adjust sign
  if (feIsNegative(x) !== (xSign === 1n)) {
    x = feNeg(x);
  }

  return { x, y };
}

/**
 * Scalar multiplication: s * P (in affine coordinates)
 */
function scalarMultAffine(s, px, py) {
  let rx = 0n, ry = 1n; // Identity

  while (s > 0n) {
    if (s & 1n) {
      // Add point
      const r = pointAddAffine(rx, ry, px, py);
      rx = r.x;
      ry = r.y;
    }
    // Double base point
    const d = pointDouble(px, py);
    px = d.x;
    py = d.y;
    s = s >> 1n;
  }

  return { x: rx, y: ry };
}

/**
 * Point addition in affine coordinates
 */
function pointAddAffine(x1, y1, x2, y2) {
  // Handle identity
  if (x1 === 0n && y1 === 1n) return { x: x2, y: y2 };
  if (x2 === 0n && y2 === 1n) return { x: x1, y: y1 };

  // Standard twisted Edwards addition formula (a = -1)
  // x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
  // y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
  const x1y2 = feMul(x1, y2);
  const y1x2 = feMul(y1, x2);
  const y1y2 = feMul(y1, y2);
  const x1x2 = feMul(x1, x2);
  const dProduct = feMul(D, feMul(x1x2, y1y2));

  const numX = feAdd(x1y2, y1x2);
  const denX = feAdd(1n, dProduct);
  const numY = feAdd(y1y2, x1x2);
  const denY = feSub(1n, dProduct);

  if (feIsZero(denX) || feIsZero(denY)) {
    return { x: 0n, y: 1n }; // Result is identity or undefined
  }

  const x3 = feMul(numX, feInv(denX));
  const y3 = feMul(numY, feInv(denY));

  return { x: x3, y: y3 };
}

// ============================================================================
// Hash to Point (H_p)
// ============================================================================

/**
 * Hash a public key to a curve point
 * This is the H_p function: hash_to_ec in crypto.cpp
 *
 * Steps:
 * 1. Hash the public key with Keccak256
 * 2. Map hash to curve point using Elligator 2
 * 3. Multiply by cofactor 8 to ensure point is in prime-order subgroup
 *
 * @param {Uint8Array|string} publicKey - 32-byte public key
 * @returns {Uint8Array} 32-byte compressed curve point
 */
export function hashToPoint(publicKey) {
  if (typeof publicKey === 'string') {
    publicKey = hexToBytes(publicKey);
  }

  // Step 1: Hash the public key
  const hash = keccak256(publicKey);

  // Step 2: Map to curve using Elligator 2
  const point = elligator2(hash);

  // Step 3: Multiply by cofactor 8
  const point8 = pointMul8(point.x, point.y);

  // Compress to 32 bytes
  return pointCompress(point8.x, point8.y);
}

// ============================================================================
// Key Image Generation
// ============================================================================

/**
 * Generate key image from output public key and secret key
 * KI = secretKey * H_p(publicKey)
 *
 * @param {Uint8Array|string} outputPublicKey - 32-byte output public key
 * @param {Uint8Array|string} outputSecretKey - 32-byte output secret key
 * @returns {Uint8Array|null} 32-byte key image, or null if computation fails
 */
export function generateKeyImage(outputPublicKey, outputSecretKey) {
  if (typeof outputPublicKey === 'string') {
    outputPublicKey = hexToBytes(outputPublicKey);
  }
  if (typeof outputSecretKey === 'string') {
    outputSecretKey = hexToBytes(outputSecretKey);
  }

  // H_p(P) - hash public key to point
  const hpBytes = hashToPoint(outputPublicKey);

  // Decompress H_p point
  const hp = pointDecompress(hpBytes);
  if (!hp) return null;

  // Convert secret key to scalar
  let scalar = 0n;
  for (let i = 31; i >= 0; i--) {
    scalar = (scalar << 8n) | BigInt(outputSecretKey[i]);
  }
  scalar = scalar % L;

  // KI = scalar * H_p(P)
  const ki = scalarMultAffine(scalar, hp.x, hp.y);

  // Compress result
  return pointCompress(ki.x, ki.y);
}

/**
 * Derive the key image generator for a public key
 * This is H_p(P) without the scalar multiplication
 *
 * @param {Uint8Array|string} publicKey - 32-byte public key
 * @returns {Uint8Array} 32-byte key image generator point
 */
export function deriveKeyImageGenerator(publicKey) {
  return hashToPoint(publicKey);
}

// ============================================================================
// Key Image Validation
// ============================================================================

/**
 * Check if a key image is valid (on the curve)
 *
 * @param {Uint8Array|string} keyImage - 32-byte key image
 * @returns {boolean} True if valid
 */
export function isValidKeyImage(keyImage) {
  if (typeof keyImage === 'string') {
    keyImage = hexToBytes(keyImage);
  }

  if (keyImage.length !== 32) {
    return false;
  }

  // Reject all zeros (not a valid key image)
  let isAllZeros = true;
  for (let i = 0; i < 32; i++) {
    if (keyImage[i] !== 0) {
      isAllZeros = false;
      break;
    }
  }
  if (isAllZeros) return false;

  // Try to decompress
  const point = pointDecompress(keyImage);
  if (!point) return false;

  // Check it's not the identity
  if (point.x === 0n && point.y === 1n) return false;

  // Check for degenerate points (y=0 implies x=sqrt(-1) which is technically valid but unusual)
  if (point.y === 0n) return false;

  // Verify on curve: -x² + y² = 1 + dx²y²
  const x2 = feSq(point.x);
  const y2 = feSq(point.y);
  const lhs = feSub(y2, x2);
  const rhs = feAdd(1n, feMul(D, feMul(x2, y2)));

  return lhs === rhs;
}

/**
 * Extract the y-coordinate from a key image
 * @param {Uint8Array|string} keyImage - 32-byte key image
 * @returns {Object} { y: Uint8Array, sign: boolean }
 */
export function keyImageToY(keyImage) {
  if (typeof keyImage === 'string') {
    keyImage = hexToBytes(keyImage);
  }

  const y = new Uint8Array(keyImage);
  const sign = (y[31] & 0x80) !== 0;
  y[31] &= 0x7f;

  return { y, sign };
}

/**
 * Reconstruct key image from y-coordinate and sign
 * @param {Uint8Array} y - 32-byte y-coordinate
 * @param {boolean} sign - Sign bit
 * @returns {Uint8Array} 32-byte key image
 */
export function keyImageFromY(y, sign) {
  const keyImage = new Uint8Array(y);
  if (sign) {
    keyImage[31] |= 0x80;
  }
  return keyImage;
}

// ============================================================================
// Export/Import for View-Only Wallets
// ============================================================================

/**
 * Export key images for a list of outputs
 * @param {Array} outputs - Array of { outputPublicKey, outputSecretKey, outputIndex }
 * @returns {Array} Array of { keyImage, outputPublicKey, outputIndex }
 */
export function exportKeyImages(outputs) {
  return outputs.map(output => {
    const keyImage = generateKeyImage(output.outputPublicKey, output.outputSecretKey);
    return {
      keyImage: keyImage ? bytesToHex(keyImage) : null,
      outputPublicKey: typeof output.outputPublicKey === 'string'
        ? output.outputPublicKey
        : bytesToHex(output.outputPublicKey),
      outputIndex: output.outputIndex
    };
  }).filter(o => o.keyImage !== null);
}

/**
 * Import key images (for view-only wallet)
 * @param {Array} keyImages - Array of { keyImage, outputPublicKey }
 * @returns {Map} Map of outputPublicKey -> keyImage
 */
export function importKeyImages(keyImages) {
  const map = new Map();
  for (const { keyImage, outputPublicKey } of keyImages) {
    map.set(outputPublicKey, keyImage);
  }
  return map;
}

// ============================================================================
// Exports
// ============================================================================

export default {
  hashToPoint,
  generateKeyImage,
  deriveKeyImageGenerator,
  isValidKeyImage,
  keyImageToY,
  keyImageFromY,
  exportKeyImages,
  importKeyImages
};
