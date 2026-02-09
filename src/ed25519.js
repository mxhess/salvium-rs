/**
 * Ed25519 Elliptic Curve Operations
 *
 * Uses @noble/ed25519 for optimized scalar multiplication (hot path).
 * Falls back to BigInt implementation for specialized operations.
 */

import { Point as NoblePoint } from '@noble/ed25519';

// Prime field: p = 2^255 - 19
const P = (1n << 255n) - 19n;

// Curve constant d = -121665/121666 mod p
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

// 2*d
const D2 = (2n * D) % P;

// sqrt(-1) mod p
const I = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

// Base point G (Ed25519 standard base point)
// GY = 4/5 mod P, GX is the positive (even) square root satisfying the curve equation
const GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
const GY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

// Generator T for CARROT/FCMP++ (from Salvium generators.cpp)
// T = H_p(keccak("Monero Generator T"))
// Encoded as: 966fc66b82cd56cf85eaec801c42845f5f408878d1561e00d3d7ded2794d094f
const T_BYTES = new Uint8Array([
  0x96, 0x6f, 0xc6, 0x6b, 0x82, 0xcd, 0x56, 0xcf,
  0x85, 0xea, 0xec, 0x80, 0x1c, 0x42, 0x84, 0x5f,
  0x5f, 0x40, 0x88, 0x78, 0xd1, 0x56, 0x1e, 0x00,
  0xd3, 0xd7, 0xde, 0xd2, 0x79, 0x4d, 0x09, 0x4f
]);

// Group order L
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function getRandomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

// Field operations
function feAdd(a, b) {
  return (a + b) % P;
}

function feSub(a, b) {
  return (a - b + P) % P;
}

function feMul(a, b) {
  return (a * b) % P;
}

function feSq(a) {
  return (a * a) % P;
}

function feNeg(a) {
  return (P - a) % P;
}

// Modular exponentiation
function fePow(base, exp) {
  let result = 1n;
  base = base % P;
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

// Square root mod p (for point decompression)
// p ≡ 5 (mod 8), so sqrt(a) = a^((p+3)/8) or i*a^((p+3)/8)
function feSqrt(a) {
  const exp = (P + 3n) / 8n;
  let r = fePow(a, exp);

  // Check if r^2 = a
  if (feSq(r) === a) return r;

  // Try i*r
  r = feMul(r, I);
  if (feSq(r) === a) return r;

  return null; // No square root exists
}

// Point in extended coordinates: (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z
// Represented as {X, Y, Z, T} with BigInt values

function pointZero() {
  return { X: 0n, Y: 1n, Z: 1n, T: 0n };
}

function pointFromXY(x, y) {
  return { X: x, Y: y, Z: 1n, T: feMul(x, y) };
}

function pointCopy(p) {
  return { X: p.X, Y: p.Y, Z: p.Z, T: p.T };
}

// Point addition using unified formula (works for doubling too)
// Based on https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
function pointAdd(p, q) {
  const A = feMul(feSub(p.Y, p.X), feSub(q.Y, q.X));
  const B = feMul(feAdd(p.Y, p.X), feAdd(q.Y, q.X));
  const C = feMul(feMul(p.T, q.T), D2);
  const D_ = feMul(p.Z, q.Z);
  const D2_ = feAdd(D_, D_);
  const E = feSub(B, A);
  const F = feSub(D2_, C);
  const G = feAdd(D2_, C);
  const H = feAdd(B, A);

  return {
    X: feMul(E, F),
    Y: feMul(G, H),
    Z: feMul(F, G),
    T: feMul(E, H)
  };
}

// Point doubling using ge_p2_dbl formula from Salvium ref10
// This matches ge_p2_dbl.h exactly
function pointDouble(p) {
  // Matching ge_p2_dbl.h exactly:
  // XX = X^2
  const XX = feSq(p.X);
  // YY = Y^2
  const YY = feSq(p.Y);
  // B = 2*Z^2 (fe_sq2 computes 2*a^2)
  const B = feMul(2n, feSq(p.Z));
  // A = X + Y
  const A = feAdd(p.X, p.Y);
  // AA = A^2 = (X+Y)^2
  const AA = feSq(A);
  // Y3 = YY + XX
  const Y3_p1p1 = feAdd(YY, XX);
  // Z3 = YY - XX
  const Z3_p1p1 = feSub(YY, XX);
  // X3 = AA - Y3 = (X+Y)^2 - (YY+XX) = 2XY
  const X3_p1p1 = feSub(AA, Y3_p1p1);
  // T3 = B - Z3 = 2Z^2 - (YY-XX)
  const T3_p1p1 = feSub(B, Z3_p1p1);

  // Now convert from p1p1 to p3 (extended) using ge_p1p1_to_p3
  // r->X = p->X * p->T
  // r->Y = p->Y * p->Z
  // r->Z = p->Z * p->T
  // r->T = p->X * p->Y
  return {
    X: feMul(X3_p1p1, T3_p1p1),
    Y: feMul(Y3_p1p1, Z3_p1p1),
    Z: feMul(Z3_p1p1, T3_p1p1),
    T: feMul(X3_p1p1, Y3_p1p1)
  };
}

// Unified add formula for comparison
function pointAddUnified(p, q) {
  const A = feMul(feSub(p.Y, p.X), feSub(q.Y, q.X));
  const B = feMul(feAdd(p.Y, p.X), feAdd(q.Y, q.X));
  const C = feMul(feMul(p.T, q.T), D2);
  const D_ = feMul(p.Z, q.Z);
  const D2_ = feAdd(D_, D_);
  const E = feSub(B, A);
  const F = feSub(D2_, C);
  const G = feAdd(D2_, C);
  const H = feAdd(B, A);

  return {
    X: feMul(E, F),
    Y: feMul(G, H),
    Z: feMul(F, G),
    T: feMul(E, H)
  };
}

// Scalar multiplication using double-and-add
function scalarMult(p, s) {
  let result = pointZero();
  let base = pointCopy(p);

  // Process scalar bits from LSB to MSB
  while (s > 0n) {
    if (s & 1n) {
      result = pointAdd(result, base);
    }
    base = pointDouble(base);
    s = s >> 1n;
  }

  return result;
}

// Compress point to 32 bytes
function pointToBytes(p) {
  // Convert to affine: x = X/Z, y = Y/Z
  const zi = feInv(p.Z);
  const x = feMul(p.X, zi);
  const y = feMul(p.Y, zi);

  // Encode y with sign of x in high bit
  const bytes = new Uint8Array(32);
  let yy = y;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(yy & 0xffn);
    yy = yy >> 8n;
  }

  // Set high bit if x is "negative" (odd)
  if (x & 1n) {
    bytes[31] |= 0x80;
  }

  return bytes;
}

// Decompress 32 bytes to point
function pointFromBytes(bytes) {
  // Extract y (clear high bit)
  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(bytes[i]);
  }
  const xSign = (y >> 255n) & 1n;
  y = y & ((1n << 255n) - 1n);

  if (y >= P) return null;

  // Recover x from curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
  const y2 = feSq(y);
  const num = feSub(y2, 1n);
  const den = feAdd(feMul(D, y2), 1n);
  const denInv = feInv(den);
  const x2 = feMul(num, denInv);

  let x = feSqrt(x2);
  if (x === null) return null;

  // Adjust sign
  if ((x & 1n) !== xSign) {
    x = feNeg(x);
  }

  return pointFromXY(x, y);
}

// Convert scalar bytes (little-endian) to BigInt
function scalarFromBytes(bytes) {
  let s = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    s = (s << 8n) | BigInt(bytes[i]);
  }
  return s;
}

// Public API

/**
 * Check if scalar is valid (< L)
 * @param {Uint8Array} s - 32-byte scalar
 * @returns {boolean} true if valid
 */
export function scalarCheck(s) {
  if (s.length !== 32) return false;
  const scalar = scalarFromBytes(s);
  return scalar < L;
}

/**
 * Check if scalar is non-zero
 * @param {Uint8Array} s - 32-byte scalar
 * @returns {boolean} true if non-zero
 */
export function scalarIsNonzero(s) {
  const scalar = scalarFromBytes(s);
  return scalar !== 0n;
}

/**
 * Scalar subtraction: r = a - b (mod L)
 * @param {Uint8Array} r - 32-byte output
 * @param {Uint8Array} a - 32-byte input
 * @param {Uint8Array} b - 32-byte input
 */
export function scalarSub(r, a, b) {
  const aVal = scalarFromBytes(a);
  const bVal = scalarFromBytes(b);
  let result = (aVal - bVal) % L;
  if (result < 0n) result += L;

  // Convert back to bytes (little-endian)
  for (let i = 0; i < 32; i++) {
    r[i] = Number(result & 0xffn);
    result = result >> 8n;
  }
}

/**
 * Scalar multiplication with base point: s * G
 * Uses @noble/ed25519 for optimized performance.
 * @param {Uint8Array} s - 32-byte scalar
 * @returns {Uint8Array} 32-byte compressed public key
 */
export function scalarMultBase(s) {
  try {
    // Convert scalar to BigInt (little-endian)
    let scalar = 0n;
    for (let i = 0; i < 32; i++) {
      scalar |= BigInt(s[i]) << BigInt(i * 8);
    }
    // Use @noble for fast base point multiplication
    const result = NoblePoint.BASE.multiply(scalar);
    return result.toBytes();
  } catch (e) {
    // Fallback to original implementation
    const scalarBig = scalarFromBytes(s);
    const G = pointFromXY(GX, GY);
    const result = scalarMult(G, scalarBig);
    return pointToBytes(result);
  }
}

/**
 * Scalar multiplication with arbitrary point: s * P
 * Uses @noble/ed25519 for optimized performance.
 * @param {Uint8Array} s - 32-byte scalar
 * @param {Uint8Array} P - 32-byte compressed point
 * @returns {Uint8Array|null} 32-byte compressed result, or null if P is invalid
 */
export function scalarMultPoint(s, P) {
  try {
    // Convert scalar to BigInt (little-endian)
    let scalar = 0n;
    for (let i = 0; i < 32; i++) {
      scalar |= BigInt(s[i]) << BigInt(i * 8);
    }
    // Use @noble for fast scalar multiplication
    const point = NoblePoint.fromBytes(P);
    const result = point.multiply(scalar);
    return result.toBytes();
  } catch (e) {
    return null;
  }
}

/**
 * Get the T generator point (used in CARROT)
 * @returns {Uint8Array} 32-byte compressed T point
 */
export function getGeneratorT() {
  return new Uint8Array(T_BYTES);
}

/**
 * Get the G generator point (standard Ed25519 base point)
 * @returns {Uint8Array} 32-byte compressed G point
 */
export function getGeneratorG() {
  const G = pointFromXY(GX, GY);
  return pointToBytes(G);
}

/**
 * Point addition: P + Q
 * @param {Uint8Array} P - 32-byte compressed point
 * @param {Uint8Array} Q - 32-byte compressed point
 * @returns {Uint8Array|null} 32-byte compressed result, or null if invalid
 */
export function pointAddCompressed(P, Q) {
  const p = pointFromBytes(P);
  const q = pointFromBytes(Q);
  if (!p || !q) return null;
  const result = pointAdd(p, q);
  return pointToBytes(result);
}

/**
 * Compute CARROT account spend public key: K_s = k_gi * G + k_ps * T
 * @param {Uint8Array} k_gi - 32-byte generate-image key
 * @param {Uint8Array} k_ps - 32-byte prove-spend key
 * @returns {Uint8Array} 32-byte compressed public key
 */
export function computeCarrotSpendPubkey(k_gi, k_ps) {
  const giScalar = scalarFromBytes(k_gi);
  const psScalar = scalarFromBytes(k_ps);

  // Get generators
  const G = pointFromXY(GX, GY);
  const T = pointFromBytes(T_BYTES);
  if (!T) throw new Error('Failed to decode T generator');

  // K_s = k_gi * G + k_ps * T
  const giG = scalarMult(G, giScalar);
  const psT = scalarMult(T, psScalar);
  const result = pointAdd(giG, psT);

  return pointToBytes(result);
}

/**
 * Compute CARROT account view public key: K_v = k_vi * K_s
 * Used for subaddress derivation, NOT for main address
 * @param {Uint8Array} k_vi - 32-byte view-incoming key
 * @param {Uint8Array} K_s - 32-byte spend public key
 * @returns {Uint8Array|null} 32-byte compressed view public key, or null if K_s invalid
 */
export function computeCarrotAccountViewPubkey(k_vi, K_s) {
  return scalarMultPoint(k_vi, K_s);
}

/**
 * Compute CARROT main address view public key: K_v = k_vi * G
 * This is what goes into the main address (j=0)
 * @param {Uint8Array} k_vi - 32-byte view-incoming key
 * @returns {Uint8Array} 32-byte compressed view public key
 */
export function computeCarrotMainAddressViewPubkey(k_vi) {
  return scalarMultBase(k_vi);
}

/**
 * Decompress a public key (ge_frombytes_vartime equivalent)
 * @param {Uint8Array} pk - 32-byte compressed public key
 * @returns {Object|null} Point or null if invalid
 */
export { pointFromBytes };

/**
 * Compress a point to bytes (ge_tobytes equivalent)
 * @param {Object} p - Point {X, Y, Z, T}
 * @returns {Uint8Array} 32-byte compressed point
 */
export { pointToBytes };

/**
 * Double scalar multiplication: aP + bG
 * @param {Uint8Array} a - 32-byte scalar
 * @param {Object} P - Point
 * @param {Uint8Array} b - 32-byte scalar
 * @returns {Uint8Array} 32-byte compressed result
 */
export function doubleScalarMultBase(a, P, b) {
  const aScalar = scalarFromBytes(a);
  const bScalar = scalarFromBytes(b);
  const G = pointFromXY(GX, GY);

  // Compute a*P + b*G
  const aP = scalarMult(P, aScalar);
  const bG = scalarMult(G, bScalar);
  const result = pointAdd(aP, bG);

  return pointToBytes(result);
}

/**
 * Check if a point is the identity (neutral element)
 * @param {Uint8Array} p - 32-byte compressed point
 * @returns {boolean} true if identity
 */
export function isIdentity(p) {
  // Identity point encodes as y=1, x=0 -> bytes = [1, 0, 0, ..., 0]
  if (p[0] !== 1) return false;
  for (let i = 1; i < 32; i++) {
    if (p[i] !== 0) return false;
  }
  return true;
}

// Debug functions
export function testDouble() {
  const G = pointFromXY(GX, GY);
  const G2 = pointAdd(G, G);
  return pointToBytes(G2);
}

export function getBasePoint() {
  const G = pointFromXY(GX, GY);
  return pointToBytes(G);
}

export function test2G() {
  const scalar = new Uint8Array(32);
  scalar[0] = 2;
  return scalarMultBase(scalar);
}

// Debug: test G + identity = G
export function testIdentity() {
  const G = pointFromXY(GX, GY);
  const identity = pointZero();
  const result = pointAdd(G, identity);
  return pointToBytes(result);
}

// Debug: get affine coordinates of 2G
export function get2GAffine() {
  const G = pointFromXY(GX, GY);
  const G2 = pointAdd(G, G);
  const zi = feInv(G2.Z);
  const x = feMul(G2.X, zi);
  const y = feMul(G2.Y, zi);
  return { x: x.toString(), y: y.toString() };
}

// Debug: check if point (x,y) is on the curve: -x² + y² = 1 + d*x²*y²
export function isOnCurve(x, y) {
  const x2 = feSq(x);
  const y2 = feSq(y);
  const lhs = feSub(y2, x2);  // -x² + y² = y² - x²
  const rhs = feAdd(1n, feMul(D, feMul(x2, y2)));  // 1 + d*x²*y²
  return lhs === rhs;
}

// Debug: show curve equation values for G
export function debugCurveEquation() {
  const x2 = feSq(GX);
  const y2 = feSq(GY);
  const lhs = feSub(y2, x2);
  const dxy2 = feMul(D, feMul(x2, y2));
  const rhs = feAdd(1n, dxy2);

  return {
    GX: GX.toString(),
    GY: GY.toString(),
    D: D.toString(),
    P: P.toString(),
    x2: x2.toString(),
    y2: y2.toString(),
    lhs: lhs.toString(),  // y² - x²
    dxy2: dxy2.toString(),  // d*x²*y²
    rhs: rhs.toString(),  // 1 + d*x²*y²
    match: lhs === rhs,
    diff: (lhs > rhs ? lhs - rhs : rhs - lhs).toString()
  };
}

// Debug: verify G is on curve
export function checkG() {
  return isOnCurve(GX, GY);
}

// Debug: verify 2G is on curve
export function check2G() {
  const G = pointFromXY(GX, GY);
  const G2 = pointAdd(G, G);
  const zi = feInv(G2.Z);
  const x = feMul(G2.X, zi);
  const y = feMul(G2.Y, zi);
  return isOnCurve(x, y);
}

// Debug: compare doubling methods
export function compare2GMethods() {
  const G = pointFromXY(GX, GY);

  // Method 1: Using pointDouble (Salvium ge_p2_dbl)
  const G2_double = pointDouble(G);
  const zi1 = feInv(G2_double.Z);
  const x1 = feMul(G2_double.X, zi1);
  const y1 = feMul(G2_double.Y, zi1);

  // Method 2: Using unified add formula
  const G2_add = pointAddUnified(G, G);
  const zi2 = feInv(G2_add.Z);
  const x2 = feMul(G2_add.X, zi2);
  const y2 = feMul(G2_add.Y, zi2);

  return {
    doubleX: x1.toString(),
    doubleY: y1.toString(),
    addX: x2.toString(),
    addY: y2.toString(),
    match: x1 === x2 && y1 === y2,
    onCurve1: isOnCurve(x1, y1),
    onCurve2: isOnCurve(x2, y2)
  };
}

// Debug: decode expected 2G from hex and show coordinates
export function decodeExpected2G() {
  // Expected encoding: c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022
  const hex = 'c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022';
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  // Decode using our pointFromBytes
  const point = pointFromBytes(bytes);
  if (!point) return { error: 'Failed to decode point' };

  const zi = feInv(point.Z);
  const x = feMul(point.X, zi);
  const y = feMul(point.Y, zi);

  return {
    x: x.toString(),
    y: y.toString(),
    onCurve: isOnCurve(x, y)
  };
}

// Debug: verify field operations are correct
export function testFieldOps() {
  // Test that (a + b) mod p works
  const a = P - 1n;  // largest value
  const b = 2n;
  const sum = feAdd(a, b);  // should be 1

  // Test subtraction
  const diff = feSub(2n, 5n);  // should be p - 3

  // Test multiplication
  const prod = feMul(GX, GY);

  // Test identity point (0, 1) - must be on ANY Edwards curve
  const identityOnCurve = isOnCurve(0n, 1n);

  // Verify y = 4/5 mod p for base point
  // 5 * GY mod P should equal 4
  const fiveTimesY = feMul(5n, GY);
  const yIsFourFifths = fiveTimesY === 4n;

  return {
    addTest: sum === 1n,
    subTest: diff === P - 3n,
    prodNonZero: prod > 0n && prod < P,
    gxLessThanP: GX < P,
    gyLessThanP: GY < P,
    dLessThanP: D < P,
    identityOnCurve: identityOnCurve,
    yIsFourFifths: yIsFourFifths,
    fiveTimesY: fiveTimesY.toString()
  };
}

// Convert 10-limb ref10 representation to BigInt
// Limbs alternate between 26 and 25 bits: 26,25,26,25,26,25,26,25,26,25
function limbsToFe(limbs) {
  const shifts = [0n, 26n, 51n, 77n, 102n, 128n, 153n, 179n, 204n, 230n];
  let result = 0n;
  for (let i = 0; i < 10; i++) {
    result += BigInt(limbs[i]) << shifts[i];
  }
  // Reduce mod P and handle negatives
  result = ((result % P) + P) % P;
  return result;
}

// Debug: verify our D constant matches Salvium's d.h
export function verifyDConstant() {
  // From Salvium d.h:
  const dLimbs = [-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116];
  const dFromLimbs = limbsToFe(dLimbs);

  // From Salvium d2.h (2*d):
  const d2Limbs = [-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199];
  const d2FromLimbs = limbsToFe(d2Limbs);

  return {
    ourD: D.toString(),
    salviumD: dFromLimbs.toString(),
    dMatch: D === dFromLimbs,
    ourD2: D2.toString(),
    salviumD2: d2FromLimbs.toString(),
    d2Match: D2 === d2FromLimbs
  };
}

// Compute x from y for twisted Edwards curve: -x² + y² = 1 + d*x²*y²
// x² = (y² - 1) / (1 + d*y²)
export function computeXFromY(y) {
  const y2 = feSq(y);
  const num = feSub(y2, 1n);  // y² - 1
  const den = feAdd(1n, feMul(D, y2));  // 1 + d*y²
  const x2 = feMul(num, feInv(den));  // (y² - 1) / (1 + d*y²)

  // Get square root
  const x = feSqrt(x2);
  const xNeg = x ? feNeg(x) : null;

  // Verify x² = x2
  const xSquaredCheck = x ? feSq(x) === x2 : null;

  // Check if computed point is on curve
  const computedOnCurve = x ? isOnCurve(x, y) : null;
  const computedNegOnCurve = xNeg ? isOnCurve(xNeg, y) : null;

  // Check if our GX satisfies x² = x2
  const gxSquared = feSq(GX);
  const gxSatisfiesX2 = gxSquared === x2;

  return {
    x2: x2.toString(),
    x: x ? x.toString() : 'no sqrt exists',
    xNeg: xNeg ? xNeg.toString() : null,
    xSquaredCheck: xSquaredCheck,
    computedOnCurve: computedOnCurve,
    computedNegOnCurve: computedNegOnCurve,
    ourGX: GX.toString(),
    gxSquared: gxSquared.toString(),
    gxSatisfiesX2: gxSatisfiesX2,
    xMatchesGX: x === GX,
    xNegMatchesGX: xNeg === GX
  };
}

/**
 * Generate a random scalar in range [1, L-1]
 * @returns {Uint8Array} 32-byte random scalar
 */
export function randomScalar() {
  // Generate 64 bytes and reduce mod L for uniform distribution
  const bytes64 = getRandomBytes(64);
  let val = 0n;
  for (let i = bytes64.length - 1; i >= 0; i--) {
    val = (val << 8n) | BigInt(bytes64[i]);
  }
  // Reduce mod L and ensure non-zero
  val = val % L;
  if (val === 0n) val = 1n;

  // Convert back to 32 bytes
  const result = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    result[i] = Number(val & 0xffn);
    val = val >> 8n;
  }
  return result;
}

/**
 * Generate a random point on the curve: r*G where r is random
 * @returns {Uint8Array} 32-byte compressed random point
 */
export function randomPoint() {
  const scalar = randomScalar();
  return scalarMultBase(scalar);
}

/**
 * Negate a point: -P
 * @param {Uint8Array} P - 32-byte compressed point
 * @returns {Uint8Array|null} 32-byte compressed negated point, or null if P invalid
 */
export function pointNegate(P) {
  const point = pointFromBytes(P);
  if (!point) return null;

  // Negate: (X, Y, Z, T) -> (-X, Y, Z, -T)
  const negated = {
    X: feNeg(point.X),
    Y: point.Y,
    Z: point.Z,
    T: feNeg(point.T)
  };

  return pointToBytes(negated);
}

/**
 * Point subtraction: P - Q = P + (-Q)
 * @param {Uint8Array} P - 32-byte compressed point
 * @param {Uint8Array} Q - 32-byte compressed point
 * @returns {Uint8Array|null} 32-byte compressed result, or null if invalid
 */
export function pointSubCompressed(P, Q) {
  const negQ = pointNegate(Q);
  if (!negQ) return null;
  return pointAddCompressed(P, negQ);
}

/**
 * Check if a point is valid (on the curve and in the prime-order subgroup)
 * @param {Uint8Array} P - 32-byte compressed point
 * @returns {boolean} true if valid
 */
export function isValidPoint(P) {
  const point = pointFromBytes(P);
  if (!point) return false;

  // Check if on curve
  const zi = feInv(point.Z);
  const x = feMul(point.X, zi);
  const y = feMul(point.Y, zi);
  if (!isOnCurve(x, y)) return false;

  // Check if in prime-order subgroup (L*P = identity)
  const lP = scalarMult(point, L);
  const lPz = feInv(lP.Z);
  const lPx = feMul(lP.X, lPz);
  const lPy = feMul(lP.Y, lPz);

  return lPx === 0n && lPy === 1n;
}

export default {
  scalarCheck,
  scalarIsNonzero,
  scalarSub,
  scalarMultBase,
  scalarMultPoint,
  pointFromBytes,
  pointToBytes,
  pointAddCompressed,
  pointSubCompressed,
  pointNegate,
  randomScalar,
  randomPoint,
  isValidPoint,
  doubleScalarMultBase,
  isIdentity,
  getGeneratorG,
  getGeneratorT,
  computeCarrotSpendPubkey,
  computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey,
  testDouble,
  getBasePoint,
  test2G,
  testIdentity,
  get2GAffine
};
