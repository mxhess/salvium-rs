/// Elligator 2 map: 32-byte hash -> Ed25519 point
/// Ported from Salvium C++ crypto-ops.c ge_fromfe_frombytes_vartime
///
/// This maps a field element (from a hash) to a curve point using the
/// Elligator 2 algorithm. The result is NOT cofactor-cleared — caller
/// must multiply by 8.
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;

/// 256-bit unsigned integer for field arithmetic mod p = 2^255 - 19
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct U256([u64; 4]); // little-endian

impl U256 {
    const ZERO: Self = U256([0, 0, 0, 0]);
    const ONE: Self = U256([1, 0, 0, 0]);
    const TWO: Self = U256([2, 0, 0, 0]);

    // p = 2^255 - 19
    const P: Self = U256([
        0xFFFFFFFFFFFFFFED,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]);

    fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let offset = i * 8;
            *limb = u64::from_le_bytes([
                bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
            ]);
        }
        U256(limbs)
    }

    fn to_bytes_le(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            let bytes = self.0[i].to_le_bytes();
            out[i*8..i*8+8].copy_from_slice(&bytes);
        }
        out
    }

    fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Least significant bit
    fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// Compare: self >= other
    fn ge(&self, other: &Self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > other.0[i] { return true; }
            if self.0[i] < other.0[i] { return false; }
        }
        true // equal
    }

    /// self + other (with carry, no reduction)
    fn add_raw(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for (i, r) in result.iter_mut().enumerate() {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + (carry as u128);
            *r = sum as u64;
            carry = (sum >> 64) as u64;
        }
        (U256(result), carry != 0)
    }

    /// self - other (with borrow, no reduction)
    fn sub_raw(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;
        for (i, r) in result.iter_mut().enumerate() {
            let diff = (self.0[i] as i128) - (other.0[i] as i128) + borrow;
            if diff < 0 {
                *r = (diff + (1i128 << 64)) as u64;
                borrow = -1;
            } else {
                *r = diff as u64;
                borrow = 0;
            }
        }
        (U256(result), borrow != 0)
    }

    /// Reduce mod p
    fn reduce(&self) -> Self {
        let mut r = *self;
        while r.ge(&Self::P) {
            let (sub, _) = r.sub_raw(&Self::P);
            r = sub;
        }
        r
    }
}

// Field operations mod p

fn fe_add(a: &U256, b: &U256) -> U256 {
    let (sum, _carry) = a.add_raw(b);
    sum.reduce()
}

fn fe_sub(a: &U256, b: &U256) -> U256 {
    if a.ge(b) {
        let (diff, _) = a.sub_raw(b);
        diff
    } else {
        let (sum, _) = a.add_raw(&U256::P);
        let (diff, _) = sum.sub_raw(b);
        diff.reduce()
    }
}

/// Multiplication mod p using schoolbook with u128 intermediates
fn fe_mul(a: &U256, b: &U256) -> U256 {
    // Full 512-bit product, then reduce mod p
    let mut prod = [0u128; 8];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let v = (a.0[i] as u128) * (b.0[j] as u128) + prod[i+j] + carry;
            prod[i+j] = v & 0xFFFFFFFFFFFFFFFF;
            carry = v >> 64;
        }
        prod[i+4] += carry;
    }

    // Convert to bytes and reduce mod p using Barrett reduction
    // For simplicity, use repeated subtraction approach with 512-bit number
    reduce_512(&prod)
}

/// Reduce a 512-bit number mod p = 2^255 - 19
fn reduce_512(prod: &[u128; 8]) -> U256 {
    // Strategy: split into low 255 bits and high bits, use p = 2^255 - 19
    // so 2^255 ≡ 19 (mod p), meaning high * 19 + low
    // We need to handle up to 512 bits.

    // Convert product limbs to a big number represented as bytes
    let mut bytes = [0u8; 64];
    for i in 0..8 {
        let b = (prod[i] as u64).to_le_bytes();
        bytes[i*8..i*8+8].copy_from_slice(&b);
    }

    // Use iterative reduction: take top bits, multiply by 19, add to bottom
    // 64 bytes = 512 bits. We reduce to 256 bits then to < p.
    let mut val = [0u128; 5]; // 5 x 64-bit limbs for 320 bits headroom
    for i in 0..8 {
        val[i.min(4)] += prod[i] & 0xFFFFFFFFFFFFFFFF;
    }

    // Actually, let's do this properly with a simple approach:
    // Load as two U256 halves and use 2^256 ≡ 2*19 = 38 (mod p)
    let lo = U256([prod[0] as u64, prod[1] as u64, prod[2] as u64, prod[3] as u64]);
    let hi = U256([prod[4] as u64, prod[5] as u64, prod[6] as u64, prod[7] as u64]);

    // result = lo + hi * 2^256 mod p
    // 2^256 = 2 * 2^255 = 2 * (p + 19) = 2p + 38 ≡ 38 (mod p)
    let hi_times_38 = mul_u256_small(&hi, 38);
    let (sum, carry) = lo.add_raw(&hi_times_38);
    let mut result = sum;
    if carry {
        // carry means we exceeded 2^256, which is another *38
        let (r, _) = result.add_raw(&U256([38, 0, 0, 0]));
        result = r;
    }
    result.reduce()
}

/// Multiply U256 by a small constant
fn mul_u256_small(a: &U256, b: u64) -> U256 {
    let mut result = [0u64; 4];
    let mut carry = 0u128;
    for (i, r) in result.iter_mut().enumerate() {
        let v = (a.0[i] as u128) * (b as u128) + carry;
        *r = v as u64;
        carry = v >> 64;
    }
    // If carry, we need to reduce: carry * 2^256 ≡ carry * 38 (mod p)
    let mut r = U256(result);
    if carry > 0 {
        let extra = U256([carry as u64 * 38, 0, 0, 0]);
        let (sum, _) = r.add_raw(&extra);
        r = sum;
    }
    r.reduce()
}

fn fe_sq(a: &U256) -> U256 {
    fe_mul(a, a)
}

fn fe_neg(a: &U256) -> U256 {
    if a.is_zero() {
        U256::ZERO
    } else {
        let (diff, _) = U256::P.sub_raw(a);
        diff
    }
}

/// Modular exponentiation: base^exp mod p
fn fe_pow(base: &U256, exp: &U256) -> U256 {
    let mut result = U256::ONE;
    let mut b = *base;

    // Process all bits
    for limb_idx in 0..4 {
        let mut bits = exp.0[limb_idx];
        for _ in 0..64 {
            if bits & 1 == 1 {
                result = fe_mul(&result, &b);
            }
            b = fe_sq(&b);
            bits >>= 1;
        }
    }
    result
}

/// Modular inverse: a^(p-2) mod p
fn fe_inv(a: &U256) -> U256 {
    // p - 2
    let exp = U256([
        0xFFFFFFFFFFFFFFEB, // ...ED - 2
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]);
    fe_pow(a, &exp)
}

/// Compute x^((p-5)/8) mod p
/// (p-5)/8 = (2^255 - 24)/8 = 2^252 - 3
fn fe_pow_pm5d8(x: &U256) -> U256 {
    let exp = U256([
        0xFFFFFFFFFFFFFFFF - 2, // 2^252 - 3 in little-endian
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x0FFFFFFFFFFFFFFF,
    ]);
    fe_pow(x, &exp)
}

/// fe_divpowm1: compute (u/v)^((p+3)/8) using the formula:
/// (u/v)^((p+3)/8) = u * v^3 * (u * v^7)^((p-5)/8)
fn fe_divpowm1(u: &U256, v: &U256) -> U256 {
    let v2 = fe_sq(v);
    let v3 = fe_mul(&v2, v);
    let v4 = fe_sq(&v2);
    let v7 = fe_mul(&v4, &v3);
    let uv7 = fe_mul(u, &v7);
    let uv7_pow = fe_pow_pm5d8(&uv7);
    fe_mul(&fe_mul(u, &v3), &uv7_pow)
}

/// Square root mod p
fn fe_sqrt(a: &U256) -> Option<U256> {
    if a.is_zero() { return Some(U256::ZERO); }

    // candidate = a^((p+3)/8)
    let exp = U256([
        0xFFFFFFFFFFFFFFFE, // (2^255 - 19 + 3)/8 = 2^252 - 2
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x0FFFFFFFFFFFFFFF,
    ]);
    let candidate = fe_pow(a, &exp);

    if fe_sq(&candidate) == *a { return Some(candidate); }

    // sqrt(-1) mod p
    let sqrt_m1 = U256::from_bytes_le(&[
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
    ]);
    let adjusted = fe_mul(&candidate, &sqrt_m1);
    if fe_sq(&adjusted) == *a { return Some(adjusted); }

    None
}

/// Precomputed constants
fn sqrt_m1() -> U256 {
    U256::from_bytes_le(&[
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
    ])
}

const A_MONT: u64 = 486662;

/// Main Elligator 2 map: 32-byte hash -> EdwardsPoint (NOT cofactor-cleared)
/// Ported from Salvium C++ crypto-ops.c ge_fromfe_frombytes_vartime
pub fn ge_fromfe_frombytes_vartime(hash: &[u8; 32]) -> EdwardsPoint {
    // Load hash as field element u, reduced mod p
    // The C++ fe_frombytes loads all 256 bits and reduces via carry chain.
    // We load the full value and reduce mod p to match.
    let u = U256::from_bytes_le(hash).reduce();

    let neg_a = fe_neg(&U256([A_MONT, 0, 0, 0]).reduce());
    let neg_a_sq = fe_sq(&U256([A_MONT, 0, 0, 0]).reduce());
    let neg_a_sq = fe_neg(&neg_a_sq);

    // v = 2 * u^2
    let u2 = fe_sq(&u);
    let v = fe_add(&u2, &u2);

    // w = 2*u^2 + 1
    let w = fe_add(&v, &U256::ONE);

    // x = w^2 - 2*A^2*u^2 = w^2 + 2*(-A^2)*u^2
    let w2 = fe_sq(&w);
    let term = fe_mul(&fe_add(&neg_a_sq, &neg_a_sq), &u2); // 2*(-A^2)*u^2
    let mut x = fe_add(&w2, &term);

    // r_X = (w/x)^((p+3)/8) via fe_divpowm1
    let mut r_x = fe_divpowm1(&w, &x);

    // y = r_X^2 * x
    let mut y = fe_mul(&fe_sq(&r_x), &x);

    let sqm1 = sqrt_m1();
    let mut z = neg_a;
    let sign;

    // Check branches
    let diff1 = fe_sub(&w, &y);
    if diff1.is_zero() {
        // y == w
        // fffb2 = sqrt(2*A*(A+2))
        let a_val = U256([A_MONT, 0, 0, 0]).reduce();
        let a_plus_2 = fe_add(&a_val, &U256::TWO);
        let two_a_ap2 = fe_mul(&fe_add(&a_val, &a_val), &a_plus_2);
        if let Some(fffb2) = fe_sqrt(&two_a_ap2) {
            r_x = fe_mul(&r_x, &fffb2);
        }
        r_x = fe_mul(&r_x, &u);
        z = fe_mul(&z, &v);
        sign = false;
    } else {
        let sum1 = fe_add(&w, &y);
        if sum1.is_zero() {
            // y == -w
            // fffb1 = sqrt(-2*A*(A+2))
            let a_val = U256([A_MONT, 0, 0, 0]).reduce();
            let a_plus_2 = fe_add(&a_val, &U256::TWO);
            let two_a_ap2 = fe_mul(&fe_add(&a_val, &a_val), &a_plus_2);
            let neg_two_a_ap2 = fe_neg(&two_a_ap2);
            if let Some(fffb1) = fe_sqrt(&neg_two_a_ap2) {
                r_x = fe_mul(&r_x, &fffb1);
            }
            r_x = fe_mul(&r_x, &u);
            z = fe_mul(&z, &v);
            sign = false;
        } else {
            // Negative branch: multiply x by sqrt(-1)
            x = fe_mul(&x, &sqm1);
            y = fe_mul(&fe_sq(&r_x), &x);

            let diff2 = fe_sub(&w, &y);
            if diff2.is_zero() {
                // fffb4 = sqrt(sqrt(-1)*A*(A+2))
                let a_val = U256([A_MONT, 0, 0, 0]).reduce();
                let a_plus_2 = fe_add(&a_val, &U256::TWO);
                let sqm1_a_ap2 = fe_mul(&sqm1, &fe_mul(&a_val, &a_plus_2));
                if let Some(fffb4) = fe_sqrt(&sqm1_a_ap2) {
                    r_x = fe_mul(&r_x, &fffb4);
                }
            } else {
                // fffb3 = sqrt(-sqrt(-1)*A*(A+2))
                let a_val = U256([A_MONT, 0, 0, 0]).reduce();
                let a_plus_2 = fe_add(&a_val, &U256::TWO);
                let neg_sqm1_a_ap2 = fe_neg(&fe_mul(&sqm1, &fe_mul(&a_val, &a_plus_2)));
                if let Some(fffb3) = fe_sqrt(&neg_sqm1_a_ap2) {
                    r_x = fe_mul(&r_x, &fffb3);
                }
            }
            // z remains as -A
            sign = true;
        }
    }

    // Adjust sign of r_X
    if r_x.is_odd() != sign {
        r_x = fe_neg(&r_x);
    }

    // Compute projective coordinates
    // Z_coord = z + w
    // Y_coord = z - w
    // X_coord = r_X * Z_coord
    let z_coord = fe_add(&z, &w);
    let y_coord = fe_sub(&z, &w);
    let x_coord = fe_mul(&r_x, &z_coord);

    // Convert to affine: x = X/Z, y = Y/Z
    let z_inv = fe_inv(&z_coord);
    let affine_x = fe_mul(&x_coord, &z_inv);
    let affine_y = fe_mul(&y_coord, &z_inv);

    // Compress to Ed25519 format: y with sign bit of x in high bit
    let mut compressed = affine_y.to_bytes_le();
    if affine_x.is_odd() {
        compressed[31] |= 0x80;
    }

    CompressedEdwardsY(compressed).decompress().expect("elligator2 produced invalid point")
}
