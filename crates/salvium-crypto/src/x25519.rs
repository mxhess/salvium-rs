//! Montgomery ladder for X25519 scalar multiplication.
//!
//! This is a self-contained, constant-time implementation of the X25519
//! Montgomery ladder over GF(2^255 - 19). It does NOT apply any clamping —
//! the caller (lib.rs) is responsible for applying Salvium's non-standard
//! clamping before calling `montgomery_ladder`.
//!
//! The ladder follows the algorithm in RFC 7748 Section 5, but without the
//! clamping steps (decodeScalar25519), since Salvium uses its own clamping.
//!
//! Field: GF(p) where p = 2^255 - 19
//! Curve: v^2 = u^3 + A*u^2 + u, with A = 486662, a24 = (A - 2) / 4 = 121666

/// 2 * p (for subtraction without underflow, where p = 2^255 - 19)
const P2: [u64; 5] = [
    0x7FFFFFFFFFFED * 2,
    0x7FFFFFFFFFFFF * 2,
    0x7FFFFFFFFFFFF * 2,
    0x7FFFFFFFFFFFF * 2,
    0x7FFFFFFFFFFFF * 2,
];

/// a24 = 121666
const A24: u64 = 121666;

/// Field element in radix-2^51 representation (5 limbs).
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Decode a 32-byte little-endian integer into a field element.
    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let mut h = [0u64; 5];
        // Load 256 bits into 5 × 51-bit limbs
        let load = |src: &[u8]| -> u64 {
            let mut buf = [0u8; 8];
            let len = src.len().min(8);
            buf[..len].copy_from_slice(&src[..len]);
            u64::from_le_bytes(buf)
        };
        h[0] = load(&bytes[0..]) & 0x7FFFFFFFFFFFF;
        h[1] = (load(&bytes[6..]) >> 3) & 0x7FFFFFFFFFFFF;
        h[2] = (load(&bytes[12..]) >> 6) & 0x7FFFFFFFFFFFF;
        h[3] = (load(&bytes[19..]) >> 1) & 0x7FFFFFFFFFFFF;
        h[4] = (load(&bytes[24..]) >> 12) & 0x7FFFFFFFFFFFF;
        Fe(h)
    }

    /// Encode a field element to 32-byte little-endian, fully reduced mod p.
    #[allow(clippy::needless_range_loop)]
    fn to_bytes(self) -> [u8; 32] {
        let mut h = self.0;
        // Carry and reduce
        let mut carry: i64;

        // First pass: propagate carries
        for i in 0..4 {
            carry = h[i] as i64 >> 51;
            h[i] &= 0x7FFFFFFFFFFFF;
            h[i + 1] = (h[i + 1] as i64 + carry) as u64;
        }
        carry = h[4] as i64 >> 51;
        h[4] &= 0x7FFFFFFFFFFFF;
        h[0] = (h[0] as i64 + carry * 19) as u64;

        // Second pass
        for i in 0..4 {
            carry = h[i] as i64 >> 51;
            h[i] &= 0x7FFFFFFFFFFFF;
            h[i + 1] = (h[i + 1] as i64 + carry) as u64;
        }
        carry = h[4] as i64 >> 51;
        h[4] &= 0x7FFFFFFFFFFFF;
        h[0] = (h[0] as i64 + carry * 19) as u64;

        // Now h is in [0, 2^255-1]. Need to reduce mod p.
        // Check if h >= p and subtract if so.
        // h >= p iff h + 19 >= 2^255
        let mut q = (h[0] + 19) >> 51;
        for i in 1..5 {
            q = (h[i] + q) >> 51;
        }
        // q is 0 or 1. If 1, h >= p, subtract p (add 19, then mask).
        h[0] += 19 * q;
        carry = h[0] as i64 >> 51;
        h[0] &= 0x7FFFFFFFFFFFF;
        for i in 1..4 {
            h[i] = (h[i] as i64 + carry) as u64;
            carry = h[i] as i64 >> 51;
            h[i] &= 0x7FFFFFFFFFFFF;
        }
        h[4] = (h[4] as i64 + carry) as u64;
        h[4] &= 0x7FFFFFFFFFFFF;

        // Pack 5 × 51-bit limbs into a 256-bit number stored in 4 × u64s
        let mut out = [0u8; 32];
        let t0 = h[0] | (h[1] << 51);
        let t1 = (h[1] >> 13) | (h[2] << 38);
        let t2 = (h[2] >> 26) | (h[3] << 25);
        let t3 = (h[3] >> 39) | (h[4] << 12);

        out[0..8].copy_from_slice(&t0.to_le_bytes());
        out[8..16].copy_from_slice(&t1.to_le_bytes());
        out[16..24].copy_from_slice(&t2.to_le_bytes());
        out[24..32].copy_from_slice(&t3.to_le_bytes());

        out
    }

    /// Field addition: a + b
    fn add(a: &Fe, b: &Fe) -> Fe {
        Fe([
            a.0[0] + b.0[0],
            a.0[1] + b.0[1],
            a.0[2] + b.0[2],
            a.0[3] + b.0[3],
            a.0[4] + b.0[4],
        ])
    }

    /// Field subtraction: a - b (adds 2p first to avoid underflow)
    fn sub(a: &Fe, b: &Fe) -> Fe {
        Fe([
            a.0[0] + P2[0] - b.0[0],
            a.0[1] + P2[1] - b.0[1],
            a.0[2] + P2[2] - b.0[2],
            a.0[3] + P2[3] - b.0[3],
            a.0[4] + P2[4] - b.0[4],
        ])
    }

    /// Carry-reduce a field element to keep limbs in ~51-bit range.
    fn carry_reduce(&self) -> Fe {
        let mut h = self.0;
        let mut carry: u64;
        for i in 0..4 {
            carry = h[i] >> 51;
            h[i] &= 0x7FFFFFFFFFFFF;
            h[i + 1] += carry;
        }
        carry = h[4] >> 51;
        h[4] &= 0x7FFFFFFFFFFFF;
        h[0] += carry * 19;
        // One more pass for h[0]
        carry = h[0] >> 51;
        h[0] &= 0x7FFFFFFFFFFFF;
        h[1] += carry;
        Fe(h)
    }

    /// Field multiplication: a * b mod p
    fn mul(a: &Fe, b: &Fe) -> Fe {
        // Schoolbook multiplication with 128-bit intermediates
        let (a0, a1, a2, a3, a4) = (a.0[0] as u128, a.0[1] as u128, a.0[2] as u128, a.0[3] as u128, a.0[4] as u128);
        let (b0, b1, b2, b3, b4) = (b.0[0] as u128, b.0[1] as u128, b.0[2] as u128, b.0[3] as u128, b.0[4] as u128);

        // Precompute 19*b_i for reduction
        let b1_19 = 19 * b1;
        let b2_19 = 19 * b2;
        let b3_19 = 19 * b3;
        let b4_19 = 19 * b4;

        // Compute product limbs with reduction (terms that overflow 5 limbs
        // wrap around with factor 19, since 2^255 ≡ 19 mod p)
        let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        // Carry propagation
        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;
        let carry = t1 >> 51; t1 &= 0x7FFFFFFFFFFFF; t2 += carry;
        let carry = t2 >> 51; t2 &= 0x7FFFFFFFFFFFF; t3 += carry;
        let carry = t3 >> 51; t3 &= 0x7FFFFFFFFFFFF; t4 += carry;
        let carry = t4 >> 51; t4 &= 0x7FFFFFFFFFFFF; t0 += carry * 19;
        // One more carry for t0
        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;

        Fe([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
    }

    /// Field squaring: a^2 mod p (optimized)
    fn sq(a: &Fe) -> Fe {
        let (a0, a1, a2, a3, a4) = (a.0[0] as u128, a.0[1] as u128, a.0[2] as u128, a.0[3] as u128, a.0[4] as u128);

        // Double cross terms
        let d0 = 2 * a0;
        let d1 = 2 * a1;

        let a1_38 = 38 * a1;
        let a2_38 = 38 * a2;
        let a3_38 = 38 * a3;
        let a4_19 = 19 * a4;

        let mut t0 = a0 * a0 + a1_38 * a4 + a2_38 * a3;
        let mut t1 = d0 * a1 + a2_38 * a4 + 19 * a3 * a3;
        let mut t2 = d0 * a2 + a1 * a1 + a3_38 * a4;
        let mut t3 = d0 * a3 + d1 * a2 + a4_19 * a4;
        let mut t4 = d0 * a4 + d1 * a3 + a2 * a2;

        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;
        let carry = t1 >> 51; t1 &= 0x7FFFFFFFFFFFF; t2 += carry;
        let carry = t2 >> 51; t2 &= 0x7FFFFFFFFFFFF; t3 += carry;
        let carry = t3 >> 51; t3 &= 0x7FFFFFFFFFFFF; t4 += carry;
        let carry = t4 >> 51; t4 &= 0x7FFFFFFFFFFFF; t0 += carry * 19;
        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;

        Fe([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
    }

    /// Field multiplication by a small constant
    fn mul_small(a: &Fe, c: u64) -> Fe {
        let c = c as u128;
        let mut t0 = a.0[0] as u128 * c;
        let mut t1 = a.0[1] as u128 * c;
        let mut t2 = a.0[2] as u128 * c;
        let mut t3 = a.0[3] as u128 * c;
        let mut t4 = a.0[4] as u128 * c;

        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;
        let carry = t1 >> 51; t1 &= 0x7FFFFFFFFFFFF; t2 += carry;
        let carry = t2 >> 51; t2 &= 0x7FFFFFFFFFFFF; t3 += carry;
        let carry = t3 >> 51; t3 &= 0x7FFFFFFFFFFFF; t4 += carry;
        let carry = t4 >> 51; t4 &= 0x7FFFFFFFFFFFF; t0 += carry * 19;
        let carry = t0 >> 51; t0 &= 0x7FFFFFFFFFFFF; t1 += carry;

        Fe([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
    }

    /// Field inversion: a^(-1) mod p = a^(p-2) mod p
    /// Uses the addition chain for p-2 = 2^255 - 21
    fn invert(a: &Fe) -> Fe {
        // Compute a^(p-2) via the standard addition chain for 2^255 - 21
        let z2 = Fe::sq(a);                     // a^2
        let z9 = {
            let t = Fe::sq(&z2);                // a^4
            let t = Fe::sq(&t);                 // a^8
            Fe::mul(&t, a)                      // a^9
        };
        let z11 = Fe::mul(&z9, &z2);           // a^11
        let z_5_0 = {
            let t = Fe::sq(&z11);               // a^22
            Fe::mul(&t, &z9)                    // a^31 = a^(2^5 - 1)
        };
        let z_10_0 = {
            let mut t = Fe::sq(&z_5_0);         // a^(2^6 - 2)
            for _ in 1..5 { t = Fe::sq(&t); }   // a^(2^10 - 2^5)
            Fe::mul(&t, &z_5_0)                 // a^(2^10 - 1)
        };
        let z_20_0 = {
            let mut t = Fe::sq(&z_10_0);
            for _ in 1..10 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_10_0)                // a^(2^20 - 1)
        };
        let z_40_0 = {
            let mut t = Fe::sq(&z_20_0);
            for _ in 1..20 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_20_0)                // a^(2^40 - 1)
        };
        let z_50_0 = {
            let mut t = Fe::sq(&z_40_0);
            for _ in 1..10 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_10_0)                // a^(2^50 - 1)
        };
        let z_100_0 = {
            let mut t = Fe::sq(&z_50_0);
            for _ in 1..50 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_50_0)                // a^(2^100 - 1)
        };
        let z_200_0 = {
            let mut t = Fe::sq(&z_100_0);
            for _ in 1..100 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_100_0)               // a^(2^200 - 1)
        };
        let z_250_0 = {
            let mut t = Fe::sq(&z_200_0);
            for _ in 1..50 { t = Fe::sq(&t); }
            Fe::mul(&t, &z_50_0)                // a^(2^250 - 1)
        };
        {
            let mut t = Fe::sq(&z_250_0);
            for _ in 1..5 { t = Fe::sq(&t); }   // a^(2^255 - 32)
            Fe::mul(&t, &z11)                   // a^(2^255 - 21) = a^(p-2)
        }
    }

    /// Constant-time conditional swap: if swap != 0, swap a and b.
    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap); // 0 or 0xFFFF...
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}

/// Convert Ed25519 compressed point to X25519 u-coordinate.
/// u = (1 + y) / (1 - y) mod p, where y is the Ed25519 y-coordinate.
pub(crate) fn edwards_to_montgomery_u(ed_point: &[u8; 32]) -> [u8; 32] {
    // Extract y-coordinate (clear the sign bit in the high byte)
    let mut y_bytes = *ed_point;
    y_bytes[31] &= 0x7F;
    let y = Fe::from_bytes(&y_bytes);

    // u = (1 + y) / (1 - y)
    let numerator = Fe::add(&Fe::ONE, &y).carry_reduce();
    let denominator = Fe::sub(&Fe::ONE, &y).carry_reduce();
    let inv_denom = Fe::invert(&denominator);
    let u = Fe::mul(&numerator, &inv_denom);
    u.to_bytes()
}

/// Montgomery ladder: compute scalar * u_point on Curve25519 (Montgomery form).
///
/// scalar: 32-byte little-endian scalar (already clamped by caller).
/// u_coord: 32-byte little-endian u-coordinate of the point.
///
/// Returns the 32-byte little-endian u-coordinate of the result.
///
/// This follows RFC 7748 Section 5 algorithm, but WITHOUT applying
/// decodeScalar25519 (clamping), since the caller handles that.
pub(crate) fn montgomery_ladder(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    let u = Fe::from_bytes(u_coord);

    // Montgomery ladder state: (x_2, z_2) and (x_3, z_3)
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = u;
    let mut z_3 = Fe::ONE;

    let mut swap: u64 = 0;

    // Process bits from 254 down to 0 (bit 255 is always 0 after clamping)
    for pos in (0..=254).rev() {
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        let k_t = ((scalar[byte_idx] >> bit_idx) & 1) as u64;

        swap ^= k_t;
        Fe::cswap(&mut x_2, &mut x_3, swap);
        Fe::cswap(&mut z_2, &mut z_3, swap);
        swap = k_t;

        let a = Fe::add(&x_2, &z_2).carry_reduce();
        let aa = Fe::sq(&a);
        let b = Fe::sub(&x_2, &z_2).carry_reduce();
        let bb = Fe::sq(&b);
        let e = Fe::sub(&aa, &bb).carry_reduce();
        let c = Fe::add(&x_3, &z_3).carry_reduce();
        let d = Fe::sub(&x_3, &z_3).carry_reduce();
        let da = Fe::mul(&d, &a);
        let cb = Fe::mul(&c, &b);
        x_3 = Fe::sq(&Fe::add(&da, &cb).carry_reduce());
        z_3 = Fe::mul(&u, &Fe::sq(&Fe::sub(&da, &cb).carry_reduce()));
        x_2 = Fe::mul(&aa, &bb);
        z_2 = Fe::mul(&e, &Fe::add(&bb, &Fe::mul_small(&e, A24)).carry_reduce());
    }

    Fe::cswap(&mut x_2, &mut x_3, swap);
    Fe::cswap(&mut z_2, &mut z_3, swap);

    // Result = x_2 / z_2 = x_2 * z_2^(-1)
    let z_inv = Fe::invert(&z_2);
    let result = Fe::mul(&x_2, &z_inv);
    result.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fe_roundtrip() {
        // Test that from_bytes -> to_bytes is identity for a known value
        let mut bytes = [0u8; 32];
        bytes[0] = 9; // u = 9 (X25519 basepoint)
        let fe = Fe::from_bytes(&bytes);
        let out = fe.to_bytes();
        assert_eq!(out, bytes);
    }

    #[test]
    fn test_fe_one() {
        let one = Fe::ONE;
        let bytes = one.to_bytes();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_fe_zero() {
        let zero = Fe::ZERO;
        let bytes = zero.to_bytes();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_fe_mul_identity() {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let a = Fe::from_bytes(&bytes);
        let result = Fe::mul(&a, &Fe::ONE);
        assert_eq!(result.to_bytes(), bytes);
    }

    #[test]
    fn test_fe_invert() {
        let mut bytes = [0u8; 32];
        bytes[0] = 9;
        let a = Fe::from_bytes(&bytes);
        let inv = Fe::invert(&a);
        let product = Fe::mul(&a, &inv);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(product.to_bytes(), expected);
    }

    #[test]
    fn test_rfc7748_basepoint_scalar() {
        // RFC 7748 Section 6.1 test vector (but with standard clamping applied
        // to the scalar manually, since our ladder doesn't clamp)
        //
        // Input scalar (after standard clamping):
        //   a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
        //   Clamped: a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44
        // Input u-coordinate:
        //   e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
        // Expected output:
        //   c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
        let scalar_hex = "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44";
        let u_hex = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
        let expected_hex = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

        let scalar = hex_to_bytes32(scalar_hex);
        let u = hex_to_bytes32(u_hex);
        let expected = hex_to_bytes32(expected_hex);

        let result = montgomery_ladder(&scalar, &u);
        assert_eq!(result, expected, "RFC 7748 test vector mismatch");
    }

    #[test]
    fn test_rfc7748_second_vector() {
        // RFC 7748 Section 6.1, second test vector (after standard clamping)
        // Input scalar (clamped):
        //   4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
        //   Clamped: 4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d
        // Input u:
        //   e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
        // Expected:
        //   95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957
        let scalar_hex = "4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d";
        let u_hex = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
        let expected_hex = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

        let scalar = hex_to_bytes32(scalar_hex);
        let u = hex_to_bytes32(u_hex);
        let expected = hex_to_bytes32(expected_hex);

        let result = montgomery_ladder(&scalar, &u);
        assert_eq!(result, expected, "RFC 7748 second test vector mismatch");
    }

    #[test]
    fn test_salvium_clamping_differs_from_rfc7748() {
        // Verify that Salvium clamping (only clear bit 255) differs from
        // RFC 7748 clamping (clear bits 0,1,2, set bit 254, clear bit 255)
        // when bits 0-2 or bit 254 matter.
        let mut scalar = [0u8; 32];
        scalar[0] = 0x07; // bits 0,1,2 set
        scalar[31] = 0x80; // bit 255 set

        // Salvium clamping: only clear bit 255
        let mut salvium_clamped = scalar;
        salvium_clamped[31] &= 0x7F;
        assert_eq!(salvium_clamped[0], 0x07); // bits 0-2 preserved
        assert_eq!(salvium_clamped[31] & 0x40, 0x00); // bit 254 NOT set

        // RFC 7748 clamping would be:
        let mut rfc_clamped = scalar;
        rfc_clamped[0] &= 0xF8; // clear bits 0,1,2
        rfc_clamped[31] &= 0x7F; // clear bit 255
        rfc_clamped[31] |= 0x40; // set bit 254

        // They should differ
        assert_ne!(salvium_clamped, rfc_clamped);
    }

    #[test]
    fn test_x25519_basepoint() {
        // Scalar 9 * basepoint(9) should give a known result
        // This is the first iteration of the iterated X25519 test
        let mut scalar = [0u8; 32];
        scalar[0] = 9;
        let mut u = [0u8; 32];
        u[0] = 9;

        // Apply Salvium clamping: only clear bit 255
        // scalar[31] is 0, so bit 255 is already clear — no change
        let result = montgomery_ladder(&scalar, &u);

        // The result should be a valid 32-byte value, not all zeros
        assert_ne!(result, [0u8; 32]);
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
        }
        out
    }
}
