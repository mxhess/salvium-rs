//! Multisig key image computation for CryptoNote and CARROT outputs.
//!
//! In multisig, each signer holds a weighted share of the private key.
//! Key images are computed additively: each signer produces a partial key image
//! using their weighted share, and the partial key images are summed to produce
//! the full key image.
//!
//! For CryptoNote:
//!   partial_ki_i = weighted_key_share_i * H_p(output_pubkey)
//!   full_ki = sum(partial_ki_i)
//!
//! For CARROT (TCLSAG):
//!   The spend key is split into G-component (k_gi) and extension (k^o_g).
//!   Each signer produces: partial_ki_i = (coeff_i * k_gi_i) * H_p(Ko)
//!   One designated signer adds: + k^o_g * H_p(Ko)
//!   full_ki = sum(partial_ki_i)

/// Compute a partial key image for one output (CryptoNote).
///
/// `partial_ki = weighted_key_share * H_p(output_pubkey)`
///
/// The weighted key share should already include the aggregation coefficient:
/// `weighted_key_share = coeff_i * k_i`
pub fn compute_partial_key_image(
    weighted_key_share: &[u8; 32],
    output_pubkey: &[u8; 32],
) -> [u8; 32] {
    let hp = salvium_crypto::hash_to_point(output_pubkey);
    let result = salvium_crypto::scalar_mult_point(weighted_key_share, &hp);
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&result);
    ki
}

/// Combine partial key images from threshold signers.
///
/// `full_ki = sum(partial_ki_i)`
///
/// # Errors
/// Returns `Err` if the partials slice is empty.
pub fn combine_partial_key_images(partials: &[[u8; 32]]) -> Result<[u8; 32], String> {
    if partials.is_empty() {
        return Err("no partial key images to combine".to_string());
    }

    let mut combined = partials[0];
    for partial in &partials[1..] {
        let sum = salvium_crypto::point_add_compressed(&combined, partial);
        combined.copy_from_slice(&sum[..32]);
    }

    Ok(combined)
}

/// Compute a partial CARROT key image for the G-component (k_x).
///
/// For CARROT outputs, the spend key on the G-component is:
///   sk_x = k_gi + k^o_g
///
/// where k^o_g is a deterministic extension scalar derived from the scanning
/// shared secret and commitment. Since k^o_g is public (all signers can compute
/// it), only ONE signer adds it to their share to maintain additive sharing:
///
///   signer 0: partial_ki = (coeff_0 * k_gi_0 + k^o_g) * H_p(Ko)
///   signer i: partial_ki = (coeff_i * k_gi_i) * H_p(Ko)
///
/// The `extension_scalar` should be `k^o_g` for the designated signer (typically
/// signer 0) and all-zeros for other signers.
pub fn compute_partial_carrot_key_image(
    weighted_gi_share: &[u8; 32],
    output_pubkey: &[u8; 32],
    extension_scalar: &[u8; 32],
) -> [u8; 32] {
    // effective_share = weighted_gi_share + extension_scalar
    let effective = salvium_crypto::sc_add(weighted_gi_share, extension_scalar);
    let mut eff32 = [0u8; 32];
    eff32.copy_from_slice(&effective[..32]);

    let hp = salvium_crypto::hash_to_point(output_pubkey);
    let result = salvium_crypto::scalar_mult_point(&eff32, &hp);
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&result);
    ki
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scalar(seed: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = seed;
        let r = salvium_crypto::sc_reduce32(&s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&r[..32]);
        a
    }

    fn make_point(seed: u8) -> [u8; 32] {
        let s = make_scalar(seed);
        let p = salvium_crypto::scalar_mult_base(&s);
        let mut r = [0u8; 32];
        r.copy_from_slice(&p);
        r
    }

    #[test]
    fn test_partial_key_image_deterministic() {
        let share = make_scalar(42);
        let pubkey = make_point(7);
        let ki1 = compute_partial_key_image(&share, &pubkey);
        let ki2 = compute_partial_key_image(&share, &pubkey);
        assert_eq!(ki1, ki2);
        assert_ne!(ki1, [0u8; 32]);
    }

    #[test]
    fn test_partial_key_image_different_keys_differ() {
        let pubkey = make_point(7);
        let ki1 = compute_partial_key_image(&make_scalar(10), &pubkey);
        let ki2 = compute_partial_key_image(&make_scalar(20), &pubkey);
        assert_ne!(ki1, ki2);
    }

    #[test]
    fn test_combine_matches_single_signer() {
        let secret = make_scalar(55);
        let pubkey = {
            let p = salvium_crypto::scalar_mult_base(&secret);
            let mut r = [0u8; 32];
            r.copy_from_slice(&p);
            r
        };

        let full_ki = salvium_crypto::generate_key_image(&pubkey, &secret);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&full_ki);

        let partial = compute_partial_key_image(&secret, &pubkey);
        assert_eq!(partial, expected);
    }

    #[test]
    fn test_combine_two_partials() {
        let share0 = make_scalar(10);
        let share1 = make_scalar(20);

        // output_pubkey = (share0 + share1) * G
        let combined_secret = {
            let s = salvium_crypto::sc_add(&share0, &share1);
            let mut a = [0u8; 32];
            a.copy_from_slice(&s[..32]);
            a
        };
        let pubkey = {
            let p = salvium_crypto::scalar_mult_base(&combined_secret);
            let mut r = [0u8; 32];
            r.copy_from_slice(&p);
            r
        };

        let pki0 = compute_partial_key_image(&share0, &pubkey);
        let pki1 = compute_partial_key_image(&share1, &pubkey);
        let combined = combine_partial_key_images(&[pki0, pki1]).unwrap();

        let expected = salvium_crypto::generate_key_image(&pubkey, &combined_secret);
        let mut exp32 = [0u8; 32];
        exp32.copy_from_slice(&expected);

        assert_eq!(combined, exp32);
    }

    #[test]
    fn test_combine_empty_fails() {
        let result = combine_partial_key_images(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_carrot_partial_key_image_with_extension() {
        let weighted_share = make_scalar(10);
        let extension = make_scalar(5);
        let pubkey = make_point(7);
        let zero = [0u8; 32];

        // With extension should differ from without
        let ki_with = compute_partial_carrot_key_image(&weighted_share, &pubkey, &extension);
        let ki_without = compute_partial_carrot_key_image(&weighted_share, &pubkey, &zero);
        assert_ne!(ki_with, ki_without);

        // Manually compute: (weighted + extension) * H_p(pubkey)
        let combined_scalar = {
            let s = salvium_crypto::sc_add(&weighted_share, &extension);
            let mut a = [0u8; 32];
            a.copy_from_slice(&s[..32]);
            a
        };
        let expected = compute_partial_key_image(&combined_scalar, &pubkey);
        assert_eq!(ki_with, expected);
    }

    #[test]
    fn test_carrot_partial_zero_extension_equals_standard() {
        let weighted_share = make_scalar(42);
        let pubkey = make_point(7);
        let zero = [0u8; 32];

        let carrot = compute_partial_carrot_key_image(&weighted_share, &pubkey, &zero);
        let standard = compute_partial_key_image(&weighted_share, &pubkey);
        assert_eq!(carrot, standard);
    }
}
