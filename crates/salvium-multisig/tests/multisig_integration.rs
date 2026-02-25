//! Comprehensive multisig integration tests.
//!
//! Covers KEX protocol (positive + negative), CLSAG/TCLSAG signing,
//! MultisigTxSet lifecycle, and end-to-end workflows.

use salvium_multisig::account::MultisigAccount;
use salvium_multisig::carrot::MultisigCarrotAccount;
use salvium_multisig::constants::MULTISIG_MAX_SIGNERS;
use salvium_multisig::kex::{kex_rounds_required, KexMessage};
use salvium_multisig::signing::{
    combine_partial_signatures, combine_partial_signatures_ext, compute_nonce_binding,
    generate_nonces, generate_nonces_ext, partial_sign, partial_sign_tclsag, MultisigClsagContext,
    SignerNonces,
};
use salvium_multisig::tx_set::{MultisigTxSet, PendingMultisigTx};
use salvium_multisig::wallet::{
    compute_dh_secret, create_multisig_wallet, generate_multisig_nonces,
    get_multisig_blinded_secret_key, nonce_to_public,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a random valid Ed25519 scalar. Returns (hex, bytes).
fn generate_random_scalar() -> (String, [u8; 32]) {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    let reduced = salvium_crypto::sc_reduce32(&buf);
    let mut s = [0u8; 32];
    s.copy_from_slice(&reduced[..32]);
    (hex::encode(s), s)
}

/// Run a complete KEX protocol for an M-of-N multisig group.
/// Returns the completed accounts.
fn run_full_kex(threshold: usize, signer_count: usize) -> Vec<MultisigAccount> {
    let mut accounts: Vec<MultisigAccount> = (0..signer_count)
        .map(|_| MultisigAccount::new(threshold, signer_count).unwrap())
        .collect();

    // Generate keys and set indices
    let keys: Vec<(String, String)> = (0..signer_count)
        .map(|_| {
            let (spend_hex, _) = generate_random_scalar();
            let (view_hex, _) = generate_random_scalar();
            (spend_hex, view_hex)
        })
        .collect();

    for (i, acct) in accounts.iter_mut().enumerate() {
        acct.set_signer_index(i);
    }

    // Initialize KEX and collect round-1 messages
    let round1_msgs: Vec<KexMessage> = accounts
        .iter_mut()
        .enumerate()
        .map(|(i, acct)| acct.initialize_kex(&keys[i].0, &keys[i].1).unwrap())
        .collect();

    // Register signers on all accounts
    for acct in accounts.iter_mut() {
        acct.register_signers(&round1_msgs).unwrap();
    }

    // Process round 1
    let mut next_msgs: Vec<Option<KexMessage>> = Vec::new();
    for acct in accounts.iter_mut() {
        let out = acct.process_kex_round(&round1_msgs).unwrap();
        next_msgs.push(out);
    }

    // If there are more rounds, keep going
    if next_msgs[0].is_some() {
        let mut current_msgs: Vec<KexMessage> = next_msgs.into_iter().map(|m| m.unwrap()).collect();

        loop {
            let mut next = Vec::new();
            for acct in accounts.iter_mut() {
                let out = acct.process_kex_round(&current_msgs).unwrap();
                next.push(out);
            }

            if next[0].is_none() {
                // KEX complete
                break;
            }
            current_msgs = next.into_iter().map(|m| m.unwrap()).collect();
        }
    }

    // Verify all accounts completed KEX
    for acct in &accounts {
        assert!(
            acct.is_kex_complete(),
            "KEX not complete for signer {}",
            acct.signer_index
        );
    }

    accounts
}

/// Create a synthetic CLSAG signing context.
fn make_signing_context(ring_size: usize) -> MultisigClsagContext {
    let ring: Vec<String> = (0..ring_size)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0] = (i + 1) as u8;
            let reduced = salvium_crypto::sc_reduce32(&s);
            hex::encode(salvium_crypto::scalar_mult_base(&reduced))
        })
        .collect();

    let commitments: Vec<String> = (0..ring_size)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0] = (i + 50) as u8;
            let reduced = salvium_crypto::sc_reduce32(&s);
            hex::encode(salvium_crypto::scalar_mult_base(&reduced))
        })
        .collect();

    let ki_scalar = {
        let mut s = [0u8; 32];
        s[0] = 99;
        salvium_crypto::sc_reduce32(&s)
    };
    let key_image = hex::encode(salvium_crypto::scalar_mult_base(&ki_scalar));

    let pseudo = {
        let mut s = [0u8; 32];
        s[0] = 77;
        let reduced = salvium_crypto::sc_reduce32(&s);
        hex::encode(salvium_crypto::scalar_mult_base(&reduced))
    };

    MultisigClsagContext {
        ring,
        commitments,
        key_image,
        pseudo_output_commitment: pseudo,
        message: "aa".repeat(32),
        real_index: 0,
        use_tclsag: false,
        key_image_y: None,
    }
}

/// Create a synthetic TCLSAG signing context.
fn make_tclsag_context(ring_size: usize) -> MultisigClsagContext {
    let mut ctx = make_signing_context(ring_size);
    ctx.use_tclsag = true;
    let ki_y_scalar = {
        let mut s = [0u8; 32];
        s[0] = 88;
        salvium_crypto::sc_reduce32(&s)
    };
    ctx.key_image_y = Some(hex::encode(salvium_crypto::scalar_mult_base(&ki_y_scalar)));
    ctx
}

// ===========================================================================
// KEX Positive Tests
// ===========================================================================

#[test]
fn test_kex_2_of_2_completes() {
    let accounts = run_full_kex(2, 2);
    assert!(accounts[0].multisig_pubkey.is_some());
    assert!(accounts[1].multisig_pubkey.is_some());
    assert_eq!(accounts[0].multisig_pubkey, accounts[1].multisig_pubkey);
    assert_eq!(accounts[0].common_pubkey, accounts[1].common_pubkey);
}

#[test]
fn test_kex_2_of_3_completes() {
    let accounts = run_full_kex(2, 3);
    let pk0 = accounts[0].multisig_pubkey.as_ref().unwrap();
    let pk1 = accounts[1].multisig_pubkey.as_ref().unwrap();
    let pk2 = accounts[2].multisig_pubkey.as_ref().unwrap();
    assert_eq!(pk0, pk1);
    assert_eq!(pk1, pk2);
}

#[test]
fn test_kex_3_of_3_completes() {
    let accounts = run_full_kex(3, 3);
    let pks: Vec<_> = accounts
        .iter()
        .map(|a| a.multisig_pubkey.as_ref().unwrap().clone())
        .collect();
    assert!(pks.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn test_kex_3_of_5_completes() {
    let accounts = run_full_kex(3, 5);
    let pks: Vec<_> = accounts
        .iter()
        .map(|a| a.multisig_pubkey.as_ref().unwrap().clone())
        .collect();
    assert!(pks.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn test_kex_2_of_8_completes() {
    let accounts = run_full_kex(2, 8);
    let pks: Vec<_> = accounts
        .iter()
        .map(|a| a.multisig_pubkey.as_ref().unwrap().clone())
        .collect();
    assert!(pks.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn test_kex_different_keys_different_aggregates() {
    let a = run_full_kex(2, 2);
    let b = run_full_kex(2, 2);
    assert_ne!(a[0].multisig_pubkey, b[0].multisig_pubkey);
}

#[test]
fn test_kex_deterministic_with_same_keys() {
    let spend0 = "11".repeat(32);
    let view0 = "22".repeat(32);
    let spend1 = "33".repeat(32);
    let view1 = "44".repeat(32);

    let run = || {
        let mut accounts = [
            MultisigAccount::new(2, 2).unwrap(),
            MultisigAccount::new(2, 2).unwrap(),
        ];
        accounts[0].set_signer_index(0);
        accounts[1].set_signer_index(1);

        let msg0 = accounts[0].initialize_kex(&spend0, &view0).unwrap();
        let msg1 = accounts[1].initialize_kex(&spend1, &view1).unwrap();

        let msgs = vec![msg0, msg1];
        for a in accounts.iter_mut() {
            a.register_signers(&msgs).unwrap();
        }

        let mut round_msgs: Vec<KexMessage> = Vec::new();
        for a in accounts.iter_mut() {
            let out = a.process_kex_round(&msgs).unwrap();
            round_msgs.push(out.unwrap());
        }

        // Verification round
        for a in accounts.iter_mut() {
            a.process_kex_round(&round_msgs).unwrap();
        }

        accounts[0].multisig_pubkey.clone().unwrap()
    };

    assert_eq!(run(), run());
}

#[test]
fn test_kex_signer_registration() {
    let mut acct = MultisigAccount::new(2, 3).unwrap();
    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["aa".repeat(32), "bb".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 2,
            keys: vec!["ee".repeat(32), "ff".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    acct.register_signers(&msgs).unwrap();
    assert_eq!(acct.signers.len(), 3);
    assert_eq!(acct.signers[0].index, 0);
    assert_eq!(acct.signers[1].public_spend_key, "cc".repeat(32));
    assert_eq!(acct.signers[2].public_view_key, "ff".repeat(32));
}

#[test]
fn test_kex_rounds_formula() {
    for n in 2..=8usize {
        for m in 2..=n {
            let expected = n - m + 1;
            assert_eq!(
                kex_rounds_required(m, n),
                expected,
                "kex_rounds_required({}, {}) should be {}",
                m,
                n,
                expected
            );
        }
    }
}

// ===========================================================================
// KEX Negative Tests
// ===========================================================================

#[test]
fn test_kex_threshold_too_low() {
    let result = MultisigAccount::new(1, 2);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("threshold"));
}

#[test]
fn test_kex_threshold_exceeds_signers() {
    let result = MultisigAccount::new(5, 3);
    assert!(result.is_err());
}

#[test]
fn test_kex_exceeds_max_signers() {
    let result = MultisigAccount::new(2, MULTISIG_MAX_SIGNERS + 1);
    assert!(result.is_err());
}

#[test]
fn test_kex_empty_spend_key() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    let result = acct.initialize_kex("", &"22".repeat(32));
    assert!(result.is_err());
}

#[test]
fn test_kex_empty_view_key() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    let result = acct.initialize_kex(&"11".repeat(32), "");
    assert!(result.is_err());
}

#[test]
fn test_kex_invalid_hex_spend_key() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    let result = acct.initialize_kex("not_valid_hex!", &"22".repeat(32));
    assert!(result.is_err());
}

#[test]
fn test_kex_process_before_init() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    let msgs = vec![KexMessage::new(), KexMessage::new()];
    let result = acct.process_kex_round(&msgs);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("initialize_kex"));
}

#[test]
fn test_kex_round1_wrong_message_count() {
    let mut acct = MultisigAccount::new(2, 3).unwrap();
    acct.initialize_kex(&"11".repeat(32), &"22".repeat(32))
        .unwrap();

    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["aa".repeat(32), "bb".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    acct.register_signers(&msgs).unwrap();
    let result = acct.process_kex_round(&msgs);
    assert!(result.is_err());
}

#[test]
fn test_kex_round1_wrong_round_number() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    acct.initialize_kex(&"11".repeat(32), &"22".repeat(32))
        .unwrap();

    let msgs = vec![
        KexMessage {
            round: 2,
            signer_index: 0,
            keys: vec!["aa".repeat(32), "bb".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexRound,
        },
        KexMessage {
            round: 2,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexRound,
        },
    ];
    acct.register_signers(&msgs).unwrap();
    let result = acct.process_kex_round(&msgs);
    assert!(result.is_err());
}

#[test]
fn test_kex_round1_too_few_keys() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    acct.initialize_kex(&"11".repeat(32), &"22".repeat(32))
        .unwrap();

    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["aa".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    // register_signers will fail due to missing view key on signer 0
    let result = acct.register_signers(&msgs);
    assert!(result.is_err());
}

#[test]
fn test_kex_round1_invalid_hex_key() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    acct.initialize_kex(&"11".repeat(32), &"22".repeat(32))
        .unwrap();

    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["not_hex!".to_string(), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    // register_signers will accept these (it doesn't validate hex format, just non-empty)
    acct.register_signers(&msgs).unwrap();
    let result = acct.process_kex_round(&msgs);
    assert!(result.is_err());
}

#[test]
fn test_kex_verification_corrupted_hash() {
    let spend0 = "11".repeat(32);
    let view0 = "22".repeat(32);
    let spend1 = "33".repeat(32);
    let view1 = "44".repeat(32);

    let mut accounts = [
        MultisigAccount::new(2, 2).unwrap(),
        MultisigAccount::new(2, 2).unwrap(),
    ];
    accounts[0].set_signer_index(0);
    accounts[1].set_signer_index(1);

    let msg0 = accounts[0].initialize_kex(&spend0, &view0).unwrap();
    let msg1 = accounts[1].initialize_kex(&spend1, &view1).unwrap();

    let msgs = vec![msg0, msg1];
    for a in accounts.iter_mut() {
        a.register_signers(&msgs).unwrap();
    }

    let mut verify_msgs = Vec::new();
    for a in accounts.iter_mut() {
        let out = a.process_kex_round(&msgs).unwrap();
        verify_msgs.push(out.unwrap());
    }

    // Corrupt one verification hash
    verify_msgs[1].keys[0] = "00".repeat(32);

    let result = accounts[0].process_kex_round(&verify_msgs);
    assert!(result.is_err());
}

#[test]
fn test_kex_duplicate_signer_indices() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    acct.initialize_kex(&"11".repeat(32), &"22".repeat(32))
        .unwrap();

    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["aa".repeat(32), "bb".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    acct.register_signers(&msgs).unwrap();
    // Should not panic; may or may not return an error
    let _ = acct.process_kex_round(&msgs);
}

#[test]
fn test_register_signers_rejects_empty_keys() {
    let mut acct = MultisigAccount::new(2, 2).unwrap();
    let msgs = vec![
        KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec!["aa".repeat(32), "".to_string()],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
        KexMessage {
            round: 1,
            signer_index: 1,
            keys: vec!["cc".repeat(32), "dd".repeat(32)],
            msg_type: salvium_multisig::constants::MultisigMsgType::KexInit,
        },
    ];
    let result = acct.register_signers(&msgs);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("empty"));
}

// ===========================================================================
// Signing Positive Tests
// ===========================================================================

#[test]
fn test_nonces_structure() {
    let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
    let nonces = generate_nonces(0, &key_image).unwrap();
    assert_eq!(nonces.secret_nonces.len(), 2);
    assert_eq!(nonces.pub_nonces_g.len(), 2);
    assert_eq!(nonces.pub_nonces_hp.len(), 2);
}

#[test]
fn test_nonces_are_unique() {
    let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
    let n1 = generate_nonces(0, &key_image).unwrap();
    let n2 = generate_nonces(0, &key_image).unwrap();
    assert_ne!(n1.secret_nonces[0], n2.secret_nonces[0]);
    assert_ne!(n1.pub_nonces_g[0], n2.pub_nonces_g[0]);
}

#[test]
fn test_nonces_ext_tclsag() {
    let key_image = hex::encode(salvium_crypto::scalar_mult_base(&[1u8; 32]));
    let key_image_y = hex::encode(salvium_crypto::scalar_mult_base(&[2u8; 32]));
    let nonces = generate_nonces_ext(0, &key_image, Some(&key_image_y)).unwrap();
    assert_eq!(nonces.secret_nonces_y.len(), 2);
    assert_eq!(nonces.pub_nonces_g_y.len(), 2);
    assert_eq!(nonces.pub_nonces_hp_y.len(), 2);
}

#[test]
fn test_partial_sign_valid_scalars() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let (privkey_hex, _) = generate_random_scalar();

    let partial = partial_sign(&ctx, &nonces0, &privkey_hex, &[nonces0.clone(), nonces1]).unwrap();
    assert_eq!(partial.s_partial.len(), 64);
    assert_eq!(partial.c_0.len(), 64);
    hex::decode(&partial.s_partial).unwrap();
    hex::decode(&partial.c_0).unwrap();
}

#[test]
fn test_partial_sign_deterministic() {
    let ctx = make_signing_context(2);
    let key_image = &ctx.key_image;

    let nonces0 = generate_nonces(0, key_image).unwrap();
    let nonces1 = generate_nonces(1, key_image).unwrap();
    let privkey = "11".repeat(32);
    let all = vec![nonces0.clone(), nonces1];

    let p1 = partial_sign(&ctx, &nonces0, &privkey, &all).unwrap();
    let p2 = partial_sign(&ctx, &nonces0, &privkey, &all).unwrap();
    assert_eq!(p1.s_partial, p2.s_partial);
    assert_eq!(p1.c_0, p2.c_0);
}

#[test]
fn test_two_signers_different_partials() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let (key0, _) = generate_random_scalar();
    let (key1, _) = generate_random_scalar();

    let p0 = partial_sign(&ctx, &nonces0, &key0, &all).unwrap();
    let p1 = partial_sign(&ctx, &nonces1, &key1, &all).unwrap();
    assert_ne!(p0.s_partial, p1.s_partial);
}

#[test]
fn test_combine_two_partials() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let (key0, _) = generate_random_scalar();
    let (key1, _) = generate_random_scalar();

    let p0 = partial_sign(&ctx, &nonces0, &key0, &all).unwrap();
    let p1 = partial_sign(&ctx, &nonces1, &key1, &all).unwrap();

    let (s, c) = combine_partial_signatures(&[p0, p1]).unwrap();
    assert_eq!(s.len(), 64);
    assert_eq!(c.len(), 64);
    let s_bytes = hex::decode(&s).unwrap();
    assert_ne!(s_bytes, vec![0u8; 32]);
}

#[test]
fn test_combine_three_partials() {
    let ctx = make_signing_context(2);
    let nonces: Vec<SignerNonces> = (0..3)
        .map(|i| generate_nonces(i, &ctx.key_image).unwrap())
        .collect();

    let keys: Vec<String> = (0..3).map(|_| generate_random_scalar().0).collect();

    let partials: Vec<_> = (0..3)
        .map(|i| partial_sign(&ctx, &nonces[i], &keys[i], &nonces).unwrap())
        .collect();

    let (s, _c) = combine_partial_signatures(&partials).unwrap();
    let s_bytes = hex::decode(&s).unwrap();
    assert_ne!(s_bytes, vec![0u8; 32]);
}

#[test]
fn test_combine_ext_returns_struct() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let (key0, _) = generate_random_scalar();
    let (key1, _) = generate_random_scalar();

    let p0 = partial_sign(&ctx, &nonces0, &key0, &all).unwrap();
    let p1 = partial_sign(&ctx, &nonces1, &key1, &all).unwrap();

    let combined = combine_partial_signatures_ext(&[p0, p1]).unwrap();
    assert_eq!(combined.s.len(), 64);
    assert_eq!(combined.c_0.len(), 64);
    assert!(combined.sy.is_none()); // no TCLSAG
}

#[test]
fn test_tclsag_partial_produces_sy() {
    let ctx = make_tclsag_context(2);
    let ki_y = ctx.key_image_y.as_ref().unwrap();
    let nonces0 = generate_nonces_ext(0, &ctx.key_image, Some(ki_y)).unwrap();
    let nonces1 = generate_nonces_ext(1, &ctx.key_image, Some(ki_y)).unwrap();
    let (key, _) = generate_random_scalar();
    let (key_y, _) = generate_random_scalar();

    let partial =
        partial_sign_tclsag(&ctx, &nonces0, &key, &key_y, &[nonces0.clone(), nonces1]).unwrap();
    assert!(partial.sy_partial.is_some());
    assert_eq!(partial.sy_partial.as_ref().unwrap().len(), 64);
}

#[test]
fn test_tclsag_combine_includes_sy() {
    let ctx = make_tclsag_context(2);
    let ki_y = ctx.key_image_y.as_ref().unwrap();

    let nonces0 = generate_nonces_ext(0, &ctx.key_image, Some(ki_y)).unwrap();
    let nonces1 = generate_nonces_ext(1, &ctx.key_image, Some(ki_y)).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let (k0, _) = generate_random_scalar();
    let (k0y, _) = generate_random_scalar();
    let (k1, _) = generate_random_scalar();
    let (k1y, _) = generate_random_scalar();

    let p0 = partial_sign_tclsag(&ctx, &nonces0, &k0, &k0y, &all).unwrap();
    let p1 = partial_sign_tclsag(&ctx, &nonces1, &k1, &k1y, &all).unwrap();

    let combined = combine_partial_signatures_ext(&[p0, p1]).unwrap();
    assert!(combined.sy.is_some());
    let sy_bytes = hex::decode(combined.sy.unwrap()).unwrap();
    assert_ne!(sy_bytes, vec![0u8; 32]);
}

#[test]
fn test_nonce_binding_deterministic() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let b1 = compute_nonce_binding(&ctx, &all).unwrap();
    let b2 = compute_nonce_binding(&ctx, &all).unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn test_nonce_binding_varies_with_message() {
    let ctx1 = make_signing_context(2);
    let mut ctx2 = make_signing_context(2);
    ctx2.message = "bb".repeat(32); // different message

    let nonces0 = generate_nonces(0, &ctx1.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx1.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let b1 = compute_nonce_binding(&ctx1, &all).unwrap();
    let b2 = compute_nonce_binding(&ctx2, &all).unwrap();
    assert_ne!(b1, b2);
}

#[test]
fn test_signing_algebraic_correctness() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let (privkey_hex, privkey_bytes) = generate_random_scalar();
    let all = vec![nonces0.clone(), nonces1];

    let partial = partial_sign(&ctx, &nonces0, &privkey_hex, &all).unwrap();

    // Recompute: combined_alpha = alpha[0] + b * alpha[1]
    let b = compute_nonce_binding(&ctx, &all).unwrap();
    let b_reduced = salvium_crypto::sc_reduce32(&b);

    let one = {
        let mut v = [0u8; 32];
        v[0] = 1;
        v
    };
    let zero = [0u8; 32];
    let mut b_arr = [0u8; 32];
    b_arr.copy_from_slice(&b_reduced[..32]);

    let neg_b_vec = salvium_crypto::sc_mul_sub(&one, &b_arr, &zero);
    let mut neg_b = [0u8; 32];
    neg_b.copy_from_slice(&neg_b_vec[..32]);

    let alpha0 = nonces0.secret_nonces[0];
    let alpha1 = nonces0.secret_nonces[1];

    let combined_vec = salvium_crypto::sc_mul_sub(&neg_b, &alpha1, &alpha0);
    let mut combined_alpha = [0u8; 32];
    combined_alpha.copy_from_slice(&combined_vec[..32]);

    // Recompute challenge
    let combined_g = salvium_crypto::scalar_mult_base(&combined_alpha);
    let mut c_data = Vec::new();
    c_data.extend_from_slice(b"CLSAG_c");
    c_data.extend_from_slice(&hex::decode(&ctx.ring[ctx.real_index]).unwrap());
    c_data.extend_from_slice(&hex::decode(&ctx.key_image).unwrap());
    c_data.extend_from_slice(&hex::decode(&ctx.pseudo_output_commitment).unwrap());
    c_data.extend_from_slice(&hex::decode(&ctx.message).unwrap());
    c_data.extend_from_slice(&combined_g);
    let c_hash = salvium_crypto::keccak256(&c_data);
    let c_reduced = salvium_crypto::sc_reduce32(&c_hash);
    let mut c32 = [0u8; 32];
    c32.copy_from_slice(&c_reduced[..32]);

    // s_expected = combined_alpha - c * privkey
    let s_expected_vec = salvium_crypto::sc_mul_sub(&c32, &privkey_bytes, &combined_alpha);

    assert_eq!(partial.s_partial, hex::encode(&s_expected_vec));
    assert_eq!(partial.c_0, hex::encode(c32));
}

// ===========================================================================
// Signing Negative Tests
// ===========================================================================

#[test]
fn test_combine_empty_partials() {
    let (s, c) = combine_partial_signatures(&[]).unwrap();
    assert_eq!(s, hex::encode([0u8; 32]));
    assert_eq!(c, hex::encode([0u8; 32]));
}

#[test]
fn test_partial_sign_invalid_privkey_hex() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    // Non-hex key — should now return an error
    let result = partial_sign(&ctx, &nonces0, "not_hex!", &[nonces0.clone(), nonces1]);
    assert!(result.is_err());
}

#[test]
fn test_nonce_reuse_identical_signatures() {
    let ctx = make_signing_context(2);
    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let (key, _) = generate_random_scalar();
    let all = vec![nonces0.clone(), nonces1];

    let p1 = partial_sign(&ctx, &nonces0, &key, &all).unwrap();
    let p2 = partial_sign(&ctx, &nonces0, &key, &all).unwrap();
    assert_eq!(p1.s_partial, p2.s_partial);
}

#[test]
fn test_different_real_index_different_challenge() {
    let mut ctx1 = make_signing_context(4);
    ctx1.real_index = 0;
    let mut ctx2 = make_signing_context(4);
    ctx2.real_index = 2;

    let nonces0 = generate_nonces(0, &ctx1.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx1.key_image).unwrap();
    let (key, _) = generate_random_scalar();
    let all = vec![nonces0.clone(), nonces1];

    let p1 = partial_sign(&ctx1, &nonces0, &key, &all).unwrap();
    let p2 = partial_sign(&ctx2, &nonces0, &key, &all).unwrap();
    assert_ne!(p1.c_0, p2.c_0);
}

// ===========================================================================
// MultisigTxSet Tests
// ===========================================================================

#[test]
fn test_tx_set_with_config() {
    let set = MultisigTxSet::with_config(3, 5);
    assert_eq!(set.threshold, 3);
    assert_eq!(set.signer_count, 5);
    assert!(set.pending_txs.is_empty());
    assert!(!set.is_complete());
}

#[test]
fn test_tx_set_add_pending_tx() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.add_pending_tx(PendingMultisigTx {
        tx_blob: "deadbeef".to_string(),
        key_images: vec!["aa".repeat(32)],
        tx_prefix_hash: "bb".repeat(32),
        input_nonces: Vec::new(),
        input_partials: Vec::new(),
        fee: 10_000_000,
        destinations: vec!["SC1test".to_string()],
    });
    assert_eq!(set.pending_txs.len(), 1);
    assert_eq!(set.pending_txs[0].fee, 10_000_000);
}

#[test]
fn test_tx_set_mark_signer_contributed() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.mark_signer_contributed("signer_pubkey_0");
    assert_eq!(set.signers_contributed.len(), 1);
    assert!(set.signers_contributed.contains("signer_pubkey_0"));
}

#[test]
fn test_tx_set_complete_at_threshold() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.mark_signer_contributed("pk0");
    assert!(!set.is_complete());
    set.mark_signer_contributed("pk1");
    assert!(set.is_complete());
}

#[test]
fn test_tx_set_complete_above_threshold() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.mark_signer_contributed("pk0");
    set.mark_signer_contributed("pk1");
    set.mark_signer_contributed("pk2");
    assert!(set.is_complete());
    assert_eq!(set.signers_contributed.len(), 3);
}

#[test]
fn test_tx_set_duplicate_signer_not_counted() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.mark_signer_contributed("pk0");
    set.mark_signer_contributed("pk0");
    assert_eq!(set.signers_contributed.len(), 1);
    assert!(!set.is_complete());
}

#[test]
fn test_tx_set_zero_threshold_not_complete() {
    let set = MultisigTxSet::new();
    assert!(!set.is_complete());
}

#[test]
fn test_tx_set_serde_roundtrip() {
    let mut set = MultisigTxSet::with_config(2, 3);
    set.add_transaction("tx_hex_1".to_string());
    set.add_key_image("aa".repeat(32));
    set.mark_signer_contributed("pk0");
    set.add_pending_tx(PendingMultisigTx {
        tx_blob: "blob".to_string(),
        key_images: vec!["bb".repeat(32)],
        tx_prefix_hash: "cc".repeat(32),
        input_nonces: Vec::new(),
        input_partials: Vec::new(),
        fee: 5_000_000,
        destinations: vec!["dest".to_string()],
    });

    let data = set.serialize();
    let restored = MultisigTxSet::deserialize(&data).unwrap();

    assert_eq!(restored.threshold, 2);
    assert_eq!(restored.signer_count, 3);
    assert_eq!(restored.transactions.len(), 1);
    assert_eq!(restored.key_images.len(), 1);
    assert_eq!(restored.signers_contributed.len(), 1);
    assert_eq!(restored.pending_txs.len(), 1);
    assert_eq!(restored.pending_txs[0].fee, 5_000_000);
}

#[test]
fn test_tx_set_multiple_pending_txs() {
    let mut set = MultisigTxSet::with_config(2, 3);
    for i in 0..5 {
        set.add_pending_tx(PendingMultisigTx {
            tx_blob: format!("blob_{}", i),
            key_images: vec![],
            tx_prefix_hash: format!("{:02x}", i).repeat(32),
            input_nonces: Vec::new(),
            input_partials: Vec::new(),
            fee: (i + 1) as u64 * 1_000_000,
            destinations: vec![],
        });
    }
    assert_eq!(set.pending_txs.len(), 5);
    assert_eq!(set.pending_txs[4].fee, 5_000_000);
}

// ===========================================================================
// End-to-End Workflow Tests
// ===========================================================================

#[test]
fn test_e2e_2_of_3_kex_then_sign() {
    let accounts = run_full_kex(2, 3);

    let ctx = make_signing_context(2);

    let nonces0 = generate_nonces(0, &ctx.key_image).unwrap();
    let nonces1 = generate_nonces(1, &ctx.key_image).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let key0 = accounts[0].spend_key().unwrap().to_string();
    let key1 = accounts[1].spend_key().unwrap().to_string();

    let p0 = partial_sign(&ctx, &nonces0, &key0, &all).unwrap();
    let p1 = partial_sign(&ctx, &nonces1, &key1, &all).unwrap();

    let (s, c) = combine_partial_signatures(&[p0, p1]).unwrap();
    assert_ne!(s, hex::encode([0u8; 32]));
    assert_ne!(c, hex::encode([0u8; 32]));

    let mut tx_set2 = MultisigTxSet::with_config(2, 3);
    tx_set2.mark_signer_contributed("signer_0");
    tx_set2.mark_signer_contributed("signer_1");
    assert!(tx_set2.is_complete());
}

#[test]
fn test_e2e_3_of_5_kex_then_sign() {
    let accounts = run_full_kex(3, 5);

    let ctx = make_signing_context(2);
    let nonces: Vec<SignerNonces> = (0..3)
        .map(|i| generate_nonces(i, &ctx.key_image).unwrap())
        .collect();

    let keys: Vec<String> = (0..3)
        .map(|i| accounts[i].spend_key().unwrap().to_string())
        .collect();

    let partials: Vec<_> = (0..3)
        .map(|i| partial_sign(&ctx, &nonces[i], &keys[i], &nonces).unwrap())
        .collect();

    let (s, c) = combine_partial_signatures(&partials).unwrap();
    assert_ne!(hex::decode(&s).unwrap(), vec![0u8; 32]);
    assert_ne!(hex::decode(&c).unwrap(), vec![0u8; 32]);
}

#[test]
fn test_e2e_tclsag_2_of_3() {
    let accounts = run_full_kex(2, 3);
    let ctx = make_tclsag_context(2);
    let ki_y = ctx.key_image_y.as_ref().unwrap();

    let nonces0 = generate_nonces_ext(0, &ctx.key_image, Some(ki_y)).unwrap();
    let nonces1 = generate_nonces_ext(1, &ctx.key_image, Some(ki_y)).unwrap();
    let all = vec![nonces0.clone(), nonces1.clone()];

    let key0 = accounts[0].spend_key().unwrap().to_string();
    let key1 = accounts[1].spend_key().unwrap().to_string();
    let (key0y, _) = generate_random_scalar();
    let (key1y, _) = generate_random_scalar();

    let p0 = partial_sign_tclsag(&ctx, &nonces0, &key0, &key0y, &all).unwrap();
    let p1 = partial_sign_tclsag(&ctx, &nonces1, &key1, &key1y, &all).unwrap();

    let combined = combine_partial_signatures_ext(&[p0, p1]).unwrap();
    assert!(combined.sy.is_some());
    assert_ne!(hex::decode(&combined.s).unwrap(), vec![0u8; 32]);
    assert_ne!(hex::decode(combined.sy.unwrap()).unwrap(), vec![0u8; 32]);
}

#[test]
fn test_e2e_wallet_api() {
    let (spend, view) = (generate_random_scalar().0, generate_random_scalar().0);
    let wallet = create_multisig_wallet(2, 3, &spend, &view).unwrap();
    assert!(wallet.is_multisig());
    assert!(!wallet.is_ready());
    assert_eq!(wallet.get_threshold(), 2);
    assert_eq!(wallet.get_signer_count(), 3);
}

#[test]
fn test_e2e_wallet_helpers() {
    let key = "ab".repeat(32);
    let blinded = get_multisig_blinded_secret_key(&key);
    assert_eq!(blinded.len(), 64);
    hex::decode(&blinded).unwrap();

    let (priv_hex, priv_bytes) = generate_random_scalar();
    let pub_point = hex::encode(salvium_crypto::scalar_mult_base(&priv_bytes));
    let dh = compute_dh_secret(&priv_hex, &pub_point);
    assert_eq!(dh.len(), 64);

    let nonces = generate_multisig_nonces(3);
    assert_eq!(nonces.len(), 3);
    for pair in &nonces {
        assert_eq!(pair.len(), 2);
    }

    let pub_nonce = nonce_to_public(&nonces[0][0]);
    assert_eq!(pub_nonce.len(), 64);
    hex::decode(&pub_nonce).unwrap();
}

#[test]
fn test_e2e_carrot_keys_after_kex() {
    let accounts = run_full_kex(2, 3);

    let spend = accounts[0].spend_key().unwrap().to_string();
    let view = accounts[0].view_key().unwrap().to_string();

    let mut carrot = MultisigCarrotAccount::new(2, 3).unwrap();
    carrot.account.kex_complete = true;
    carrot.account.multisig_pubkey = accounts[0].multisig_pubkey.clone();

    let keys = carrot.derive_carrot_keys(&spend, &view).unwrap();
    assert_eq!(keys.prove_spend_key.len(), 64);
    assert_eq!(keys.view_incoming_key.len(), 64);
    assert_eq!(keys.generate_image_key.len(), 64);
    assert_eq!(keys.generate_address_secret.len(), 64);
    assert_eq!(keys.account_spend_pubkey.len(), 64);

    let addr = carrot.get_carrot_address("testnet").unwrap();
    assert!(addr.starts_with("SC1T"));

    let sub = carrot.get_carrot_subaddress("testnet", 0, 1).unwrap();
    assert!(sub.starts_with("SC1T"));
    assert_ne!(addr, sub);
}

// ===========================================================================
// Weighted Key Share Tests
// ===========================================================================

#[test]
fn test_weighted_key_share_algebraic() {
    // Verify: sum(coeff_i * k_i) * G == aggregate multisig pubkey
    let accounts = run_full_kex(2, 3);
    let expected_pubkey_hex = accounts[0].multisig_pubkey.as_ref().unwrap();

    // Compute weighted shares and sum their public points
    let mut sum_point: Option<[u8; 32]> = None;
    for acct in &accounts {
        let weighted = acct.get_weighted_spend_key_share().unwrap();
        let point = salvium_crypto::scalar_mult_base(&weighted);
        let mut p32 = [0u8; 32];
        p32.copy_from_slice(&point);
        sum_point = Some(match sum_point {
            None => p32,
            Some(acc) => {
                let s = salvium_crypto::point_add_compressed(&acc, &p32);
                let mut r = [0u8; 32];
                r.copy_from_slice(&s[..32]);
                r
            }
        });
    }

    assert_eq!(hex::encode(sum_point.unwrap()), *expected_pubkey_hex);
}

#[test]
fn test_aggregation_coefficient_deterministic() {
    let accounts = run_full_kex(2, 3);
    let c1 = accounts[0].get_aggregation_coefficient().unwrap();
    let c2 = accounts[0].get_aggregation_coefficient().unwrap();
    assert_eq!(c1, c2);
    // Different signers should have different coefficients
    let c3 = accounts[1].get_aggregation_coefficient().unwrap();
    assert_ne!(c1, c3);
}

// ===========================================================================
// Key Image Tests
// ===========================================================================

#[test]
fn test_partial_key_image_deterministic() {
    let weighted_share = {
        let mut s = [0u8; 32];
        s[0] = 42;
        let reduced = salvium_crypto::sc_reduce32(&s);
        let mut r = [0u8; 32];
        r.copy_from_slice(&reduced[..32]);
        r
    };
    let output_pubkey = {
        let mut s = [0u8; 32];
        s[0] = 7;
        let p = salvium_crypto::scalar_mult_base(&salvium_crypto::sc_reduce32(&s));
        let mut r = [0u8; 32];
        r.copy_from_slice(&p);
        r
    };

    let ki1 =
        salvium_multisig::key_image::compute_partial_key_image(&weighted_share, &output_pubkey);
    let ki2 =
        salvium_multisig::key_image::compute_partial_key_image(&weighted_share, &output_pubkey);
    assert_eq!(ki1, ki2);
    assert_ne!(ki1, [0u8; 32]);
}

#[test]
fn test_combine_key_images_matches_single_signer() {
    // For a single "signer" with the full key, the partial KI should equal the full KI
    let secret_key = {
        let mut s = [0u8; 32];
        s[0] = 55;
        let reduced = salvium_crypto::sc_reduce32(&s);
        let mut r = [0u8; 32];
        r.copy_from_slice(&reduced[..32]);
        r
    };
    let output_pubkey = {
        let p = salvium_crypto::scalar_mult_base(&secret_key);
        let mut r = [0u8; 32];
        r.copy_from_slice(&p);
        r
    };

    // Full key image: secret_key * H_p(output_pubkey)
    let full_ki = salvium_crypto::generate_key_image(&output_pubkey, &secret_key);
    let mut full_ki32 = [0u8; 32];
    full_ki32.copy_from_slice(&full_ki);

    // Partial with the full key (as if 1-of-1, coefficient = 1)
    let partial =
        salvium_multisig::key_image::compute_partial_key_image(&secret_key, &output_pubkey);

    assert_eq!(partial, full_ki32);
}

#[test]
fn test_combine_two_partial_key_images() {
    let share0 = {
        let mut s = [0u8; 32];
        s[0] = 10;
        let r = salvium_crypto::sc_reduce32(&s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&r[..32]);
        a
    };
    let share1 = {
        let mut s = [0u8; 32];
        s[0] = 20;
        let r = salvium_crypto::sc_reduce32(&s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&r[..32]);
        a
    };
    let output_pubkey = {
        // combined_key = share0 + share1
        let combined = salvium_crypto::sc_add(&share0, &share1);
        let mut c = [0u8; 32];
        c.copy_from_slice(&combined[..32]);
        let p = salvium_crypto::scalar_mult_base(&c);
        let mut r = [0u8; 32];
        r.copy_from_slice(&p);
        r
    };

    let pki0 = salvium_multisig::key_image::compute_partial_key_image(&share0, &output_pubkey);
    let pki1 = salvium_multisig::key_image::compute_partial_key_image(&share1, &output_pubkey);

    let combined = salvium_multisig::key_image::combine_partial_key_images(&[pki0, pki1]).unwrap();

    // The combined key image should match: (share0+share1) * H_p(output_pubkey)
    let full_secret = {
        let s = salvium_crypto::sc_add(&share0, &share1);
        let mut a = [0u8; 32];
        a.copy_from_slice(&s[..32]);
        a
    };
    let expected = salvium_crypto::generate_key_image(&output_pubkey, &full_secret);
    let mut expected32 = [0u8; 32];
    expected32.copy_from_slice(&expected);

    assert_eq!(combined, expected32);
}
