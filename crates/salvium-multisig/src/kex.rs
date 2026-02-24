use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::MultisigMsgType;

/// Returns the number of main KEX rounds required for a given M-of-N multisig.
///
/// Matches the C++ protocol: `N - M + 1` main rounds, plus 1 verification round.
/// The total rounds (including verification) is `kex_rounds_required() + 1`.
pub fn kex_rounds_required(threshold: usize, signers: usize) -> usize {
    // N - M + 1 main rounds (N = signers, M = threshold)
    signers - threshold + 1
}

/// Computes the cofactored DH shared secret: `8 * k * K_other`.
///
/// The cofactor multiplication prevents small-subgroup attacks.
fn cofactored_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    // First compute k * K_other
    let shared = salvium_crypto::scalar_mult_point(private_key, public_key);
    // Multiply by cofactor 8: add the point to itself 3 times (8 = 2^3)
    let double1 = salvium_crypto::point_add_compressed(&shared, &shared);
    let mut d1 = [0u8; 32];
    d1.copy_from_slice(&double1[..32]);
    let double2 = salvium_crypto::point_add_compressed(&d1, &d1);
    let mut d2 = [0u8; 32];
    d2.copy_from_slice(&double2[..32]);
    let double3 = salvium_crypto::point_add_compressed(&d2, &d2);
    let mut result = [0u8; 32];
    result.copy_from_slice(&double3[..32]);
    result
}

/// Compute an aggregation coefficient for a signer's public key.
///
/// `coeff = H(pk_i || all_sorted_pubkeys || "multisig")`, then reduced to a scalar.
/// This prevents rogue-key attacks (key cancellation).
pub fn aggregation_coefficient(
    signer_pubkey: &[u8; 32],
    all_pubkeys_sorted: &[[u8; 32]],
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(signer_pubkey);
    for pk in all_pubkeys_sorted {
        data.extend_from_slice(pk);
    }
    data.extend_from_slice(b"multisig");
    let hash = salvium_crypto::keccak256(&data);
    let reduced = salvium_crypto::sc_reduce32(&hash);
    let mut result = [0u8; 32];
    result.copy_from_slice(&reduced[..32]);
    result
}

/// Processes KEX rounds, tracking DH shared secrets and deriving the aggregate key.
#[derive(Debug, Clone)]
pub struct KexRoundProcessor {
    /// Our signer index in the group.
    pub signer_index: usize,
    /// Number of signers (N).
    pub signer_count: usize,
    /// Threshold (M).
    pub threshold: usize,
    /// Our base private key (reduced scalar).
    private_key: [u8; 32],
    /// All base public keys collected in round 1, indexed by signer.
    pub base_pubkeys: Vec<[u8; 32]>,
    /// All base common (view) private keys from round 1.
    pub base_common_privkeys: Vec<[u8; 32]>,
    /// DH shared secrets computed during KEX, mapped to originating signer indices.
    pub kex_keys_to_origins: HashMap<[u8; 32], Vec<usize>>,
    /// Keys produced in each round for forwarding.
    round_keys: Vec<Vec<[u8; 32]>>,
}

impl KexRoundProcessor {
    /// Create a new processor for this signer.
    pub fn new(
        signer_index: usize,
        signer_count: usize,
        threshold: usize,
        private_key: [u8; 32],
    ) -> Self {
        Self {
            signer_index,
            signer_count,
            threshold,
            private_key,
            base_pubkeys: Vec::with_capacity(signer_count),
            base_common_privkeys: Vec::with_capacity(signer_count),
            kex_keys_to_origins: HashMap::new(),
            round_keys: Vec::new(),
        }
    }

    /// Process round 1: collect base pubkeys and common privkeys from all signers.
    ///
    /// Each message should have `keys = [hex(pub_spend), hex(pub_view)]`.
    /// Returns the next round's outgoing `KexMessage`, or `None` if this was the last
    /// main round (only possible for N-of-N where N-M+1 = 1).
    pub fn process_round1(
        &mut self,
        messages: &[KexMessage],
    ) -> Result<Option<KexMessage>, String> {
        if messages.len() != self.signer_count {
            return Err(format!(
                "expected {} round-1 messages, got {}",
                self.signer_count,
                messages.len()
            ));
        }

        // Collect base pubkeys and view keys from each signer.
        self.base_pubkeys.clear();
        self.base_common_privkeys.clear();
        for msg in messages {
            if msg.round != 1 {
                return Err(format!("expected round 1, got round {}", msg.round));
            }
            if msg.keys.len() < 2 {
                return Err(format!(
                    "round 1 message from signer {} has {} keys, need 2",
                    msg.signer_index,
                    msg.keys.len()
                ));
            }
            let pub_spend = hex_to_32(&msg.keys[0])?;
            let pub_view = hex_to_32(&msg.keys[1])?;
            self.base_pubkeys.push(pub_spend);
            self.base_common_privkeys.push(pub_view);
        }

        let main_rounds = kex_rounds_required(self.threshold, self.signer_count);

        if main_rounds == 1 {
            // N-of-N: only 1 main round, go straight to finalization.
            return Ok(None);
        }

        // For round 2: compute DH shared secrets with each other signer.
        let mut out_keys = Vec::new();
        for (i, pk) in self.base_pubkeys.iter().enumerate() {
            if i == self.signer_index {
                continue;
            }
            let dh = cofactored_dh(&self.private_key, pk);
            self.kex_keys_to_origins
                .entry(dh)
                .or_default()
                .push(i);
            out_keys.push(dh);
        }
        self.round_keys.push(out_keys.clone());

        Ok(Some(KexMessage {
            round: 2,
            signer_index: self.signer_index,
            keys: out_keys.iter().map(hex::encode).collect(),
            msg_type: MultisigMsgType::KexRound,
        }))
    }

    /// Process a subsequent KEX round (round >= 2).
    ///
    /// Collects DH-derived keys from all signers, then derives next-round keys
    /// by further DH with each unique key we haven't seen from ourselves.
    /// Returns `None` when main rounds are complete (ready for verification).
    pub fn process_round_n(
        &mut self,
        round: usize,
        messages: &[KexMessage],
    ) -> Result<Option<KexMessage>, String> {
        if messages.len() != self.signer_count {
            return Err(format!(
                "expected {} messages for round {}, got {}",
                self.signer_count, round, messages.len()
            ));
        }

        // Collect all incoming DH keys and record origins.
        let mut all_incoming = Vec::new();
        for msg in messages {
            if msg.round != round {
                return Err(format!("expected round {}, got round {}", round, msg.round));
            }
            for key_hex in &msg.keys {
                let key = hex_to_32(key_hex)?;
                self.kex_keys_to_origins
                    .entry(key)
                    .or_default()
                    .push(msg.signer_index);
                all_incoming.push(key);
            }
        }

        let main_rounds = kex_rounds_required(self.threshold, self.signer_count);

        if round >= main_rounds {
            // All main rounds done. Ready for verification.
            self.round_keys.push(all_incoming);
            return Ok(None);
        }

        // Compute next round: DH with each unique incoming key.
        let mut out_keys = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for key in &all_incoming {
            if seen.insert(*key) {
                let dh = cofactored_dh(&self.private_key, key);
                out_keys.push(dh);
            }
        }
        self.round_keys.push(out_keys.clone());

        Ok(Some(KexMessage {
            round: round + 1,
            signer_index: self.signer_index,
            keys: out_keys.iter().map(hex::encode).collect(),
            msg_type: MultisigMsgType::KexRound,
        }))
    }

    /// Finalize KEX: compute the aggregate multisig public key and common (view) key.
    ///
    /// Returns `(multisig_pubkey, common_view_key)`.
    pub fn finalize(&self) -> Result<([u8; 32], [u8; 32]), String> {
        if self.base_pubkeys.len() != self.signer_count {
            return Err("KEX not complete: missing base pubkeys".to_string());
        }

        // Sort pubkeys for deterministic aggregation.
        let mut sorted = self.base_pubkeys.clone();
        sorted.sort();

        // Compute aggregate multisig public key: sum(coeff_i * K_i)
        let mut aggregate = None::<[u8; 32]>;
        for pk in &self.base_pubkeys {
            let coeff = aggregation_coefficient(pk, &sorted);
            let weighted = salvium_crypto::scalar_mult_point(&coeff, pk);
            let mut w32 = [0u8; 32];
            w32.copy_from_slice(&weighted);

            aggregate = Some(match aggregate {
                None => w32,
                Some(acc) => {
                    let sum = salvium_crypto::point_add_compressed(&acc, &w32);
                    let mut s32 = [0u8; 32];
                    s32.copy_from_slice(&sum[..32]);
                    s32
                }
            });
        }

        let multisig_pubkey =
            aggregate.ok_or_else(|| "no pubkeys to aggregate".to_string())?;

        // Common view key: H(sorted base common privkeys concat)
        let mut common_data = Vec::new();
        let mut sorted_views = self.base_common_privkeys.clone();
        sorted_views.sort();
        for v in &sorted_views {
            common_data.extend_from_slice(v);
        }
        let common_hash = salvium_crypto::keccak256(&common_data);
        let common_reduced = salvium_crypto::sc_reduce32(&common_hash);
        let mut common_view_key = [0u8; 32];
        common_view_key.copy_from_slice(&common_reduced[..32]);

        Ok((multisig_pubkey, common_view_key))
    }

    /// Generate a verification message for the post-KEX verification round.
    ///
    /// Contains a hash of the aggregate key so all participants can confirm agreement.
    pub fn verification_message(
        &self,
        multisig_pubkey: &[u8; 32],
        common_view_key: &[u8; 32],
    ) -> KexMessage {
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(b"multisig_kex_verify");
        verify_data.extend_from_slice(multisig_pubkey);
        verify_data.extend_from_slice(common_view_key);
        let verify_hash = salvium_crypto::keccak256(&verify_data);

        KexMessage {
            round: kex_rounds_required(self.threshold, self.signer_count) + 1,
            signer_index: self.signer_index,
            keys: vec![hex::encode(&verify_hash)],
            msg_type: MultisigMsgType::KexVerify,
        }
    }

    /// Verify that all signers derived the same aggregate key.
    pub fn verify_kex(
        &self,
        messages: &[KexMessage],
        multisig_pubkey: &[u8; 32],
        common_view_key: &[u8; 32],
    ) -> Result<(), String> {
        let expected = self.verification_message(multisig_pubkey, common_view_key);
        let expected_hash = &expected.keys[0];

        for msg in messages {
            if msg.msg_type != MultisigMsgType::KexVerify {
                return Err(format!(
                    "expected KexVerify from signer {}, got {:?}",
                    msg.signer_index, msg.msg_type
                ));
            }
            if msg.keys.is_empty() {
                return Err(format!(
                    "signer {} sent empty verification",
                    msg.signer_index
                ));
            }
            if msg.keys[0] != *expected_hash {
                return Err(format!(
                    "signer {} derived a different aggregate key",
                    msg.signer_index
                ));
            }
        }

        Ok(())
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// A message exchanged during the multisig key-exchange protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KexMessage {
    /// The KEX round number (1-indexed).
    pub round: usize,
    /// Index of the signer who produced this message.
    pub signer_index: usize,
    /// Hex-encoded public keys contributed during this round.
    pub keys: Vec<String>,
    /// The type of this message.
    pub msg_type: MultisigMsgType,
}

impl KexMessage {
    /// Create a new KexMessage with default values.
    pub fn new() -> Self {
        Self {
            round: 0,
            signer_index: 0,
            keys: Vec::new(),
            msg_type: MultisigMsgType::KexInit,
        }
    }

    /// Serialize to a JSON byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("KexMessage serialization should not fail")
    }

    /// Deserialize from a JSON byte slice.
    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| format!("Failed to deserialize KexMessage: {}", e))
    }

    /// Deserialize from a JSON string.
    pub fn from_string(s: &str) -> Result<Self, String> {
        serde_json::from_str(s).map_err(|e| format!("Failed to parse KexMessage: {}", e))
    }
}

impl std::fmt::Display for KexMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).expect("KexMessage to_string should not fail"))
    }
}

impl Default for KexMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: convert Vec<u8> from scalar_mult_base to [u8; 32].
    fn to_32(v: Vec<u8>) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v[..32]);
        arr
    }

    #[test]
    fn test_kex_rounds_required_2_of_2() {
        // N - M + 1 = 2 - 2 + 1 = 1
        assert_eq!(kex_rounds_required(2, 2), 1);
    }

    #[test]
    fn test_kex_rounds_required_2_of_3() {
        // N - M + 1 = 3 - 2 + 1 = 2
        assert_eq!(kex_rounds_required(2, 3), 2);
    }

    #[test]
    fn test_kex_rounds_required_3_of_3() {
        // N - M + 1 = 3 - 3 + 1 = 1
        assert_eq!(kex_rounds_required(3, 3), 1);
    }

    #[test]
    fn test_kex_rounds_required_various() {
        assert_eq!(kex_rounds_required(2, 4), 3);  // 4 - 2 + 1
        assert_eq!(kex_rounds_required(3, 4), 2);  // 4 - 3 + 1
        assert_eq!(kex_rounds_required(4, 4), 1);  // 4 - 4 + 1
        assert_eq!(kex_rounds_required(5, 5), 1);  // 5 - 5 + 1
        assert_eq!(kex_rounds_required(2, 10), 9); // 10 - 2 + 1
    }

    #[test]
    fn test_kex_message_default() {
        let msg = KexMessage::new();
        assert_eq!(msg.round, 0);
        assert_eq!(msg.signer_index, 0);
        assert!(msg.keys.is_empty());
        assert_eq!(msg.msg_type, MultisigMsgType::KexInit);
    }

    #[test]
    fn test_kex_message_serialize_deserialize_roundtrip() {
        let msg = KexMessage {
            round: 1,
            signer_index: 0,
            keys: vec![
                "aa".repeat(32),
                "bb".repeat(32),
            ],
            msg_type: MultisigMsgType::KexRound,
        };

        let serialized = msg.serialize();
        let restored = KexMessage::deserialize(&serialized).unwrap();

        assert_eq!(restored.round, msg.round);
        assert_eq!(restored.signer_index, msg.signer_index);
        assert_eq!(restored.keys.len(), 2);
        assert_eq!(restored.keys[0], msg.keys[0]);
        assert_eq!(restored.keys[1], msg.keys[1]);
        assert_eq!(restored.msg_type, MultisigMsgType::KexRound);
    }

    #[test]
    fn test_kex_message_to_string_from_string_roundtrip() {
        let msg = KexMessage {
            round: 2,
            signer_index: 1,
            keys: vec!["11".repeat(32)],
            msg_type: MultisigMsgType::KexVerify,
        };

        let s = msg.to_string();
        let restored = KexMessage::from_string(&s).unwrap();

        assert_eq!(restored.round, msg.round);
        assert_eq!(restored.signer_index, msg.signer_index);
        assert_eq!(restored.keys.len(), 1);
        assert_eq!(restored.msg_type, MultisigMsgType::KexVerify);
    }

    #[test]
    fn test_kex_message_deserialize_invalid() {
        let result = KexMessage::deserialize(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_kex_message_from_string_invalid() {
        let result = KexMessage::from_string("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_cofactored_dh_deterministic() {
        let mut sk = [0u8; 32];
        sk[0] = 3;
        let sk_reduced = salvium_crypto::sc_reduce32(&sk);
        let mut sk32 = [0u8; 32];
        sk32.copy_from_slice(&sk_reduced[..32]);

        let pk = to_32(salvium_crypto::scalar_mult_base(&sk32));

        let d1 = cofactored_dh(&sk32, &pk);
        let d2 = cofactored_dh(&sk32, &pk);
        assert_eq!(d1, d2);
        // Result should not be identity
        assert_ne!(d1, [0u8; 32]);
    }

    #[test]
    fn test_aggregation_coefficient_deterministic() {
        let pk1 = to_32(salvium_crypto::scalar_mult_base(&[1u8; 32]));
        let pk2 = to_32(salvium_crypto::scalar_mult_base(&[2u8; 32]));
        let all = vec![pk1, pk2];

        let c1 = aggregation_coefficient(&pk1, &all);
        let c2 = aggregation_coefficient(&pk1, &all);
        assert_eq!(c1, c2);
        // Coefficients for different keys should differ
        let c3 = aggregation_coefficient(&pk2, &all);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_kex_round_processor_2_of_2() {
        // 2-of-2: 1 main round + verification
        let mut sk0 = [0u8; 32];
        sk0[0] = 10;
        let sk0r = salvium_crypto::sc_reduce32(&sk0);
        let mut sk0_32 = [0u8; 32];
        sk0_32.copy_from_slice(&sk0r[..32]);
        let pk0 = to_32(salvium_crypto::scalar_mult_base(&sk0_32));

        let mut sk1 = [0u8; 32];
        sk1[0] = 20;
        let sk1r = salvium_crypto::sc_reduce32(&sk1);
        let mut sk1_32 = [0u8; 32];
        sk1_32.copy_from_slice(&sk1r[..32]);
        let pk1 = to_32(salvium_crypto::scalar_mult_base(&sk1_32));

        let mut proc0 = KexRoundProcessor::new(0, 2, 2, sk0_32);
        let mut proc1 = KexRoundProcessor::new(1, 2, 2, sk1_32);

        // Round 1 messages
        let msg0 = KexMessage {
            round: 1, signer_index: 0,
            keys: vec![hex::encode(pk0), hex::encode(pk0)],
            msg_type: MultisigMsgType::KexInit,
        };
        let msg1 = KexMessage {
            round: 1, signer_index: 1,
            keys: vec![hex::encode(pk1), hex::encode(pk1)],
            msg_type: MultisigMsgType::KexInit,
        };

        // For 2-of-2, main rounds = 1, so process_round1 returns None
        let out0 = proc0.process_round1(&[msg0.clone(), msg1.clone()]).unwrap();
        let out1 = proc1.process_round1(&[msg0, msg1]).unwrap();
        assert!(out0.is_none());
        assert!(out1.is_none());

        // Finalize
        let (agg0, view0) = proc0.finalize().unwrap();
        let (agg1, view1) = proc1.finalize().unwrap();
        assert_eq!(agg0, agg1);
        assert_eq!(view0, view1);

        // Verification
        let v0 = proc0.verification_message(&agg0, &view0);
        let v1 = proc1.verification_message(&agg1, &view1);
        proc0.verify_kex(&[v0.clone(), v1.clone()], &agg0, &view0).unwrap();
        proc1.verify_kex(&[v0, v1], &agg1, &view1).unwrap();
    }

    #[test]
    fn test_kex_round_processor_2_of_3() {
        // 2-of-3: 2 main rounds + verification
        let make_key = |b: u8| -> ([u8; 32], [u8; 32]) {
            let mut sk = [0u8; 32];
            sk[0] = b;
            let r = salvium_crypto::sc_reduce32(&sk);
            let mut s32 = [0u8; 32];
            s32.copy_from_slice(&r[..32]);
            let pk = to_32(salvium_crypto::scalar_mult_base(&s32));
            (s32, pk)
        };

        let (sk0, pk0) = make_key(10);
        let (sk1, pk1) = make_key(20);
        let (sk2, pk2) = make_key(30);

        let mut proc0 = KexRoundProcessor::new(0, 3, 2, sk0);
        let mut proc1 = KexRoundProcessor::new(1, 3, 2, sk1);
        let mut proc2 = KexRoundProcessor::new(2, 3, 2, sk2);

        let round1_msgs: Vec<KexMessage> = vec![
            KexMessage {
                round: 1, signer_index: 0,
                keys: vec![hex::encode(pk0), hex::encode(pk0)],
                msg_type: MultisigMsgType::KexInit,
            },
            KexMessage {
                round: 1, signer_index: 1,
                keys: vec![hex::encode(pk1), hex::encode(pk1)],
                msg_type: MultisigMsgType::KexInit,
            },
            KexMessage {
                round: 1, signer_index: 2,
                keys: vec![hex::encode(pk2), hex::encode(pk2)],
                msg_type: MultisigMsgType::KexInit,
            },
        ];

        // Round 1 -> should produce round 2 messages
        let out0 = proc0.process_round1(&round1_msgs).unwrap().unwrap();
        let out1 = proc1.process_round1(&round1_msgs).unwrap().unwrap();
        let out2 = proc2.process_round1(&round1_msgs).unwrap().unwrap();
        assert_eq!(out0.round, 2);
        assert_eq!(out1.round, 2);
        assert_eq!(out2.round, 2);

        // Round 2 (final main round for 2-of-3) -> should return None
        let round2_msgs = vec![out0, out1, out2];
        let fin0 = proc0.process_round_n(2, &round2_msgs).unwrap();
        let fin1 = proc1.process_round_n(2, &round2_msgs).unwrap();
        let fin2 = proc2.process_round_n(2, &round2_msgs).unwrap();
        assert!(fin0.is_none());
        assert!(fin1.is_none());
        assert!(fin2.is_none());

        // All three should derive the same aggregate key
        let (agg0, view0) = proc0.finalize().unwrap();
        let (agg1, view1) = proc1.finalize().unwrap();
        let (agg2, view2) = proc2.finalize().unwrap();
        assert_eq!(agg0, agg1);
        assert_eq!(agg1, agg2);
        assert_eq!(view0, view1);
        assert_eq!(view1, view2);
    }
}
