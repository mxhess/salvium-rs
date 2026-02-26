//! Shared test helpers for RCT signature verification against real chain data.
//!
//! Used by both `rct_verify_testnet.rs` and `mainnet_validation.rs`.

use salvium_rpc::daemon::{DaemonRpc, OutputRequest};
use salvium_tx::builder::relative_to_absolute;
use salvium_tx::types::*;

pub fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

pub fn write_varint(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

pub fn serialize_salvium_data_for_hash(buf: &mut Vec<u8>, sd: &Option<serde_json::Value>) {
    let sd = match sd {
        Some(v) => v,
        None => return,
    };
    let dt = sd.get("salvium_data_type").and_then(|v| v.as_u64()).unwrap_or(0);
    write_varint(buf, dt);

    // pr_proof
    serialize_zk_proof_for_hash(buf, sd.get("pr_proof"));
    // sa_proof
    serialize_zk_proof_for_hash(buf, sd.get("sa_proof"));

    if dt == 1 {
        // SalviumZeroAudit: cz_proof + input_verification_data + spend_pubkey + enc_view_privkey
        serialize_zk_proof_for_hash(buf, sd.get("cz_proof"));

        if let Some(ivd) = sd.get("input_verification_data").and_then(|v| v.as_array()) {
            write_varint(buf, ivd.len() as u64);
            for item in ivd {
                let ar = item.get("aR").and_then(|v| v.as_str()).unwrap_or("");
                if let Ok(bytes) = hex::decode(ar) {
                    buf.extend_from_slice(&bytes);
                } else {
                    buf.extend_from_slice(&[0u8; 32]);
                }
                let amount = item.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                write_varint(buf, amount);
                let i_val = item.get("i").and_then(|v| v.as_u64()).unwrap_or(0);
                write_varint(buf, i_val);
                let origin = item.get("origin_tx_type").and_then(|v| v.as_u64()).unwrap_or(0);
                write_varint(buf, origin);
                if origin != 0 {
                    let ar_stake = item.get("aR_stake").and_then(|v| v.as_str()).unwrap_or("");
                    if let Ok(bytes) = hex::decode(ar_stake) {
                        buf.extend_from_slice(&bytes);
                    } else {
                        buf.extend_from_slice(&[0u8; 32]);
                    }
                    let i_stake = item.get("i_stake").and_then(|v| v.as_u64()).unwrap_or(0);
                    buf.extend_from_slice(&i_stake.to_le_bytes());
                }
            }
        } else {
            write_varint(buf, 0);
        }

        // spend_pubkey
        let spk = sd.get("spend_pubkey").and_then(|v| v.as_str()).unwrap_or("");
        if let Ok(bytes) = hex::decode(spk) {
            buf.extend_from_slice(&bytes);
        } else {
            buf.extend_from_slice(&[0u8; 32]);
        }

        // enc_view_privkey_str
        let evp = sd.get("enc_view_privkey_str").and_then(|v| v.as_str()).unwrap_or("");
        let evp_bytes = evp.as_bytes();
        write_varint(buf, evp_bytes.len() as u64);
        buf.extend_from_slice(evp_bytes);
    }
}

pub fn serialize_zk_proof_for_hash(buf: &mut Vec<u8>, proof: Option<&serde_json::Value>) {
    let proof = match proof {
        Some(v) if !v.is_null() => v,
        _ => {
            buf.extend_from_slice(&[0u8; 96]);
            return;
        }
    };

    let r = proof.get("R").and_then(|v| v.as_str()).unwrap_or("");
    let z1 = proof.get("z1").and_then(|v| v.as_str()).unwrap_or("");
    let z2 = proof.get("z2").and_then(|v| v.as_str()).unwrap_or("");

    if r.is_empty() {
        buf.extend_from_slice(&[0u8; 96]);
    } else if let (Ok(r_b), Ok(z1_b), Ok(z2_b)) = (hex::decode(r), hex::decode(z1), hex::decode(z2))
    {
        buf.extend_from_slice(&r_b);
        buf.extend_from_slice(&z1_b);
        buf.extend_from_slice(&z2_b);
    } else {
        buf.extend_from_slice(&[0u8; 96]);
    }
}

pub struct VerificationData {
    pub rct_type: u8,
    pub message: [u8; 32],
    pub input_count: usize,
    pub ring_size: usize,
    pub key_images: Vec<[u8; 32]>,
    pub pseudo_outs: Vec<[u8; 32]>,
    pub sigs_flat: Vec<u8>,
    pub ring_pubkeys: Vec<[u8; 32]>,
    pub ring_commitments: Vec<[u8; 32]>,
}

/// Fetch a transaction by hash and parse it.
pub async fn fetch_and_parse_tx(d: &DaemonRpc, tx_hash: &str) -> (Transaction, Vec<u8>) {
    let entries = d.get_transactions(&[tx_hash], true).await.expect("get_transactions failed");
    let entry = &entries[0];
    assert!(!entry.as_hex.is_empty(), "TX {} has no hex data", tx_hash);

    let raw_bytes = hex::decode(&entry.as_hex).expect("invalid TX hex");
    let tx = Transaction::from_bytes(&raw_bytes).expect("failed to parse TX");
    (tx, raw_bytes)
}

/// Fetch ring members for all key inputs in a transaction.
/// Returns one Vec<(key, mask)> per key input.
pub async fn fetch_mix_ring(d: &DaemonRpc, tx: &Transaction) -> Vec<Vec<([u8; 32], [u8; 32])>> {
    let mut mix_ring = Vec::new();

    for input in &tx.prefix.inputs {
        match input {
            TxInput::Gen { .. } => continue,
            TxInput::Key { key_offsets, asset_type, .. } => {
                let abs_indices = relative_to_absolute(key_offsets);
                let requests: Vec<OutputRequest> = abs_indices
                    .iter()
                    .map(|&idx| OutputRequest { amount: 0, index: idx })
                    .collect();

                let outs = d.get_outs(&requests, false, asset_type).await.expect("get_outs failed");
                assert_eq!(outs.len(), abs_indices.len(), "get_outs returned wrong count");

                let ring: Vec<([u8; 32], [u8; 32])> =
                    outs.iter().map(|out| (hex_to_32(&out.key), hex_to_32(&out.mask))).collect();
                mix_ring.push(ring);
            }
        }
    }

    mix_ring
}

/// Build the flat data arrays needed for rct_verify from a parsed TX and its ring.
pub fn prepare_verification_data(
    tx: &Transaction,
    mix_ring: &[Vec<([u8; 32], [u8; 32])>],
    _raw_bytes: &[u8],
) -> VerificationData {
    let rct = tx.rct.as_ref().expect("TX has no RCT data");

    let prefix_hash = tx.prefix_hash().expect("failed to compute prefix hash");

    // Build rct_base bytes for message hash computation.
    let mut rct_base = Vec::new();
    write_varint(&mut rct_base, rct.rct_type as u64);
    write_varint(&mut rct_base, rct.txn_fee);
    for ei in &rct.ecdh_info {
        rct_base.extend_from_slice(&ei.amount);
    }
    for pk in &rct.out_pk {
        rct_base.extend_from_slice(pk);
    }
    // p_r
    if let Some(ref pr) = rct.p_r {
        rct_base.extend_from_slice(pr);
    } else {
        let mut identity = [0u8; 32];
        identity[0] = 0x01;
        rct_base.extend_from_slice(&identity);
    }
    // salvium_data
    serialize_salvium_data_for_hash(&mut rct_base, &rct.salvium_data);

    // Build BP+ components bytes.
    let mut bp_bytes = Vec::new();
    for bp in &rct.bulletproof_plus {
        bp_bytes.extend_from_slice(&bp.a);
        bp_bytes.extend_from_slice(&bp.a1);
        bp_bytes.extend_from_slice(&bp.b);
        bp_bytes.extend_from_slice(&bp.r1);
        bp_bytes.extend_from_slice(&bp.s1);
        bp_bytes.extend_from_slice(&bp.d1);
        for l in &bp.l_vec {
            bp_bytes.extend_from_slice(l);
        }
        for r in &bp.r_vec {
            bp_bytes.extend_from_slice(r);
        }
    }

    // Compute message.
    let message =
        salvium_crypto::rct_verify::compute_rct_message(&prefix_hash, &rct_base, &bp_bytes);

    // Collect key images from prefix inputs.
    let key_images: Vec<[u8; 32]> =
        tx.prefix.inputs.iter().filter_map(|i| i.key_image().copied()).collect();

    // Flatten ring data.
    let ring_size = if !mix_ring.is_empty() { mix_ring[0].len() } else { 0 };
    let mut ring_pubkeys = Vec::new();
    let mut ring_commitments = Vec::new();
    for ring in mix_ring {
        for (key, mask) in ring {
            ring_pubkeys.push(*key);
            ring_commitments.push(*mask);
        }
    }

    // Build flat sig bytes.
    let mut sigs_flat = Vec::new();
    let is_tclsag = rct.rct_type == rct_type::SALVIUM_ONE;
    if is_tclsag {
        for sig in &rct.tclsags {
            for s in &sig.sx {
                sigs_flat.extend_from_slice(s);
            }
            for s in &sig.sy {
                sigs_flat.extend_from_slice(s);
            }
            sigs_flat.extend_from_slice(&sig.c1);
            sigs_flat.extend_from_slice(&sig.d);
        }
    } else {
        for sig in &rct.clsags {
            for s in &sig.s {
                sigs_flat.extend_from_slice(s);
            }
            sigs_flat.extend_from_slice(&sig.c1);
            sigs_flat.extend_from_slice(&sig.d);
        }
    }

    VerificationData {
        rct_type: rct.rct_type,
        message,
        input_count: key_images.len(),
        ring_size,
        key_images,
        pseudo_outs: rct.pseudo_outs.clone(),
        sigs_flat,
        ring_pubkeys,
        ring_commitments,
    }
}
