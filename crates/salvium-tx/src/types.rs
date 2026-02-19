//! Typed transaction structures.
//!
//! Provides strongly-typed representations of Salvium transactions with
//! conversion to/from JSON (for interop with salvium-crypto's parse/serialize)
//! and to/from raw bytes.

use crate::TxError;
use serde_json::Value;

// ─── Transaction Constants ──────────────────────────────────────────────────

pub mod tx_type {
    pub const UNSET: u8 = 0;
    pub const MINER: u8 = 1;
    pub const PROTOCOL: u8 = 2;
    pub const TRANSFER: u8 = 3;
    pub const CONVERT: u8 = 4;
    pub const BURN: u8 = 5;
    pub const STAKE: u8 = 6;
    pub const RETURN: u8 = 7;
    pub const AUDIT: u8 = 8;
}

pub mod rct_type {
    pub const NULL: u8 = 0;
    pub const FULL: u8 = 1;
    pub const SIMPLE: u8 = 2;
    pub const BULLETPROOF: u8 = 3;
    pub const BULLETPROOF2: u8 = 4;
    pub const CLSAG: u8 = 5;
    pub const BULLETPROOF_PLUS: u8 = 6;
    pub const FULL_PROOFS: u8 = 7;
    pub const SALVIUM_ZERO: u8 = 8;
    pub const SALVIUM_ONE: u8 = 9;
}

pub mod output_type {
    pub const KEY: u8 = 0x02;
    pub const TAGGED_KEY: u8 = 0x03;
    pub const CARROT_V1: u8 = 0x04;
}

/// Protocol-specific transaction data for v4 STAKE/AUDIT (CARROT era).
/// Contains the CARROT return enote components.
#[derive(Debug, Clone)]
pub struct ProtocolTxData {
    pub version: u64,
    pub return_address: [u8; 32],
    pub return_pubkey: [u8; 32],
    pub return_view_tag: [u8; 3],
    pub return_anchor_enc: [u8; 16],
}

// ─── Core Transaction Types ─────────────────────────────────────────────────

/// Complete transaction (prefix + RingCT signatures).
#[derive(Debug, Clone)]
pub struct Transaction {
    pub prefix: TxPrefix,
    pub rct: Option<RctSignatures>,
}

/// Transaction prefix (everything before RCT signatures).
#[derive(Debug, Clone)]
pub struct TxPrefix {
    pub version: u64,
    pub unlock_time: u64,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub extra: Vec<u8>,
    pub tx_type: u8,
    // Salvium-specific fields (present for version >= 2).
    pub amount_burnt: u64,
    pub return_address: Option<Vec<u8>>,
    pub return_pubkey: Option<[u8; 32]>,
    pub return_address_list: Option<Vec<Vec<u8>>>,
    pub return_address_change_mask: Option<Vec<u8>>,
    pub protocol_tx_data: Option<ProtocolTxData>,
    pub source_asset_type: String,
    pub destination_asset_type: String,
    pub amount_slippage_limit: u64,
}

/// Transaction input.
#[derive(Debug, Clone)]
pub enum TxInput {
    /// Coinbase (generation) input.
    Gen { height: u64 },
    /// Key input (spending a previous output).
    Key {
        amount: u64,
        asset_type: String,
        key_offsets: Vec<u64>,
        key_image: [u8; 32],
    },
}

/// Transaction output.
#[derive(Debug, Clone)]
pub enum TxOutput {
    /// Legacy key output (pre-view-tag).
    Key {
        amount: u64,
        key: [u8; 32],
        asset_type: String,
        unlock_time: u64,
    },
    /// Tagged key output (with 1-byte view tag).
    TaggedKey {
        amount: u64,
        key: [u8; 32],
        asset_type: String,
        unlock_time: u64,
        view_tag: u8,
    },
    /// CARROT v1 output (3-byte view tag + Janus anchor).
    CarrotV1 {
        amount: u64,
        key: [u8; 32],
        asset_type: String,
        view_tag: [u8; 3],
        encrypted_janus_anchor: Vec<u8>,
    },
}

impl TxOutput {
    pub fn amount(&self) -> u64 {
        match self {
            Self::Key { amount, .. }
            | Self::TaggedKey { amount, .. }
            | Self::CarrotV1 { amount, .. } => *amount,
        }
    }

    pub fn key(&self) -> &[u8; 32] {
        match self {
            Self::Key { key, .. }
            | Self::TaggedKey { key, .. }
            | Self::CarrotV1 { key, .. } => key,
        }
    }

    pub fn asset_type(&self) -> &str {
        match self {
            Self::Key { asset_type, .. }
            | Self::TaggedKey { asset_type, .. }
            | Self::CarrotV1 { asset_type, .. } => asset_type,
        }
    }

    pub fn output_type_tag(&self) -> u8 {
        match self {
            Self::Key { .. } => output_type::KEY,
            Self::TaggedKey { .. } => output_type::TAGGED_KEY,
            Self::CarrotV1 { .. } => output_type::CARROT_V1,
        }
    }
}

// ─── RingCT Signatures ─────────────────────────────────────────────────────

/// RingCT signature data.
#[derive(Debug, Clone)]
pub struct RctSignatures {
    pub rct_type: u8,
    pub txn_fee: u64,
    pub ecdh_info: Vec<EcdhInfo>,
    pub out_pk: Vec<[u8; 32]>,
    pub p_r: Option<[u8; 32]>,
    pub salvium_data: Option<Value>,
    pub bulletproof_plus: Vec<BpPlusData>,
    pub clsags: Vec<ClsagData>,
    pub tclsags: Vec<TclsagData>,
    pub pseudo_outs: Vec<[u8; 32]>,
}

/// Encrypted amount (compact 8-byte ECDH form).
#[derive(Debug, Clone)]
pub struct EcdhInfo {
    pub amount: [u8; 8],
}

/// CLSAG ring signature data.
#[derive(Debug, Clone)]
pub struct ClsagData {
    pub s: Vec<[u8; 32]>,
    pub c1: [u8; 32],
    pub d: [u8; 32],
}

/// TCLSAG twin ring signature data.
#[derive(Debug, Clone)]
pub struct TclsagData {
    pub sx: Vec<[u8; 32]>,
    pub sy: Vec<[u8; 32]>,
    pub c1: [u8; 32],
    pub d: [u8; 32],
}

/// Bulletproofs+ range proof data.
#[derive(Debug, Clone)]
pub struct BpPlusData {
    pub a: [u8; 32],
    pub a1: [u8; 32],
    pub b: [u8; 32],
    pub r1: [u8; 32],
    pub s1: [u8; 32],
    pub d1: [u8; 32],
    pub l_vec: Vec<[u8; 32]>,
    pub r_vec: Vec<[u8; 32]>,
}

// ─── JSON Conversion ────────────────────────────────────────────────────────

impl Transaction {
    /// Parse a transaction from raw binary bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TxError> {
        let json_str = salvium_crypto::parse_transaction_bytes(data);
        let json: Value =
            serde_json::from_str(&json_str).map_err(|e| TxError::Parse(e.to_string()))?;
        Self::from_json(&json)
    }

    /// Parse a transaction from hex-encoded bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, TxError> {
        let bytes = hex::decode(hex_str).map_err(|e| TxError::Parse(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Parse from the JSON structure returned by salvium-crypto's tx_parse.
    pub fn from_json(json: &Value) -> Result<Self, TxError> {
        let prefix_json = json.get("prefix").ok_or(TxError::Parse("missing prefix".into()))?;
        let prefix = TxPrefix::from_json(prefix_json)?;

        let rct = json.get("rct").and_then(|v| {
            if v.is_null() {
                None
            } else {
                RctSignatures::from_json(v).ok()
            }
        });

        Ok(Self { prefix, rct })
    }

    /// Convert to JSON matching salvium-crypto's serialize format.
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("prefix".into(), self.prefix.to_json());
        if let Some(ref rct) = self.rct {
            obj.insert("rct".into(), rct.to_json());
        }
        Value::Object(obj)
    }

    /// Serialize to binary bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TxError> {
        let json = self.to_json();
        let json_str = serde_json::to_string(&json).map_err(|e| TxError::Serialize(e.to_string()))?;
        let bytes = salvium_crypto::serialize_transaction_json(&json_str);
        if bytes.is_empty() {
            return Err(TxError::Serialize("serialization returned empty".into()));
        }
        Ok(bytes)
    }

    /// Compute the transaction hash.
    pub fn tx_hash(&self) -> Result<[u8; 32], TxError> {
        let bytes = self.to_bytes()?;
        Ok(to_32(&salvium_crypto::keccak256(&bytes)))
    }

    /// Compute the prefix hash.
    pub fn prefix_hash(&self) -> Result<[u8; 32], TxError> {
        let json = self.prefix.to_json();
        let json_str = serde_json::to_string(&json).map_err(|e| TxError::Serialize(e.to_string()))?;
        let prefix_bytes = salvium_crypto::tx_serialize::serialize_tx_prefix(&json_str)
            .map_err(TxError::Serialize)?;
        Ok(to_32(&salvium_crypto::keccak256(&prefix_bytes)))
    }

    /// Get the transaction type.
    pub fn tx_type(&self) -> u8 {
        self.prefix.tx_type
    }

    /// Number of inputs.
    pub fn input_count(&self) -> usize {
        self.prefix.inputs.len()
    }

    /// Number of outputs.
    pub fn output_count(&self) -> usize {
        self.prefix.outputs.len()
    }
}

impl TxPrefix {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let version = v.get("version").and_then(|x| x.as_u64()).unwrap_or(2);
        let unlock_time = v.get("unlockTime").and_then(|x| x.as_u64()).unwrap_or(0);
        let tx_type = v.get("txType").and_then(|x| x.as_u64()).unwrap_or(0) as u8;

        let inputs = v
            .get("vin")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|i| TxInput::from_json(i).ok()).collect())
            .unwrap_or_default();

        let outputs = v
            .get("vout")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|o| TxOutput::from_json(o).ok()).collect())
            .unwrap_or_default();

        let extra = v
            .get("extra")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect())
            .unwrap_or_default();

        let amount_burnt = parse_amount_str(v.get("amount_burnt"));
        let source_asset_type = v
            .get("source_asset_type")
            .and_then(|s| s.as_str())
            .unwrap_or("SAL")
            .to_string();
        let destination_asset_type = v
            .get("destination_asset_type")
            .and_then(|s| s.as_str())
            .unwrap_or("SAL")
            .to_string();
        let amount_slippage_limit = parse_amount_str(v.get("amount_slippage_limit"));

        let return_address = v
            .get("return_address")
            .and_then(|s| s.as_str())
            .and_then(|s| hex::decode(s).ok());
        let return_pubkey = v
            .get("return_pubkey")
            .and_then(|s| s.as_str())
            .and_then(hex_to_32);
        let return_address_list = v
            .get("return_address_list")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().and_then(|h| hex::decode(h).ok()))
                    .collect()
            });
        let return_address_change_mask = v
            .get("return_address_change_mask")
            .and_then(|s| s.as_str())
            .and_then(|s| hex::decode(s).ok());

        let protocol_tx_data = v.get("protocol_tx_data").and_then(|ptd| {
            if ptd.is_null() {
                return None;
            }
            let ver = ptd.get("version").and_then(|x| x.as_u64()).unwrap_or(0);
            let ra = ptd.get("return_address").and_then(|s| s.as_str()).and_then(hex_to_32)?;
            let rp = ptd.get("return_pubkey").and_then(|s| s.as_str()).and_then(hex_to_32)?;
            let vt_hex = ptd.get("return_view_tag").and_then(|s| s.as_str())?;
            let vt_bytes = hex::decode(vt_hex).ok()?;
            if vt_bytes.len() < 3 { return None; }
            let mut vt = [0u8; 3];
            vt.copy_from_slice(&vt_bytes[..3]);
            let ae_hex = ptd.get("return_anchor_enc").and_then(|s| s.as_str())?;
            let ae_bytes = hex::decode(ae_hex).ok()?;
            if ae_bytes.len() < 16 { return None; }
            let mut ae = [0u8; 16];
            ae.copy_from_slice(&ae_bytes[..16]);
            Some(ProtocolTxData {
                version: ver,
                return_address: ra,
                return_pubkey: rp,
                return_view_tag: vt,
                return_anchor_enc: ae,
            })
        });

        Ok(Self {
            version,
            unlock_time,
            inputs,
            outputs,
            extra,
            tx_type,
            amount_burnt,
            return_address,
            return_pubkey,
            return_address_list,
            return_address_change_mask,
            protocol_tx_data,
            source_asset_type,
            destination_asset_type,
            amount_slippage_limit,
        })
    }

    pub fn to_json(&self) -> Value {
        let vin: Vec<Value> = self.inputs.iter().map(|i| i.to_json()).collect();
        let vout: Vec<Value> = self.outputs.iter().map(|o| o.to_json()).collect();
        let extra: Vec<Value> = self.extra.iter().map(|&b| Value::from(b as u64)).collect();

        let mut obj = serde_json::json!({
            "version": self.version,
            "unlockTime": self.unlock_time,
            "vin": vin,
            "vout": vout,
            "extra": extra,
            "txType": self.tx_type,
            "amount_burnt": self.amount_burnt.to_string(),
            "source_asset_type": self.source_asset_type,
            "destination_asset_type": self.destination_asset_type,
            "amount_slippage_limit": self.amount_slippage_limit.to_string(),
        });

        if let Some(ref ra) = self.return_address {
            obj["return_address"] = Value::String(hex::encode(ra));
        }
        if let Some(ref rp) = self.return_pubkey {
            obj["return_pubkey"] = Value::String(hex::encode(rp));
        }
        if let Some(ref list) = self.return_address_list {
            obj["return_address_list"] =
                Value::Array(list.iter().map(|a| Value::String(hex::encode(a))).collect());
        }
        if let Some(ref mask) = self.return_address_change_mask {
            obj["return_address_change_mask"] = Value::String(hex::encode(mask));
        }
        if let Some(ref ptd) = self.protocol_tx_data {
            obj["protocol_tx_data"] = serde_json::json!({
                "version": ptd.version,
                "return_address": hex::encode(ptd.return_address),
                "return_pubkey": hex::encode(ptd.return_pubkey),
                "return_view_tag": hex::encode(ptd.return_view_tag),
                "return_anchor_enc": hex::encode(ptd.return_anchor_enc),
            });
        }

        obj
    }
}

impl TxInput {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let type_tag = v.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u8;
        match type_tag {
            0xff => {
                let height = v.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
                Ok(Self::Gen { height })
            }
            0x02 => {
                let amount = parse_amount_str(v.get("amount"));
                let asset_type = v
                    .get("assetType")
                    .and_then(|s| s.as_str())
                    .unwrap_or("SAL")
                    .to_string();
                let key_offsets = v
                    .get("keyOffsets")
                    .and_then(|a| a.as_array())
                    .map(|arr| arr.iter().filter_map(|x| x.as_u64()).collect())
                    .unwrap_or_default();
                let key_image = v
                    .get("keyImage")
                    .and_then(|s| s.as_str())
                    .and_then(hex_to_32)
                    .ok_or(TxError::Parse("missing keyImage".into()))?;
                Ok(Self::Key {
                    amount,
                    asset_type,
                    key_offsets,
                    key_image,
                })
            }
            _ => Err(TxError::Parse(format!("unknown input type: {}", type_tag))),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Gen { height } => serde_json::json!({
                "type": 0xff_u64,
                "height": height,
            }),
            Self::Key {
                amount,
                asset_type,
                key_offsets,
                key_image,
            } => serde_json::json!({
                "type": 0x02_u64,
                "amount": amount.to_string(),
                "assetType": asset_type,
                "keyOffsets": key_offsets,
                "keyImage": hex::encode(key_image),
            }),
        }
    }

    pub fn key_image(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Key { key_image, .. } => Some(key_image),
            _ => None,
        }
    }
}

impl TxOutput {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let type_tag = v.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u8;
        let amount = parse_amount_str(v.get("amount"));
        let key = v
            .get("key")
            .and_then(|s| s.as_str())
            .and_then(hex_to_32)
            .ok_or(TxError::Parse("missing output key".into()))?;
        let asset_type = v
            .get("assetType")
            .and_then(|s| s.as_str())
            .unwrap_or("SAL")
            .to_string();

        match type_tag {
            output_type::KEY => {
                let unlock_time = v.get("unlockTime").and_then(|u| u.as_u64()).unwrap_or(0);
                Ok(Self::Key {
                    amount,
                    key,
                    asset_type,
                    unlock_time,
                })
            }
            output_type::TAGGED_KEY => {
                let unlock_time = v.get("unlockTime").and_then(|u| u.as_u64()).unwrap_or(0);
                let view_tag = v.get("viewTag").and_then(|t| t.as_u64()).unwrap_or(0) as u8;
                Ok(Self::TaggedKey {
                    amount,
                    key,
                    asset_type,
                    unlock_time,
                    view_tag,
                })
            }
            output_type::CARROT_V1 => {
                let view_tag = v
                    .get("viewTag")
                    .and_then(|s| s.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .and_then(|b| {
                        if b.len() >= 3 {
                            Some([b[0], b[1], b[2]])
                        } else {
                            None
                        }
                    })
                    .unwrap_or([0; 3]);
                let encrypted_janus_anchor = v
                    .get("encryptedJanusAnchor")
                    .and_then(|s| s.as_str())
                    .and_then(|s| hex::decode(s).ok())
                    .unwrap_or_default();
                Ok(Self::CarrotV1 {
                    amount,
                    key,
                    asset_type,
                    view_tag,
                    encrypted_janus_anchor,
                })
            }
            _ => {
                // Default to Key for unknown types.
                Ok(Self::Key {
                    amount,
                    key,
                    asset_type,
                    unlock_time: 0,
                })
            }
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Key {
                amount,
                key,
                asset_type,
                unlock_time,
            } => serde_json::json!({
                "type": output_type::KEY as u64,
                "amount": amount.to_string(),
                "key": hex::encode(key),
                "assetType": asset_type,
                "unlockTime": unlock_time,
            }),
            Self::TaggedKey {
                amount,
                key,
                asset_type,
                unlock_time,
                view_tag,
            } => serde_json::json!({
                "type": output_type::TAGGED_KEY as u64,
                "amount": amount.to_string(),
                "key": hex::encode(key),
                "assetType": asset_type,
                "unlockTime": unlock_time,
                "viewTag": *view_tag as u64,
            }),
            Self::CarrotV1 {
                amount,
                key,
                asset_type,
                view_tag,
                encrypted_janus_anchor,
            } => serde_json::json!({
                "type": output_type::CARROT_V1 as u64,
                "amount": amount.to_string(),
                "key": hex::encode(key),
                "assetType": asset_type,
                "viewTag": hex::encode(view_tag),
                "encryptedJanusAnchor": hex::encode(encrypted_janus_anchor),
            }),
        }
    }
}

impl RctSignatures {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let rct_type = v.get("type").and_then(|t| t.as_u64()).unwrap_or(0) as u8;
        let txn_fee = parse_amount_str(v.get("txnFee"));

        let ecdh_info = v
            .get("ecdhInfo")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|e| {
                        let amt = e
                            .get("amount")
                            .and_then(|s| s.as_str())
                            .and_then(|s| hex::decode(s).ok())
                            .and_then(|b| {
                                if b.len() >= 8 {
                                    let mut a = [0u8; 8];
                                    a.copy_from_slice(&b[..8]);
                                    Some(a)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or([0u8; 8]);
                        EcdhInfo { amount: amt }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let out_pk = parse_hex_array_32(v.get("outPk"));
        let pseudo_outs = parse_hex_array_32(v.get("pseudoOuts"));
        let p_r = v
            .get("p_r")
            .and_then(|s| s.as_str())
            .and_then(hex_to_32);

        let salvium_data = v.get("salvium_data").cloned();

        let bulletproof_plus = v
            .get("bulletproofPlus")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|p| BpPlusData::from_json(p).ok()).collect())
            .unwrap_or_default();

        let clsags = v
            .get("CLSAGs")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|s| ClsagData::from_json(s).ok()).collect())
            .unwrap_or_default();

        let tclsags = v
            .get("TCLSAGs")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|s| TclsagData::from_json(s).ok()).collect())
            .unwrap_or_default();

        Ok(Self {
            rct_type,
            txn_fee,
            ecdh_info,
            out_pk,
            p_r,
            salvium_data,
            bulletproof_plus,
            clsags,
            tclsags,
            pseudo_outs,
        })
    }

    pub fn to_json(&self) -> Value {
        let ecdh: Vec<Value> = self
            .ecdh_info
            .iter()
            .map(|e| serde_json::json!({ "amount": hex::encode(e.amount) }))
            .collect();
        let out_pk: Vec<Value> = self.out_pk.iter().map(|p| Value::String(hex::encode(p))).collect();
        let pseudo: Vec<Value> = self
            .pseudo_outs
            .iter()
            .map(|p| Value::String(hex::encode(p)))
            .collect();

        let mut obj = serde_json::json!({
            "type": self.rct_type as u64,
            "txnFee": self.txn_fee.to_string(),
            "ecdhInfo": ecdh,
            "outPk": out_pk,
            "pseudoOuts": pseudo,
        });

        if let Some(ref pr) = self.p_r {
            obj["p_r"] = Value::String(hex::encode(pr));
        }
        if let Some(ref sd) = self.salvium_data {
            obj["salvium_data"] = sd.clone();
        }
        if !self.bulletproof_plus.is_empty() {
            obj["bulletproofPlus"] =
                Value::Array(self.bulletproof_plus.iter().map(|p| p.to_json()).collect());
        }
        if !self.clsags.is_empty() {
            obj["CLSAGs"] = Value::Array(self.clsags.iter().map(|s| s.to_json()).collect());
        }
        if !self.tclsags.is_empty() {
            obj["TCLSAGs"] = Value::Array(self.tclsags.iter().map(|s| s.to_json()).collect());
        }

        obj
    }
}

impl ClsagData {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let s = parse_hex_array_32(v.get("s"));
        let c1 = v
            .get("c1")
            .and_then(|x| x.as_str())
            .and_then(hex_to_32)
            .ok_or(TxError::Parse("missing CLSAG c1".into()))?;
        let d = v
            .get("D")
            .and_then(|x| x.as_str())
            .and_then(hex_to_32)
            .ok_or(TxError::Parse("missing CLSAG D".into()))?;
        Ok(Self { s, c1, d })
    }

    pub fn to_json(&self) -> Value {
        let s: Vec<Value> = self.s.iter().map(|x| Value::String(hex::encode(x))).collect();
        serde_json::json!({
            "s": s,
            "c1": hex::encode(self.c1),
            "D": hex::encode(self.d),
        })
    }
}

impl TclsagData {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let sx = parse_hex_array_32(v.get("sx"));
        let sy = parse_hex_array_32(v.get("sy"));
        let c1 = v
            .get("c1")
            .and_then(|x| x.as_str())
            .and_then(hex_to_32)
            .ok_or(TxError::Parse("missing TCLSAG c1".into()))?;
        let d = v
            .get("D")
            .and_then(|x| x.as_str())
            .and_then(hex_to_32)
            .ok_or(TxError::Parse("missing TCLSAG D".into()))?;
        Ok(Self { sx, sy, c1, d })
    }

    pub fn to_json(&self) -> Value {
        let sx: Vec<Value> = self.sx.iter().map(|x| Value::String(hex::encode(x))).collect();
        let sy: Vec<Value> = self.sy.iter().map(|x| Value::String(hex::encode(x))).collect();
        serde_json::json!({
            "sx": sx,
            "sy": sy,
            "c1": hex::encode(self.c1),
            "D": hex::encode(self.d),
        })
    }
}

impl BpPlusData {
    pub fn from_json(v: &Value) -> Result<Self, TxError> {
        let get32 = |field: &str| -> Result<[u8; 32], TxError> {
            v.get(field)
                .and_then(|s| s.as_str())
                .and_then(hex_to_32)
                .ok_or(TxError::Parse(format!("missing BP+ field: {}", field)))
        };

        Ok(Self {
            a: get32("A")?,
            a1: get32("A1")?,
            b: get32("B")?,
            r1: get32("r1")?,
            s1: get32("s1")?,
            d1: get32("d1")?,
            l_vec: parse_hex_array_32(v.get("L")),
            r_vec: parse_hex_array_32(v.get("R")),
        })
    }

    pub fn to_json(&self) -> Value {
        let l: Vec<Value> = self.l_vec.iter().map(|x| Value::String(hex::encode(x))).collect();
        let r: Vec<Value> = self.r_vec.iter().map(|x| Value::String(hex::encode(x))).collect();
        serde_json::json!({
            "A": hex::encode(self.a),
            "A1": hex::encode(self.a1),
            "B": hex::encode(self.b),
            "r1": hex::encode(self.r1),
            "s1": hex::encode(self.s1),
            "d1": hex::encode(self.d1),
            "L": l,
            "R": r,
        })
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(to_32(&bytes))
}

fn parse_hex_array_32(v: Option<&Value>) -> Vec<[u8; 32]> {
    v.and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().and_then(hex_to_32))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_amount_str(v: Option<&Value>) -> u64 {
    v.and_then(|x| {
        if let Some(n) = x.as_u64() {
            Some(n)
        } else {
            x.as_str().and_then(|s| s.parse::<u64>().ok())
        }
    })
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_input_gen_roundtrip() {
        let input = TxInput::Gen { height: 12345 };
        let json = input.to_json();
        let parsed = TxInput::from_json(&json).unwrap();
        match parsed {
            TxInput::Gen { height } => assert_eq!(height, 12345),
            _ => panic!("wrong input type"),
        }
    }

    #[test]
    fn test_tx_input_key_roundtrip() {
        let input = TxInput::Key {
            amount: 0,
            asset_type: "SAL".to_string(),
            key_offsets: vec![100, 200, 50],
            key_image: [0xAA; 32],
        };
        let json = input.to_json();
        let parsed = TxInput::from_json(&json).unwrap();
        match parsed {
            TxInput::Key {
                key_image,
                key_offsets,
                ..
            } => {
                assert_eq!(key_image, [0xAA; 32]);
                assert_eq!(key_offsets, vec![100, 200, 50]);
            }
            _ => panic!("wrong input type"),
        }
    }

    #[test]
    fn test_tx_output_tagged_key_roundtrip() {
        let output = TxOutput::TaggedKey {
            amount: 0,
            key: [0xBB; 32],
            asset_type: "SAL".to_string(),
            unlock_time: 0,
            view_tag: 42,
        };
        let json = output.to_json();
        let parsed = TxOutput::from_json(&json).unwrap();
        match parsed {
            TxOutput::TaggedKey { key, view_tag, .. } => {
                assert_eq!(key, [0xBB; 32]);
                assert_eq!(view_tag, 42);
            }
            _ => panic!("wrong output type"),
        }
    }

    #[test]
    fn test_tx_output_carrot_roundtrip() {
        let output = TxOutput::CarrotV1 {
            amount: 0,
            key: [0xCC; 32],
            asset_type: "SAL".to_string(),
            view_tag: [1, 2, 3],
            encrypted_janus_anchor: vec![0xDD; 16],
        };
        let json = output.to_json();
        let parsed = TxOutput::from_json(&json).unwrap();
        match parsed {
            TxOutput::CarrotV1 {
                key,
                view_tag,
                encrypted_janus_anchor,
                ..
            } => {
                assert_eq!(key, [0xCC; 32]);
                assert_eq!(view_tag, [1, 2, 3]);
                assert_eq!(encrypted_janus_anchor.len(), 16);
            }
            _ => panic!("wrong output type"),
        }
    }

    #[test]
    fn test_tx_output_accessors() {
        let o = TxOutput::Key {
            amount: 1000,
            key: [0x11; 32],
            asset_type: "SAL1".to_string(),
            unlock_time: 0,
        };
        assert_eq!(o.amount(), 1000);
        assert_eq!(o.key(), &[0x11; 32]);
        assert_eq!(o.asset_type(), "SAL1");
        assert_eq!(o.output_type_tag(), output_type::KEY);
    }

    #[test]
    fn test_ecdh_info_roundtrip() {
        let rct = RctSignatures {
            rct_type: rct_type::SALVIUM_ONE,
            txn_fee: 30000000,
            ecdh_info: vec![EcdhInfo {
                amount: [1, 2, 3, 4, 5, 6, 7, 8],
            }],
            out_pk: vec![[0xEE; 32]],
            p_r: Some([0xFF; 32]),
            salvium_data: None,
            bulletproof_plus: vec![],
            clsags: vec![],
            tclsags: vec![],
            pseudo_outs: vec![],
        };
        let json = rct.to_json();
        let parsed = RctSignatures::from_json(&json).unwrap();
        assert_eq!(parsed.rct_type, rct_type::SALVIUM_ONE);
        assert_eq!(parsed.txn_fee, 30000000);
        assert_eq!(parsed.ecdh_info[0].amount, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(parsed.out_pk[0], [0xEE; 32]);
    }

    #[test]
    fn test_clsag_data_roundtrip() {
        let clsag = ClsagData {
            s: vec![[1u8; 32], [2u8; 32]],
            c1: [3u8; 32],
            d: [4u8; 32],
        };
        let json = clsag.to_json();
        let parsed = ClsagData::from_json(&json).unwrap();
        assert_eq!(parsed.s.len(), 2);
        assert_eq!(parsed.c1, [3u8; 32]);
    }

    #[test]
    fn test_tclsag_data_roundtrip() {
        let tclsag = TclsagData {
            sx: vec![[5u8; 32]],
            sy: vec![[6u8; 32]],
            c1: [7u8; 32],
            d: [8u8; 32],
        };
        let json = tclsag.to_json();
        let parsed = TclsagData::from_json(&json).unwrap();
        assert_eq!(parsed.sx[0], [5u8; 32]);
        assert_eq!(parsed.sy[0], [6u8; 32]);
    }

    #[test]
    fn test_bp_plus_roundtrip() {
        let bp = BpPlusData {
            a: [0x10; 32],
            a1: [0x11; 32],
            b: [0x12; 32],
            r1: [0x13; 32],
            s1: [0x14; 32],
            d1: [0x15; 32],
            l_vec: vec![[0x16; 32], [0x17; 32]],
            r_vec: vec![[0x18; 32], [0x19; 32]],
        };
        let json = bp.to_json();
        let parsed = BpPlusData::from_json(&json).unwrap();
        assert_eq!(parsed.a, [0x10; 32]);
        assert_eq!(parsed.l_vec.len(), 2);
        assert_eq!(parsed.r_vec.len(), 2);
    }

    #[test]
    fn test_parse_amount_str() {
        assert_eq!(parse_amount_str(Some(&Value::from(42u64))), 42);
        assert_eq!(
            parse_amount_str(Some(&Value::String("1000000".into()))),
            1000000
        );
        assert_eq!(parse_amount_str(None), 0);
    }

    #[test]
    fn test_full_tx_prefix_roundtrip() {
        let prefix = TxPrefix {
            version: 2,
            unlock_time: 0,
            inputs: vec![TxInput::Gen { height: 100 }],
            outputs: vec![TxOutput::TaggedKey {
                amount: 600000000000,
                key: [0xAA; 32],
                asset_type: "SAL".to_string(),
                unlock_time: 160,
                view_tag: 0xBB,
            }],
            extra: vec![1, 0xCC],
            tx_type: tx_type::MINER,
            amount_burnt: 0,
            return_address: None,
            return_pubkey: None,
            return_address_list: None,
            return_address_change_mask: None,
            protocol_tx_data: None,
            source_asset_type: "SAL".to_string(),
            destination_asset_type: "SAL".to_string(),
            amount_slippage_limit: 0,
        };

        let json = prefix.to_json();
        let parsed = TxPrefix::from_json(&json).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.tx_type, tx_type::MINER);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].amount(), 600000000000);
    }
}
