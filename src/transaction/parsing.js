/**
 * Transaction Parsing Module
 *
 * Handles all parsing operations for transactions and blocks:
 * - Transaction parsing (parseTransaction)
 * - Extra field parsing (parseExtra)
 * - RingCT signature parsing (Salvium and Monero formats)
 * - Block parsing (parseBlock)
 * - Pricing record parsing (parsePricingRecord)
 *
 * @module transaction/parsing
 */

import { hexToBytes } from '../address.js';

import {
  ParseError,
  TX_TYPE,
  RCT_TYPE,
  TXIN_TYPE,
  TXOUT_TYPE,
  HF_VERSION_ENABLE_ORACLE
} from './constants.js';

import { decodeVarint } from './serialization.js';
import { getCryptoBackend, getCurrentBackendType } from '../crypto/provider.js';

// =============================================================================
// TRANSACTION PARSING
// =============================================================================

/**
 * Convert hex string fields in a Rust-parsed result back to Uint8Array
 * for JS API compatibility.
 */
function convertHexFieldsToUint8Array(obj) {
  if (!obj || typeof obj !== 'object') return obj;

  // Recursively process arrays
  if (Array.isArray(obj)) {
    return obj.map(convertHexFieldsToUint8Array);
  }

  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) {
      result[key] = value;
    } else if (Array.isArray(value)) {
      result[key] = value.map(convertHexFieldsToUint8Array);
    } else if (typeof value === 'object') {
      result[key] = convertHexFieldsToUint8Array(value);
    } else if (typeof value === 'string') {
      // Convert fields that should be Uint8Array (32-byte keys, key images, etc.)
      // Fields that are hex-encoded binary data (not amounts/strings)
      if (['key', 'keyImage', 'return_address', 'return_pubkey',
           'viewTag', 'encryptedJanusAnchor', 'p_r',
           'R', 'z1', 'z2', 'c1', 'D', 'A', 'A1', 'B',
           'r1', 's1', 'd1', 'spend_pubkey', 'aR', 'aR_stake',
           'return_address_change_mask',
           'return_view_tag', 'return_anchor_enc'].includes(key)) {
        result[key] = hexToBytes(value);
      } else if (key === 'amount' && value.length === 16 && /^[0-9a-f]+$/i.test(value)) {
        // ecdhInfo amount is 8-byte hex, not a decimal string
        result[key] = hexToBytes(value);
      } else if (['amount_burnt', 'amount_slippage_limit', 'txnFee'].includes(key)) {
        // These are decimal strings — convert to BigInt
        result[key] = BigInt(value);
      } else if (key === 'amount' && /^\d+$/.test(value)) {
        // Regular amounts are decimal strings from Rust
        result[key] = BigInt(value);
      } else {
        result[key] = value;
      }
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Parse a Salvium transaction from binary data
 *
 * @param {Uint8Array|string} data - Raw transaction data (binary or hex)
 * @returns {Object} Parsed transaction object
 */
export function parseTransaction(data, { useNative = false } = {}) {
  if (typeof data === 'string') {
    data = hexToBytes(data);
  }

  // Rust backend: opt-in only (the JSON→hex→Uint8Array marshalling overhead
  // makes it slower than the direct JS parser for hot-path sync).
  if (useNative) {
    const bt = getCurrentBackendType();
    if (bt === 'ffi' || bt === 'wasm' || bt === 'jsi') {
      try {
        const backend = getCryptoBackend();
        if (backend.parseTransaction) {
          const result = backend.parseTransaction(data);
          if (result && !result.error) {
            return convertHexFieldsToUint8Array(result);
          }
        }
      } catch (_e) {
        // Fall through to JS implementation
      }
    }
  }

  let offset = 0;

  // Helper to read bytes
  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  // Helper to read varint
  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // Parse transaction prefix
  const version = Number(readVarint());
  const unlockTime = Number(readVarint());

  // Parse inputs
  const vinCount = Number(readVarint());
  const vin = [];

  for (let i = 0; i < vinCount; i++) {
    const inputType = data[offset++];

    if (inputType === TXIN_TYPE.GEN) {
      // Coinbase input
      const height = Number(readVarint());
      vin.push({ type: TXIN_TYPE.GEN, height });
    } else if (inputType === TXIN_TYPE.KEY) {
      // Key input (Salvium format includes asset_type)
      const amount = readVarint();

      // Salvium-specific: read asset_type string (length-prefixed)
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const keyOffsetCount = Number(readVarint());
      const keyOffsets = [];
      for (let j = 0; j < keyOffsetCount; j++) {
        keyOffsets.push(Number(readVarint()));
      }
      const keyImage = readBytes(32);
      vin.push({
        type: TXIN_TYPE.KEY,
        amount,
        assetType,
        keyOffsets,
        keyImage
      });
    } else {
      throw new Error(`Unknown input type: ${inputType}`);
    }
  }

  // Parse outputs
  const voutCount = Number(readVarint());
  const vout = [];

  for (let i = 0; i < voutCount; i++) {
    const amount = readVarint();
    const outputType = data[offset++];

    if (outputType === TXOUT_TYPE.KEY) {
      // Salvium txout_to_key: key + asset_type + unlock_time
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const outputUnlockTime = Number(readVarint());

      vout.push({
        type: TXOUT_TYPE.KEY,
        amount,
        key,
        assetType,
        unlockTime: outputUnlockTime
      });
    } else if (outputType === TXOUT_TYPE.TAGGED_KEY) {
      // Salvium txout_to_tagged_key: key + asset_type + unlock_time + view_tag
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const outputUnlockTime = Number(readVarint());
      const viewTag = data[offset++];

      vout.push({
        type: TXOUT_TYPE.TAGGED_KEY,
        amount,
        key,
        assetType,
        unlockTime: outputUnlockTime,
        viewTag
      });
    } else if (outputType === 0x04) {
      // Salvium txout_to_carrot_v1: key + asset_type + view_tag(3) + encrypted_janus_anchor(16)
      const key = readBytes(32);

      // Salvium-specific: read asset_type string
      const assetTypeLen = Number(readVarint());
      let assetType = '';
      if (assetTypeLen > 0) {
        const assetTypeBytes = readBytes(assetTypeLen);
        assetType = new TextDecoder().decode(assetTypeBytes);
      }

      const viewTag = readBytes(3);  // carrot view_tag is 3 bytes
      const encryptedJanusAnchor = readBytes(16);  // janus anchor is 16 bytes

      vout.push({
        type: 0x04,  // CARROT_V1
        amount,
        key,
        assetType,
        viewTag,
        encryptedJanusAnchor
      });
    } else {
      throw new Error(`Unknown output type: ${outputType}`);
    }
  }

  // Parse extra
  const extraSize = Number(readVarint());
  const extraBytes = readBytes(extraSize);
  const extra = parseExtra(extraBytes);

  // Salvium-specific transaction prefix fields (cryptonote_basic.h lines 249-280)
  const txType = Number(readVarint());

  let amount_burnt = 0n;
  let return_address = null;
  let return_address_list = null;
  let return_address_change_mask = null;
  let return_pubkey = null;
  let source_asset_type = '';
  let destination_asset_type = '';
  let amount_slippage_limit = 0n;
  let protocol_tx_data = null;

  // TX_TYPE: see TX_TYPE constant
  if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    // type != UNSET && type != PROTOCOL
    amount_burnt = readVarint();

    if (txType !== TX_TYPE.MINER) {
      // type != MINER
      if (txType === TX_TYPE.TRANSFER && version >= 3) {
        // TRANSFER with version >= TRANSACTION_VERSION_N_OUTS (3)
        const returnListCount = Number(readVarint());
        return_address_list = [];
        for (let i = 0; i < returnListCount; i++) {
          return_address_list.push(readBytes(32));
        }
        const changeMaskCount = Number(readVarint());
        return_address_change_mask = readBytes(changeMaskCount);
      } else if (txType === TX_TYPE.STAKE && version >= 4) {
        // STAKE with version >= TRANSACTION_VERSION_CARROT (4)
        // protocol_tx_data_t has: version(varint), return_address(32), return_pubkey(32), return_view_tag(3), return_anchor_enc(16)
        protocol_tx_data = {
          version: Number(readVarint()),
          return_address: readBytes(32),
          return_pubkey: readBytes(32),
          return_view_tag: readBytes(3),
          return_anchor_enc: readBytes(16)
        };
      } else {
        return_address = readBytes(32);
        return_pubkey = readBytes(32);
      }

      // source_asset_type (string)
      const srcTypeLen = Number(readVarint());
      if (srcTypeLen > 0) {
        source_asset_type = new TextDecoder().decode(readBytes(srcTypeLen));
      }

      // destination_asset_type (string)
      const dstTypeLen = Number(readVarint());
      if (dstTypeLen > 0) {
        destination_asset_type = new TextDecoder().decode(readBytes(dstTypeLen));
      }

      amount_slippage_limit = readVarint();
    }
  }

  const prefix = {
    version,
    unlockTime,
    vin,
    vout,
    extra,
    // Salvium-specific
    txType,
    amount_burnt,
    return_address,
    return_address_list,
    return_address_change_mask,
    return_pubkey,
    source_asset_type,
    destination_asset_type,
    amount_slippage_limit,
    protocol_tx_data
  };

  // For v1 transactions, we're done
  if (version === 1) {
    return { prefix, _bytesRead: offset, _prefixEndOffset: offset };
  }

  // Track prefix end offset for _bytesRead calculation
  const prefixEndOffset = offset;

  // Get mixin from first input (needed for CLSAG parsing)
  const mixin = vin.length > 0 && vin[0].keyOffsets ? vin[0].keyOffsets.length - 1 : 15;

  // Parse RingCT signature for v2+ transactions
  const rct = parseRingCtSignature(data, offset, vin.length, vout.length, mixin);

  // Use actual end offset from RCT parsing for accurate _bytesRead
  const rctEndOffset = rct._endOffset || (prefixEndOffset + 1); // fallback to prefix + 1 byte for Null type
  delete rct._endOffset; // Clean up internal field

  return { prefix, rct, _bytesRead: rctEndOffset, _prefixEndOffset: prefixEndOffset };
}

// =============================================================================
// EXTRA FIELD PARSING
// =============================================================================

/**
 * Parse transaction extra field
 *
 * @param {Uint8Array} extraBytes - Raw extra bytes
 * @returns {Array} Parsed extra fields
 */
export function parseExtra(extraBytes) {
  // Try Rust backend first (faster, matches C++ behavior exactly)
  const bt = getCurrentBackendType();
  if (bt === 'ffi' || bt === 'wasm' || bt === 'jsi') {
    try {
      const backend = getCryptoBackend();
      if (backend.parseExtra) {
        const jsonStr = backend.parseExtra(extraBytes);
        if (jsonStr && jsonStr !== '[]') {
          const entries = JSON.parse(jsonStr);
          // Convert hex strings back to Uint8Array for JS API compatibility
          for (const entry of entries) {
            if (entry.key && typeof entry.key === 'string') {
              entry.key = hexToBytes(entry.key);
            }
            if (entry.keys && Array.isArray(entry.keys)) {
              entry.keys = entry.keys.map(k => typeof k === 'string' ? hexToBytes(k) : k);
            }
            if (entry.data && typeof entry.data === 'string') {
              entry.data = hexToBytes(entry.data);
            }
            if (entry.paymentId && typeof entry.paymentId === 'string') {
              entry.paymentId = hexToBytes(entry.paymentId);
            }
          }
          return entries;
        }
      }
    } catch (_e) {
      // Fall through to JS implementation
    }
  }

  // JS fallback
  const extra = [];
  let offset = 0;

  while (offset < extraBytes.length) {
    const tag = extraBytes[offset++];

    switch (tag) {
      case 0x00: // TX_EXTRA_TAG_PADDING
        // Skip padding bytes (value 0x00)
        while (offset < extraBytes.length && extraBytes[offset] === 0x00) {
          offset++;
        }
        extra.push({ type: 0x00, tag: 'padding' });
        break;

      case 0x01: // TX_EXTRA_TAG_PUBKEY
        if (offset + 32 > extraBytes.length) {
          throw new Error('Invalid tx pubkey in extra');
        }
        const txPubKey = extraBytes.slice(offset, offset + 32);
        offset += 32;
        extra.push({ type: 0x01, tag: 'tx_pubkey', key: txPubKey });
        break;

      case 0x02: // TX_EXTRA_NONCE
        const nonceSize = extraBytes[offset++];
        if (offset + nonceSize > extraBytes.length) {
          throw new Error('Invalid nonce in extra');
        }
        const nonce = extraBytes.slice(offset, offset + nonceSize);
        offset += nonceSize;

        // Parse nonce contents (payment ID, encrypted payment ID, etc.)
        const nonceContent = parseExtraNonce(nonce);
        extra.push({ type: 0x02, tag: 'nonce', ...nonceContent });
        break;

      case 0x03: // TX_EXTRA_MERGE_MINING_TAG
        const { value: mmSize, bytesRead } = decodeVarint(extraBytes, offset);
        offset += bytesRead;
        const mmData = extraBytes.slice(offset, offset + Number(mmSize));
        offset += Number(mmSize);
        extra.push({ type: 0x03, tag: 'merge_mining', data: mmData });
        break;

      case 0x04: // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS
        const pubkeyCount = extraBytes[offset++];
        const additionalPubkeys = [];
        for (let i = 0; i < pubkeyCount; i++) {
          if (offset + 32 > extraBytes.length) {
            throw new Error('Invalid additional pubkey in extra');
          }
          additionalPubkeys.push(extraBytes.slice(offset, offset + 32));
          offset += 32;
        }
        extra.push({ type: 0x04, tag: 'additional_pubkeys', keys: additionalPubkeys });
        break;

      case 0xDE: { // TX_EXTRA_MYSTERIOUS_MINERGATE_TAG — varint size + data
        if (offset < extraBytes.length) {
          const { value: fieldLen, bytesRead: lenBytes } = decodeVarint(extraBytes, offset);
          const skipLen = Number(fieldLen);
          if (offset + lenBytes + skipLen <= extraBytes.length) {
            extra.push({ type: 0xDE, tag: 'minergate', data: extraBytes.slice(offset + lenBytes, offset + lenBytes + skipLen) });
            offset += lenBytes + skipLen;
          } else {
            offset = extraBytes.length;
          }
        }
        break;
      }

      default: {
        // Unknown tag — try varint-length skip (CryptoNote convention)
        let skipped = false;
        if (offset < extraBytes.length) {
          try {
            const { value: fieldLen, bytesRead: lenBytes } = decodeVarint(extraBytes, offset);
            const skipLen = Number(fieldLen);
            if (skipLen >= 0 && offset + lenBytes + skipLen <= extraBytes.length) {
              extra.push({ type: tag, tag: 'unknown', data: extraBytes.slice(offset + lenBytes, offset + lenBytes + skipLen) });
              offset += lenBytes + skipLen;
              skipped = true;
            }
          } catch (_e) {
            // Varint decode failed
          }
        }
        if (!skipped) {
          extra.push({ type: tag, tag: 'unknown', offset: offset - 1 });
          offset = extraBytes.length;
        }
        break;
      }
    }
  }

  return extra;
}

/**
 * Parse extra nonce content
 *
 * @param {Uint8Array} nonce - Nonce bytes
 * @returns {Object} Parsed nonce content
 */
function parseExtraNonce(nonce) {
  if (nonce.length === 0) {
    return { raw: nonce };
  }

  const tag = nonce[0];

  // Payment ID (unencrypted, 32 bytes)
  if (tag === 0x00 && nonce.length === 33) {
    return {
      paymentIdType: 'unencrypted',
      paymentId: nonce.slice(1)
    };
  }

  // Encrypted payment ID (8 bytes)
  if (tag === 0x01 && nonce.length === 9) {
    return {
      paymentIdType: 'encrypted',
      paymentId: nonce.slice(1)
    };
  }

  return { raw: nonce };
}

// =============================================================================
// RINGCT SIGNATURE PARSING
// =============================================================================

/**
 * Parse RingCT signature data (Salvium format)
 *
 * Salvium RCT format differs from Monero:
 * 1. Header byte (not RCT type)
 * 2. Salvium-specific data
 * 3. Asset type strings (length-prefixed, "SAL" or "SAL1")
 * 4. Separator byte (0x00)
 * 5. Actual RCT type
 * 6. Fee varint
 * 7. ecdhInfo
 * 8. outPk
 * 9. p_r (Salvium-specific, 32 bytes)
 * 10. Prunable data (bulletproofs, CLSAGs, pseudoOuts)
 *
 * @param {Uint8Array} data - Full transaction data
 * @param {number} startOffset - Starting offset for RCT data
 * @param {number} inputCount - Number of inputs
 * @param {number} outputCount - Number of outputs
 * @param {number} mixin - Ring size minus 1 (from first input's key_offsets.length - 1)
 * @returns {Object} Parsed RingCT signature
 */
function parseRingCtSignature(data, startOffset, inputCount, outputCount, mixin = 15) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of RCT data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // Salvium RCT format (rctTypes.h lines 430-489):
  // 1. type (1 byte)
  // 2. txnFee (varint) - if type != Null
  // 3. ecdhInfo (8 bytes per output for BulletproofPlus types)
  // 4. outPk (32 bytes per output - mask only)
  // 5. p_r (32 bytes)
  // 6. salvium_data - only for SalviumZero/SalviumOne types

  // RCT type
  const type = data[offset++];

  if (type === RCT_TYPE.Null) {
    return { type, _endOffset: offset };
  }

  // Valid types for Salvium
  const validTypes = [
    RCT_TYPE.BulletproofPlus,  // 6
    RCT_TYPE.FullProofs,       // 7
    RCT_TYPE.SalviumZero,      // 8
    RCT_TYPE.SalviumOne        // 9
  ];

  if (!validTypes.includes(type)) {
    throw new Error(`Invalid RCT type: ${type} at offset ${offset - 1}`);
  }

  // Fee
  const fee = readVarint();

  // ECDH info (encrypted amounts) - 8 bytes per output for BulletproofPlus types
  const ecdhInfo = [];
  for (let i = 0; i < outputCount; i++) {
    ecdhInfo.push({ amount: readBytes(8) });
  }

  // Output commitments (outPk) - 32 bytes per output
  const outPk = [];
  for (let i = 0; i < outputCount; i++) {
    outPk.push(readBytes(32));
  }

  // p_r - Salvium-specific field (32 bytes)
  const p_r = readBytes(32);

  const rct = {
    type,
    txnFee: fee,
    ecdhInfo,
    outPk,
    p_r
  };

  // Parse salvium_data based on type (matches Salvium rctTypes.h lines 486-494)
  // Note: salvium_data parsing is optional for wallet scanning - we have enough
  // info from outPk/ecdhInfo for output detection
  try {
    if (type === RCT_TYPE.SalviumZero || type === RCT_TYPE.SalviumOne) {
      // Full salvium_data_t
      rct.salvium_data = parseSalviumData(data, offset, true);
      offset = rct.salvium_data._endOffset;
      delete rct.salvium_data._endOffset;
    } else if (type === RCT_TYPE.FullProofs) {
      // Only pr_proof and sa_proof (2 x zk_proof = 2 x 96 bytes)
      rct.salvium_data = {
        pr_proof: parseZkProof(data, offset),
        sa_proof: parseZkProof(data, offset + 96)
      };
      offset += 192;
    }
  } catch (e) {
    // If salvium_data parsing fails, we can still use the transaction for scanning
    // Just mark it as having a parse error and skip the prunable section
    rct.salvium_data_parse_error = e.message;
    rct._endOffset = offset;
    return rct; // Return early with what we have
  }

  // Parse prunable data (bulletproofs + CLSAGs) with bounds checking
  // The prunable section follows the base section
  if (offset < data.length && type !== RCT_TYPE.Null) {
    try {
      const prunable = parseRctSigPrunable(data, offset, type, inputCount, outputCount, mixin);
      rct.bulletproofPlus = prunable.bulletproofPlus;
      rct.CLSAGs = prunable.CLSAGs;
      rct.TCLSAGs = prunable.TCLSAGs;
      rct.pseudoOuts = prunable.pseudoOuts;
      if (prunable._endOffset) {
        offset = prunable._endOffset;
      }
    } catch (e) {
      if (e instanceof ParseError) {
        rct.prunable_parse_error = e.toString();
      } else {
        rct.prunable_parse_error = `Unexpected error parsing prunable: ${e.message}`;
      }
    }
  }

  rct._endOffset = offset;
  return rct;
}

/**
 * Parse RingCT signature data (Monero format - for compatibility)
 */
function parseRingCtSignatureMonero(data, startOffset, inputCount, outputCount) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of RCT data at offset ${offset}`);
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // RCT type
  const type = data[offset++];

  if (type === RCT_TYPE.Null) {
    return { type };
  }

  // Fee
  const fee = readVarint();

  // Pseudo outputs (for simple/bulletproof types)
  const pseudoOuts = [];
  if (type === RCT_TYPE.Simple || type >= RCT_TYPE.Bulletproof) {
    for (let i = 0; i < inputCount; i++) {
      pseudoOuts.push(readBytes(32));
    }
  }

  // ECDH info (encrypted amounts)
  const ecdhInfo = [];
  for (let i = 0; i < outputCount; i++) {
    if (type >= RCT_TYPE.Bulletproof2) {
      ecdhInfo.push({ amount: readBytes(8) });
    } else {
      ecdhInfo.push({
        mask: readBytes(32),
        amount: readBytes(32)
      });
    }
  }

  // Output commitments
  const outPk = [];
  for (let i = 0; i < outputCount; i++) {
    outPk.push(readBytes(32));
  }

  return {
    type,
    txnFee: fee,
    pseudoOuts,
    ecdhInfo,
    outPk
  };
}

/**
 * Parse zk_proof structure (R, z1, z2 - 3 x 32 bytes = 96 bytes)
 * Matches Salvium rctTypes.h lines 94-103
 */
function parseZkProof(data, offset) {
  return {
    R: data.slice(offset, offset + 32),
    z1: data.slice(offset + 32, offset + 64),
    z2: data.slice(offset + 64, offset + 96)
  };
}

/**
 * Parse salvium_data_t structure
 * Matches Salvium rctTypes.h lines 390-412
 */
function parseSalviumData(data, startOffset, full = true) {
  let offset = startOffset;

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const result = {};

  // salvium_data_type (varint)
  result.salvium_data_type = Number(readVarint());

  // pr_proof (zk_proof = 96 bytes)
  result.pr_proof = parseZkProof(data, offset);
  offset += 96;

  // sa_proof (zk_proof = 96 bytes)
  result.sa_proof = parseZkProof(data, offset);
  offset += 96;

  // SalviumZeroAudit (type 1) has additional fields
  if (result.salvium_data_type === 1) {
    // cz_proof (zk_proof = 96 bytes)
    result.cz_proof = parseZkProof(data, offset);
    offset += 96;

    // input_verification_data (vector of salvium_input_data_t)
    const inputCount = Number(readVarint());
    result.input_verification_data = [];
    for (let i = 0; i < inputCount; i++) {
      // salvium_input_data_t (per rctTypes.h lines 371-388):
      // - aR: key_derivation (32 bytes)
      // - amount: xmr_amount (VARINT_FIELD)
      // - i: size_t (VARINT_FIELD)
      // - origin_tx_type: uint8_t (VARINT_FIELD)
      // - if origin_tx_type != UNSET:
      //   - aR_stake: key_derivation (FIELD = 32 bytes)
      //   - i_stake: size_t (FIELD = 8 bytes little-endian, NOT varint!)
      const aR = data.slice(offset, offset + 32);
      offset += 32;
      const amount = readVarint();
      const idx = Number(readVarint());
      const origin_tx_type = Number(readVarint());

      const inputData = { aR, amount, i: idx, origin_tx_type };

      // Per Salvium source: if (origin_tx_type != cryptonote::transaction_type::UNSET)
      if (origin_tx_type !== 0) {
        inputData.aR_stake = data.slice(offset, offset + 32);
        offset += 32;
        // i_stake uses FIELD() for size_t = 8 bytes little-endian uint64
        inputData.i_stake = Number(
          BigInt(data[offset]) |
          (BigInt(data[offset + 1]) << 8n) |
          (BigInt(data[offset + 2]) << 16n) |
          (BigInt(data[offset + 3]) << 24n) |
          (BigInt(data[offset + 4]) << 32n) |
          (BigInt(data[offset + 5]) << 40n) |
          (BigInt(data[offset + 6]) << 48n) |
          (BigInt(data[offset + 7]) << 56n)
        );
        offset += 8;
      }

      result.input_verification_data.push(inputData);
    }

    // spend_pubkey (32 bytes)
    result.spend_pubkey = data.slice(offset, offset + 32);
    offset += 32;

    // enc_view_privkey_str (length-prefixed string)
    const strLen = Number(readVarint());
    result.enc_view_privkey_str = new TextDecoder().decode(data.slice(offset, offset + strLen));
    offset += strLen;
  }

  result._endOffset = offset;
  return result;
}

/**
 * Parse RCT prunable section (bulletproofs + CLSAGs/TCLSAGs + pseudoOuts)
 * Matches Salvium rctTypes.h lines 518-679
 *
 * @param {number} mixin - Ring size minus 1 (CLSAG s array has mixin+1 elements with NO size prefix)
 */
function parseRctSigPrunable(data, startOffset, type, inputCount, outputCount, mixin) {
  let offset = startOffset;

  const readBytes = (count, fieldName) => {
    if (offset + count > data.length) {
      throw new ParseError(`Unexpected end of data reading ${fieldName}`, {
        field: fieldName,
        offset,
        expected: count,
        actual: data.length - offset,
        dataLength: data.length
      });
    }
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = (fieldName) => {
    if (offset >= data.length) {
      throw new ParseError(`Unexpected end of data reading varint for ${fieldName}`, {
        field: fieldName,
        offset,
        dataLength: data.length
      });
    }
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const result = { _endOffset: offset };

  // For BulletproofPlus types (6, 7, 8, 9), parse BulletproofPlus
  if (type >= RCT_TYPE.BulletproofPlus) {
    const nbp = readVarint('bulletproofPlus count');
    if (nbp > 1000) {
      throw new ParseError('Invalid bulletproofPlus count', {
        field: 'bulletproofPlus count',
        offset,
        expected: '<=1000',
        actual: nbp
      });
    }

    result.bulletproofPlus = [];
    for (let i = 0; i < nbp; i++) {
      const A = readBytes(32, `bulletproofPlus[${i}].A`);
      const A1 = readBytes(32, `bulletproofPlus[${i}].A1`);
      const B = readBytes(32, `bulletproofPlus[${i}].B`);
      const r1 = readBytes(32, `bulletproofPlus[${i}].r1`);
      const s1 = readBytes(32, `bulletproofPlus[${i}].s1`);
      const d1 = readBytes(32, `bulletproofPlus[${i}].d1`);

      // L array
      const Lcount = readVarint(`bulletproofPlus[${i}].L count`);
      if (Lcount > 64) {
        throw new ParseError('Invalid L array count in bulletproofPlus', {
          field: `bulletproofPlus[${i}].L count`,
          offset,
          expected: '<=64',
          actual: Lcount
        });
      }
      const L = [];
      for (let j = 0; j < Lcount; j++) {
        L.push(readBytes(32, `bulletproofPlus[${i}].L[${j}]`));
      }

      // R array (has its own varint count, same as L in practice)
      const Rcount = readVarint(`bulletproofPlus[${i}].R count`);
      if (Rcount > 64) {
        throw new ParseError('Invalid R array count in bulletproofPlus', {
          field: `bulletproofPlus[${i}].R count`,
          offset,
          expected: '<=64',
          actual: Rcount
        });
      }
      const R = [];
      for (let j = 0; j < Rcount; j++) {
        R.push(readBytes(32, `bulletproofPlus[${i}].R[${j}]`));
      }

      result.bulletproofPlus.push({ A, A1, B, r1, s1, d1, L, R });
    }
  }

  // Parse CLSAGs or TCLSAGs based on type
  // Note: s/sx/sy arrays have NO size prefix - size is mixin + 1
  const ringSize = mixin + 1;

  if (type === RCT_TYPE.SalviumOne) {
    // TCLSAGs (Twin CLSAG) - has sx and sy arrays (Salvium rctTypes.h lines 560-612)
    result.TCLSAGs = [];
    for (let i = 0; i < inputCount; i++) {
      // sx array: mixin + 1 elements, NO size prefix
      const sx = [];
      for (let j = 0; j < ringSize; j++) {
        sx.push(readBytes(32, `TCLSAG[${i}].sx[${j}]`));
      }

      // sy array: mixin + 1 elements, NO size prefix
      const sy = [];
      for (let j = 0; j < ringSize; j++) {
        sy.push(readBytes(32, `TCLSAG[${i}].sy[${j}]`));
      }

      const c1 = readBytes(32, `TCLSAG[${i}].c1`);
      const D = readBytes(32, `TCLSAG[${i}].D`);

      result.TCLSAGs.push({ sx, sy, c1, D });
    }
  } else if (type >= RCT_TYPE.CLSAG) {
    // CLSAGs (Salvium rctTypes.h lines 613-652)
    result.CLSAGs = [];
    for (let i = 0; i < inputCount; i++) {
      // s array: mixin + 1 elements, NO size prefix
      const s = [];
      for (let j = 0; j < ringSize; j++) {
        s.push(readBytes(32, `CLSAG[${i}].s[${j}]`));
      }

      const c1 = readBytes(32, `CLSAG[${i}].c1`);
      const D = readBytes(32, `CLSAG[${i}].D`);

      result.CLSAGs.push({ s, c1, D });
    }
  }

  // pseudoOuts (for types that have them in prunable)
  if (type >= RCT_TYPE.BulletproofPlus) {
    result.pseudoOuts = [];
    for (let i = 0; i < inputCount; i++) {
      result.pseudoOuts.push(readBytes(32, `pseudoOuts[${i}]`));
    }
  }

  result._endOffset = offset;
  return result;
}

/**
 * Parse Bulletproofs range proof
 */
function parseBulletproofs(data, startOffset) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const proofCount = Number(readVarint());
  const proofs = [];

  for (let i = 0; i < proofCount; i++) {
    const A = readBytes(32);
    const S = readBytes(32);
    const T1 = readBytes(32);
    const T2 = readBytes(32);
    const taux = readBytes(32);
    const mu = readBytes(32);

    const Lcount = Number(readVarint());
    const L = [];
    for (let j = 0; j < Lcount; j++) {
      L.push(readBytes(32));
    }

    const Rcount = Number(readVarint());
    const R = [];
    for (let j = 0; j < Rcount; j++) {
      R.push(readBytes(32));
    }

    const a = readBytes(32);
    const b = readBytes(32);
    const t = readBytes(32);

    proofs.push({ A, S, T1, T2, taux, mu, L, R, a, b, t });
  }

  return { proofs, _endOffset: offset };
}

/**
 * Parse Bulletproofs+ range proof
 */
function parseBulletproofPlus(data, startOffset, outputCount) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  const proofCount = Number(readVarint());
  const proofs = [];

  for (let i = 0; i < proofCount; i++) {
    const A = readBytes(32);
    const A1 = readBytes(32);
    const B = readBytes(32);
    const r1 = readBytes(32);
    const s1 = readBytes(32);
    const d1 = readBytes(32);

    const Lcount = Number(readVarint());
    const L = [];
    for (let j = 0; j < Lcount; j++) {
      L.push(readBytes(32));
    }

    const Rcount = Number(readVarint());
    const R = [];
    for (let j = 0; j < Rcount; j++) {
      R.push(readBytes(32));
    }

    proofs.push({ A, A1, B, r1, s1, d1, L, R });
  }

  return { proofs, _endOffset: offset };
}

/**
 * Parse CLSAG signature
 */
function parseCLSAG(data, startOffset, ringSize) {
  let offset = startOffset;

  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  // s values (ringSize scalars)
  const s = [];
  for (let i = 0; i < ringSize; i++) {
    s.push(readBytes(32));
  }

  // c1 (scalar)
  const c1 = readBytes(32);

  // D (point)
  const D = readBytes(32);

  return {
    sig: { s, c1, D },
    endOffset: offset
  };
}

// =============================================================================
// BLOCK PARSING
// =============================================================================

/**
 * Parse a Salvium pricing_record from binary data
 *
 * Structure (from oracle/pricing_record.h):
 * - pr_version: varint
 * - height: varint
 * - supply: { sal: varint, vsd: varint }
 * - assets: vector of { asset_type: string, spot_price: varint, ma_price: varint }
 * - timestamp: varint
 * - signature: vector of bytes
 *
 * @param {Uint8Array} data - Raw binary data
 * @param {number} [startOffset=0] - Starting offset in data
 * @returns {{ record: Object, bytesRead: number }} Parsed pricing record and bytes consumed
 */
export function parsePricingRecord(data, startOffset = 0) {
  let offset = startOffset;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data reading ${count} bytes at offset ${offset}`);
    }
    const bytes = data.slice(offset, offset + count);
    offset += count;
    return bytes;
  };

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readString = () => {
    const len = Number(readVarint());
    if (len === 0) return '';
    const bytes = readBytes(len);
    return new TextDecoder().decode(bytes);
  };

  // pr_version
  const prVersion = Number(readVarint());

  // height
  const height = Number(readVarint());

  // supply_data { sal, vsd }
  const supply = {
    sal: readVarint(),
    vsd: readVarint()
  };

  // assets vector
  const assetsCount = Number(readVarint());
  const assets = [];
  for (let i = 0; i < assetsCount; i++) {
    assets.push({
      assetType: readString(),
      spotPrice: readVarint(),
      maPrice: readVarint()
    });
  }

  // timestamp
  const timestamp = Number(readVarint());

  // signature (vector of bytes)
  const signatureLen = Number(readVarint());
  const signature = signatureLen > 0 ? readBytes(signatureLen) : new Uint8Array(0);

  return {
    record: {
      prVersion,
      height,
      supply,
      assets,
      timestamp,
      signature
    },
    bytesRead: offset - startOffset
  };
}

/**
 * Parse a Salvium block from binary data
 *
 * Structure (from cryptonote_basic/cryptonote_basic.h):
 *
 * block_header:
 * - major_version: varint
 * - minor_version: varint
 * - timestamp: varint
 * - prev_id: 32 bytes (hash)
 * - nonce: 4 bytes (uint32 LE)
 * - pricing_record: only if major_version >= HF_VERSION_ENABLE_ORACLE (255)
 *
 * block (extends block_header):
 * - miner_tx: full transaction (coinbase)
 * - protocol_tx: full transaction (Salvium-specific: conversions, yields, refunds)
 * - tx_hashes: vector of 32-byte hashes
 *
 * @param {Uint8Array} data - Raw binary block data
 * @returns {Object} Parsed block
 */
export function parseBlock(data, { useNative = false } = {}) {
  // Rust backend: opt-in only (same marshalling overhead as parseTransaction)
  if (useNative) {
    const bt = getCurrentBackendType();
    if (bt === 'ffi' || bt === 'wasm' || bt === 'jsi') {
      try {
        const backend = getCryptoBackend();
        if (backend.parseBlock) {
          const result = backend.parseBlock(data);
          if (result && !result.error) {
            return convertHexFieldsToUint8Array(result);
          }
        }
      } catch (_e) {
        // Fall through to JS implementation
      }
    }
  }
  let offset = 0;

  const readBytes = (count) => {
    if (offset + count > data.length) {
      throw new Error(`Unexpected end of data reading ${count} bytes at offset ${offset}`);
    }
    const bytes = data.slice(offset, offset + count);
    offset += count;
    return bytes;
  };

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readUint32LE = () => {
    const bytes = readBytes(4);
    return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  };

  // ============================================
  // BLOCK HEADER
  // ============================================

  const majorVersion = Number(readVarint());
  const minorVersion = Number(readVarint());
  const timestamp = Number(readVarint());
  const prevId = readBytes(32);
  const nonce = readUint32LE();

  // Pricing record (only if major_version >= HF_VERSION_ENABLE_ORACLE)
  let pricingRecord = null;
  if (majorVersion >= HF_VERSION_ENABLE_ORACLE) {
    const prResult = parsePricingRecord(data, offset);
    pricingRecord = prResult.record;
    offset += prResult.bytesRead;
  }

  // ============================================
  // BLOCK BODY
  // ============================================

  // Parse miner_tx (coinbase transaction)
  const minerTxStartOffset = offset;
  const minerTxData = data.slice(offset);
  const minerTx = parseTransaction(minerTxData);
  minerTx._blockOffset = minerTxStartOffset;
  offset += minerTx._bytesRead || estimateTransactionSize(minerTxData);

  // Parse protocol_tx (Salvium-specific transaction)
  const protocolTxStartOffset = offset;
  const protocolTxData = data.slice(offset);
  const protocolTx = parseTransaction(protocolTxData);
  protocolTx._blockOffset = protocolTxStartOffset;
  offset += protocolTx._bytesRead || estimateTransactionSize(protocolTxData);

  // Parse tx_hashes vector
  const txHashCount = Number(readVarint());
  const txHashes = [];
  for (let i = 0; i < txHashCount; i++) {
    txHashes.push(readBytes(32));
  }

  return {
    header: {
      majorVersion,
      minorVersion,
      timestamp,
      prevId,
      nonce,
      pricingRecord
    },
    minerTx,
    protocolTx,
    txHashes,
    _bytesRead: offset
  };
}

/**
 * Estimate transaction size by parsing it (internal helper)
 * This is needed because parseTransaction doesn't return bytes read
 *
 * @param {Uint8Array} data - Transaction data
 * @returns {number} Estimated bytes consumed
 * @private
 */
function estimateTransactionSize(data) {
  // Parse the transaction and track how many bytes were consumed
  // This is a simplified re-parse just for size calculation
  let offset = 0;

  const readVarint = () => {
    let result = 0n;
    let shift = 0n;
    while (offset < data.length) {
      const byte = data[offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
    }
    return result;
  };

  const readBytes = (count) => {
    offset += count;
    return data.slice(offset - count, offset);
  };

  // version
  readVarint();
  // unlock_time
  readVarint();

  // inputs
  const vinCount = Number(readVarint());
  for (let i = 0; i < vinCount; i++) {
    const inputType = data[offset++];
    if (inputType === TXIN_TYPE.GEN) {
      readVarint(); // height
    } else if (inputType === TXIN_TYPE.KEY) {
      readVarint(); // amount
      const assetLen = Number(readVarint());
      if (assetLen > 0) readBytes(assetLen);
      const offsets = Number(readVarint());
      for (let j = 0; j < offsets; j++) readVarint();
      readBytes(32); // key image
    }
  }

  // outputs
  const voutCount = Number(readVarint());
  for (let i = 0; i < voutCount; i++) {
    readVarint(); // amount
    const outputType = data[offset++];
    readBytes(32); // key
    const assetLen = Number(readVarint());
    if (assetLen > 0) readBytes(assetLen);
    if (outputType === TXOUT_TYPE.KEY) {
      readVarint(); // unlock_time
    } else if (outputType === TXOUT_TYPE.TAGGED_KEY) {
      readVarint(); // unlock_time
      offset++; // view_tag
    } else if (outputType === 0x04) {
      readBytes(3); // view_tag
      readBytes(16); // anchor
    }
  }

  // extra
  const extraSize = Number(readVarint());
  readBytes(extraSize);

  // tx_type
  const txType = Number(readVarint());

  // Salvium-specific fields (simplified)
  if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    readVarint(); // amount_burnt
    if (txType !== TX_TYPE.MINER) {
      readBytes(32); // return_address
      readBytes(32); // return_pubkey
      readVarint(); // source len
      readVarint(); // dest len
      readVarint(); // slippage
    }
  }

  // RCT type
  const rctType = data[offset++];

  if (rctType === RCT_TYPE.Null) {
    return offset;
  }

  // This is a rough estimate - we don't need exact size for fallback
  return offset + 100; // Add some buffer for RCT data
}
