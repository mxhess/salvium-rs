/**
 * Transaction Serialization Module
 *
 * Handles all serialization operations for transactions:
 * - Scalar operations (mod L arithmetic)
 * - Pedersen commitments
 * - Varint encoding/decoding
 * - Transaction prefix serialization
 * - RingCT serialization
 * - CLSAG signature serialization
 *
 * @module transaction/serialization
 */

import { keccak256 } from '../keccak.js';
import { scalarMultBase, scalarMultPoint, pointAddCompressed } from '../ed25519.js';
import { bytesToHex, hexToBytes } from '../address.js';

import {
  L,
  H,
  TX_TYPE,
  RCT_TYPE,
  TXOUT_TYPE,
  TXIN_TYPE
} from './constants.js';

// =============================================================================
// SCALAR OPERATIONS MOD L
// =============================================================================

/**
 * Convert bytes to BigInt (little-endian)
 * @param {Uint8Array|string} bytes - Input bytes or hex string
 * @returns {bigint} BigInt value
 */
export function bytesToBigInt(bytes) {
  if (typeof bytes === 'string') {
    bytes = hexToBytes(bytes);
  }
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Convert BigInt to bytes (little-endian, 32 bytes)
 * @param {bigint} n - BigInt value
 * @returns {Uint8Array} 32-byte array
 */
export function bigIntToBytes(n) {
  // Ensure positive
  n = ((n % L) + L) % L;
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return bytes;
}

/**
 * Reduce a scalar mod L
 * @param {Uint8Array|string} scalar - 32-byte scalar
 * @returns {Uint8Array} Reduced scalar
 */
export function scReduce32(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  const n = bytesToBigInt(scalar);
  return bigIntToBytes(n % L);
}

/**
 * Reduce a 64-byte scalar mod L (used after multiplication)
 * @param {Uint8Array|string} scalar - 64-byte scalar
 * @returns {Uint8Array} Reduced 32-byte scalar
 */
export function scReduce64(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  const n = bytesToBigInt(scalar);
  return bigIntToBytes(n % L);
}

/**
 * Add two scalars mod L: result = a + b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Sum mod L
 */
export function scAdd(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes((aBig + bBig) % L);
}

/**
 * Subtract two scalars mod L: result = a - b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Difference mod L
 */
export function scSub(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes(((aBig - bBig) % L + L) % L);
}

/**
 * Multiply two scalars mod L: result = a * b mod L
 * @param {Uint8Array|string} a - First scalar
 * @param {Uint8Array|string} b - Second scalar
 * @returns {Uint8Array} Product mod L
 */
export function scMul(a, b) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  return bigIntToBytes((aBig * bBig) % L);
}

/**
 * Multiply-add: result = a*b + c mod L
 * @param {Uint8Array|string} a - First multiplicand
 * @param {Uint8Array|string} b - Second multiplicand
 * @param {Uint8Array|string} c - Addend
 * @returns {Uint8Array} Result mod L
 */
export function scMulAdd(a, b, c) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const cBig = bytesToBigInt(c);
  return bigIntToBytes((aBig * bBig + cBig) % L);
}

/**
 * Multiply-subtract: result = c - a*b mod L
 * @param {Uint8Array|string} a - First multiplicand
 * @param {Uint8Array|string} b - Second multiplicand
 * @param {Uint8Array|string} c - Minuend
 * @returns {Uint8Array} Result mod L
 */
export function scMulSub(a, b, c) {
  const aBig = bytesToBigInt(a);
  const bBig = bytesToBigInt(b);
  const cBig = bytesToBigInt(c);
  return bigIntToBytes(((cBig - aBig * bBig) % L + L) % L);
}

/**
 * Check if scalar is valid (less than L and non-zero for some operations)
 * @param {Uint8Array|string} scalar - Scalar to check
 * @returns {boolean} True if valid
 */
export function scCheck(scalar) {
  const n = bytesToBigInt(scalar);
  return n < L;
}

/**
 * Check if scalar is zero
 * @param {Uint8Array|string} scalar - Scalar to check
 * @returns {boolean} True if zero
 */
export function scIsZero(scalar) {
  if (typeof scalar === 'string') {
    scalar = hexToBytes(scalar);
  }
  for (let i = 0; i < scalar.length; i++) {
    if (scalar[i] !== 0) return false;
  }
  return true;
}

/**
 * Generate a random scalar mod L
 * @returns {Uint8Array} Random 32-byte scalar < L
 */
export function scRandom() {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  return scReduce64(bytes);
}

/**
 * Compute modular inverse: result = a^(-1) mod L
 * Uses extended Euclidean algorithm / Fermat's little theorem
 * @param {Uint8Array|string} a - Scalar to invert
 * @returns {Uint8Array} Inverse mod L
 */
export function scInvert(a) {
  const aBig = bytesToBigInt(a);
  if (aBig === 0n) {
    throw new Error('Cannot invert zero');
  }
  // Using Fermat's little theorem: a^(-1) = a^(L-2) mod L
  const result = modPow(aBig, L - 2n, L);
  return bigIntToBytes(result);
}

/**
 * Modular exponentiation: base^exp mod m
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} m
 * @returns {bigint}
 */
function modPow(base, exp, m) {
  let result = 1n;
  base = base % m;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp >> 1n;
    base = (base * base) % m;
  }
  return result;
}

// =============================================================================
// PEDERSEN COMMITMENTS
// =============================================================================

/**
 * Compute a Pedersen commitment: C = mask*G + amount*H
 * This hides the amount while allowing verification of zero-sum property.
 *
 * @param {bigint|number} amount - Amount to commit to
 * @param {Uint8Array|string} mask - Blinding factor (32-byte scalar)
 * @returns {Uint8Array} 32-byte compressed point (commitment)
 */
export function commit(amount, mask) {
  if (typeof amount === 'number') {
    amount = BigInt(amount);
  }

  // C = mask*G + amount*H
  const maskG = scalarMultBase(mask);    // mask * G

  // When amount is 0, amount*H is the identity point, so C = mask*G
  if (amount === 0n) return maskG;

  const amountBytes = bigIntToBytes(amount);
  const amountH = scalarMultPoint(amountBytes, hexToBytes(H));  // amount * H

  return pointAddCompressed(maskG, amountH);
}

/**
 * Compute a zero commitment: C = amount*H (mask = 0)
 * Used for transaction fees and other public amounts.
 *
 * @param {bigint|number} amount - Amount to commit to
 * @returns {Uint8Array} 32-byte compressed point
 */
export function zeroCommit(amount) {
  if (typeof amount === 'number') {
    amount = BigInt(amount);
  }
  const amountBytes = bigIntToBytes(amount);
  return scalarMultPoint(amountBytes, hexToBytes(H));
}

/**
 * Generate a commitment mask from a shared secret
 * Uses domain-separated hashing: mask = H("commitment_mask" || sharedSecret)
 *
 * @param {Uint8Array|string} sharedSecret - 32-byte shared secret
 * @returns {Uint8Array} 32-byte mask
 */
export function genCommitmentMask(sharedSecret) {
  if (typeof sharedSecret === 'string') {
    sharedSecret = hexToBytes(sharedSecret);
  }

  // Domain separation: "commitment_mask" || sharedSecret
  const prefix = new TextEncoder().encode('commitment_mask');
  const data = new Uint8Array(prefix.length + sharedSecret.length);
  data.set(prefix, 0);
  data.set(sharedSecret, prefix.length);

  // Hash and reduce to scalar
  const hash = keccak256(data);
  return scReduce32(hash);
}

// =============================================================================
// VARINT ENCODING/DECODING
// =============================================================================

/**
 * Encode a value as varint (variable-length integer)
 *
 * @param {number|bigint} value - Value to encode
 * @returns {Uint8Array} Encoded varint
 */
export function encodeVarint(value) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new RangeError(`encodeVarint: not an integer: ${value}`);
    value = BigInt(value);
  }

  const bytes = [];
  while (value >= 0x80n) {
    bytes.push(Number((value & 0x7fn) | 0x80n));
    value >>= 7n;
  }
  bytes.push(Number(value));

  return new Uint8Array(bytes);
}

/**
 * Decode a varint from bytes
 *
 * @param {Uint8Array} bytes - Bytes containing varint
 * @param {number} offset - Starting offset
 * @returns {{value: bigint, bytesRead: number}} Decoded value and bytes consumed
 */
export function decodeVarint(bytes, offset = 0) {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    bytesRead++;

    value |= BigInt(byte & 0x7f) << shift;

    if ((byte & 0x80) === 0) {
      break;
    }

    shift += 7n;

    // Prevent overflow (max 10 bytes for 64-bit)
    if (shift >= 70n) {
      throw new Error('Varint overflow');
    }
  }

  return { value, bytesRead };
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Concatenate multiple byte arrays
 * @param {Array<Uint8Array>} arrays - Arrays to concatenate
 * @returns {Uint8Array} Concatenated result
 */
export function concatBytes(arrays) {
  let totalLen = 0;
  for (const arr of arrays) {
    totalLen += arr.length;
  }

  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }

  return result;
}

// =============================================================================
// TRANSACTION OUTPUT SERIALIZATION
// =============================================================================

/**
 * Serialize a transaction output
 *
 * @param {Object} output - Output object
 * @param {bigint|number} output.amount - Amount (usually 0 for RingCT)
 * @param {Uint8Array} output.target - Output public key (32 bytes)
 * @param {number} [output.viewTag] - Optional view tag (1 byte)
 * @returns {Uint8Array} Serialized output
 */
export function serializeTxOutput(output) {
  const chunks = [];

  // Amount (varint, usually 0 for RingCT)
  chunks.push(encodeVarint(output.amount || 0n));

  if (output.type === TXOUT_TYPE.ToCarrotV1) {
    // CARROT v1 output (HF10+)
    chunks.push(new Uint8Array([TXOUT_TYPE.ToCarrotV1]));
    // key (32 bytes)
    chunks.push(typeof output.target === 'string' ? hexToBytes(output.target) : output.target);
    // asset_type (length-prefixed string)
    const assetBytes = new TextEncoder().encode(output.assetType || 'SAL1');
    chunks.push(encodeVarint(assetBytes.length));
    chunks.push(assetBytes);
    // view_tag (3 bytes)
    const vt = output.carrotViewTag || new Uint8Array(3);
    chunks.push(typeof vt === 'string' ? hexToBytes(vt) : vt);
    // encrypted_janus_anchor (16 bytes)
    const anchor = output.encryptedJanusAnchor || new Uint8Array(16);
    chunks.push(typeof anchor === 'string' ? hexToBytes(anchor) : anchor);
  } else if (output.viewTag !== undefined) {
    // Tagged key output (post-view-tag era)
    chunks.push(new Uint8Array([TXOUT_TYPE.ToTaggedKey]));
    chunks.push(typeof output.target === 'string' ? hexToBytes(output.target) : output.target);
    // asset_type (length-prefixed string)
    const assetBytes = new TextEncoder().encode(output.assetType || 'SAL');
    chunks.push(encodeVarint(assetBytes.length));
    chunks.push(assetBytes);
    // unlock_time (varint)
    chunks.push(encodeVarint(output.unlockTime || 0n));
    // view_tag (1 byte)
    chunks.push(new Uint8Array([output.viewTag & 0xff]));
  } else {
    // Regular key output (txout_to_key)
    chunks.push(new Uint8Array([TXOUT_TYPE.ToKey]));
    chunks.push(typeof output.target === 'string' ? hexToBytes(output.target) : output.target);
    // asset_type (length-prefixed string)
    const assetBytes = new TextEncoder().encode(output.assetType || 'SAL');
    chunks.push(encodeVarint(assetBytes.length));
    chunks.push(assetBytes);
    // unlock_time (varint)
    chunks.push(encodeVarint(output.unlockTime || 0n));
  }

  return concatBytes(chunks);
}

// =============================================================================
// TRANSACTION INPUT SERIALIZATION
// =============================================================================

/**
 * Serialize a transaction input (key input)
 *
 * @param {Object} input - Input object
 * @param {bigint|number} input.amount - Amount
 * @param {Array<bigint|number>} input.keyOffsets - Ring member offsets (relative indices)
 * @param {Uint8Array} input.keyImage - Key image (32 bytes)
 * @returns {Uint8Array} Serialized input
 */
export function serializeTxInput(input) {
  const chunks = [];

  // Input type
  chunks.push(new Uint8Array([TXIN_TYPE.ToKey]));

  // Amount (varint)
  chunks.push(encodeVarint(input.amount || 0n));

  // asset_type (length-prefixed string) — Salvium-specific field
  const assetBytes = new TextEncoder().encode(input.assetType || 'SAL');
  chunks.push(encodeVarint(assetBytes.length));
  chunks.push(assetBytes);

  // Key offsets (varint count + varint values)
  chunks.push(encodeVarint(input.keyOffsets.length));
  for (const offset of input.keyOffsets) {
    chunks.push(encodeVarint(offset));
  }

  // Key image (32 bytes)
  const ki = typeof input.keyImage === 'string' ? hexToBytes(input.keyImage) : input.keyImage;
  chunks.push(ki);

  return concatBytes(chunks);
}

/**
 * Serialize a coinbase (generation) input
 *
 * @param {number|bigint} height - Block height
 * @returns {Uint8Array} Serialized gen input
 */
export function serializeGenInput(height) {
  return concatBytes([
    new Uint8Array([TXIN_TYPE.Gen]),
    encodeVarint(height)
  ]);
}

// =============================================================================
// TRANSACTION EXTRA SERIALIZATION
// =============================================================================

/**
 * Serialize transaction extra field
 *
 * @param {Object} extra - Extra field data
 * @param {Uint8Array} extra.txPubKey - Transaction public key (32 bytes)
 * @param {Uint8Array} [extra.paymentId] - Optional encrypted payment ID (8 bytes)
 * @param {Array<Uint8Array>} [extra.additionalPubKeys] - Additional tx public keys
 * @returns {Uint8Array} Serialized extra field
 */
export function serializeTxExtra(extra) {
  const chunks = [];

  // TX_EXTRA_TAG_PUBKEY = 0x01
  if (extra.txPubKey) {
    const pk = typeof extra.txPubKey === 'string' ? hexToBytes(extra.txPubKey) : extra.txPubKey;
    chunks.push(new Uint8Array([0x01]));
    chunks.push(pk);
  }

  // TX_EXTRA_NONCE = 0x02 with encrypted payment ID
  if (extra.paymentId) {
    const pid = typeof extra.paymentId === 'string' ? hexToBytes(extra.paymentId) : extra.paymentId;
    // 0x02 (nonce tag) + length (9) + 0x01 (encrypted payment ID tag) + 8 bytes
    chunks.push(new Uint8Array([0x02, 9, 0x01]));
    chunks.push(pid);
  }

  // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04
  if (extra.additionalPubKeys && extra.additionalPubKeys.length > 0) {
    chunks.push(new Uint8Array([0x04]));
    chunks.push(encodeVarint(extra.additionalPubKeys.length));
    for (const pk of extra.additionalPubKeys) {
      const pkBytes = typeof pk === 'string' ? hexToBytes(pk) : pk;
      chunks.push(pkBytes);
    }
  }

  return concatBytes(chunks);
}

// =============================================================================
// TRANSACTION PREFIX SERIALIZATION
// =============================================================================

/**
 * Serialize transaction prefix
 *
 * @param {Object} tx - Transaction object
 * @param {number} tx.version - Transaction version (1 or 2)
 * @param {bigint|number} tx.unlockTime - Unlock time
 * @param {Array<Object>} tx.inputs - Transaction inputs
 * @param {Array<Object>} tx.outputs - Transaction outputs
 * @param {Object} tx.extra - Extra field data
 * @returns {Uint8Array} Serialized transaction prefix
 */
export function serializeTxPrefix(tx) {
  const chunks = [];

  // Version
  chunks.push(encodeVarint(tx.version));

  // Unlock time
  chunks.push(encodeVarint(tx.unlockTime || 0n));

  // Inputs
  chunks.push(encodeVarint(tx.inputs.length));
  for (const input of tx.inputs) {
    if (input.type === 'gen') {
      chunks.push(serializeGenInput(input.height));
    } else {
      chunks.push(serializeTxInput(input));
    }
  }

  // Outputs
  chunks.push(encodeVarint(tx.outputs.length));
  for (const output of tx.outputs) {
    chunks.push(serializeTxOutput(output));
  }

  // Extra
  const extraBytes = serializeTxExtra(tx.extra);
  chunks.push(encodeVarint(extraBytes.length));
  chunks.push(extraBytes);

  // Salvium-specific transaction prefix fields
  // txType (default: TRANSFER for backward compatibility)
  const txType = tx.txType ?? TX_TYPE.TRANSFER;
  chunks.push(encodeVarint(txType));

  // Fields for non-UNSET, non-PROTOCOL transaction types
  if (txType !== TX_TYPE.UNSET && txType !== TX_TYPE.PROTOCOL) {
    // amount_burnt
    chunks.push(encodeVarint(tx.amount_burnt ?? 0n));

    if (txType !== TX_TYPE.MINER) {
      // Return address handling depends on tx type and version
      if (txType === TX_TYPE.TRANSFER && tx.version >= 3) {
        // TRANSFER with version >= 3: return_address_list and change_mask
        const returnList = tx.return_address_list || [];
        chunks.push(encodeVarint(returnList.length));
        for (const addr of returnList) {
          chunks.push(typeof addr === 'string' ? hexToBytes(addr) : addr);
        }
        const changeMask = tx.return_address_change_mask || new Uint8Array(0);
        chunks.push(encodeVarint(changeMask.length));
        if (changeMask.length > 0) {
          chunks.push(changeMask);
        }
      } else if (txType === TX_TYPE.STAKE && tx.version >= 4) {
        // STAKE with CARROT (version >= 4): protocol_tx_data
        const ptxData = tx.protocol_tx_data || {};
        chunks.push(encodeVarint(ptxData.version ?? 1));
        chunks.push(typeof ptxData.return_address === 'string'
          ? hexToBytes(ptxData.return_address)
          : (ptxData.return_address || new Uint8Array(32)));
        chunks.push(typeof ptxData.return_pubkey === 'string'
          ? hexToBytes(ptxData.return_pubkey)
          : (ptxData.return_pubkey || new Uint8Array(32)));
        chunks.push(ptxData.return_view_tag || new Uint8Array(3));
        chunks.push(ptxData.return_anchor_enc || new Uint8Array(16));
      } else {
        // Legacy format: return_address + return_pubkey
        chunks.push(typeof tx.return_address === 'string'
          ? hexToBytes(tx.return_address)
          : (tx.return_address || new Uint8Array(32)));
        chunks.push(typeof tx.return_pubkey === 'string'
          ? hexToBytes(tx.return_pubkey)
          : (tx.return_pubkey || new Uint8Array(32)));
      }

      // source_asset_type (length-prefixed string)
      const srcAsset = tx.source_asset_type || 'SAL';
      const srcAssetBytes = new TextEncoder().encode(srcAsset);
      chunks.push(encodeVarint(srcAssetBytes.length));
      chunks.push(srcAssetBytes);

      // destination_asset_type (length-prefixed string)
      const dstAsset = tx.destination_asset_type || 'SAL';
      const dstAssetBytes = new TextEncoder().encode(dstAsset);
      chunks.push(encodeVarint(dstAssetBytes.length));
      chunks.push(dstAssetBytes);

      // amount_slippage_limit
      chunks.push(encodeVarint(tx.amount_slippage_limit ?? 0n));
    }
  }

  return concatBytes(chunks);
}

/**
 * Compute transaction prefix hash
 *
 * @param {Object|Uint8Array} tx - Transaction object or serialized prefix
 * @returns {Uint8Array} 32-byte hash
 */
export function getTxPrefixHash(tx) {
  if (tx instanceof Uint8Array) {
    return keccak256(tx);
  }

  // Adapt vin/vout format to inputs/outputs if needed
  // Include all Salvium-specific fields for correct hash
  const prefixForSerialization = {
    version: tx.version,
    unlockTime: tx.unlockTime,
    inputs: tx.inputs || tx.vin,
    outputs: tx.outputs || tx.vout,
    extra: tx.extra,
    // Salvium-specific fields
    txType: tx.txType,
    amount_burnt: tx.amount_burnt,
    return_address: tx.return_address,
    return_address_list: tx.return_address_list,
    return_address_change_mask: tx.return_address_change_mask,
    return_pubkey: tx.return_pubkey,
    protocol_tx_data: tx.protocol_tx_data,
    source_asset_type: tx.source_asset_type,
    destination_asset_type: tx.destination_asset_type,
    amount_slippage_limit: tx.amount_slippage_limit
  };

  return keccak256(serializeTxPrefix(prefixForSerialization));
}

// =============================================================================
// RINGCT SERIALIZATION
// =============================================================================

/**
 * Serialize a CLSAG signature
 *
 * @param {Object} sig - CLSAG signature
 * @param {Array<string>} sig.s - Response scalars (32 bytes each, as hex)
 * @param {string} sig.c1 - Initial challenge (32 bytes, as hex)
 * @param {string} sig.D - Commitment key image (32 bytes, as hex)
 * @returns {Uint8Array} Serialized CLSAG
 */
export function serializeCLSAG(sig) {
  const chunks = [];

  // s values (no length prefix, determined by ring size)
  for (const s of sig.s) {
    chunks.push(typeof s === 'string' ? hexToBytes(s) : s);
  }

  // c1
  chunks.push(typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1);

  // D (commitment key image)
  // Note: I (key image) is NOT serialized as it can be reconstructed
  chunks.push(typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D);

  return concatBytes(chunks);
}

/**
 * Serialize a TCLSAG signature (used for SalviumOne / HF10+)
 *
 * TCLSAG has sx[], sy[], c1, D (vs CLSAG which has s[], c1, D)
 * Reference: Salvium rctTypes.h lines 560-600
 *
 * @param {Object} sig - TCLSAG signature { sx: Array, sy: Array, c1, D }
 * @returns {Uint8Array} Serialized TCLSAG
 */
export function serializeTCLSAG(sig) {
  const chunks = [];

  // sx values (no length prefix, determined by ring size)
  for (const s of sig.sx) {
    chunks.push(typeof s === 'string' ? hexToBytes(s) : s);
  }

  // sy values (same count as sx)
  for (const s of sig.sy) {
    chunks.push(typeof s === 'string' ? hexToBytes(s) : s);
  }

  // c1
  chunks.push(typeof sig.c1 === 'string' ? hexToBytes(sig.c1) : sig.c1);

  // D (commitment key image)
  chunks.push(typeof sig.D === 'string' ? hexToBytes(sig.D) : sig.D);

  return concatBytes(chunks);
}

/**
 * Serialize a zk_proof (Schnorr proof: R + z1 + z2 = 96 bytes)
 *
 * @param {Object} proof - { R: Uint8Array, z1: Uint8Array, z2: Uint8Array }
 * @returns {Uint8Array} 96-byte serialized proof
 */
export function serializeZkProof(proof) {
  const chunks = [];
  chunks.push(typeof proof.R === 'string' ? hexToBytes(proof.R) : proof.R);
  chunks.push(typeof proof.z1 === 'string' ? hexToBytes(proof.z1) : proof.z1);
  chunks.push(typeof proof.z2 === 'string' ? hexToBytes(proof.z2) : proof.z2);
  return concatBytes(chunks);
}

/**
 * Serialize salvium_data_t for SalviumZero/SalviumOne RCT types.
 *
 * Reference: Salvium rctTypes.h lines 400-412
 *
 * @param {Object} data - salvium_data object
 * @param {number} data.salvium_data_type - 0=SalviumZero, 1=SalviumZeroAudit, 2=SalviumOne
 * @param {Object} data.pr_proof - { R, z1, z2 }
 * @param {Object} data.sa_proof - { R, z1, z2 }
 * @returns {Uint8Array} Serialized salvium_data
 */
export function serializeSalviumData(data) {
  const chunks = [];

  // salvium_data_type (varint)
  chunks.push(encodeVarint(data.salvium_data_type || 0));

  // pr_proof (96 bytes)
  chunks.push(serializeZkProof(data.pr_proof || { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }));

  // sa_proof (96 bytes)
  chunks.push(serializeZkProof(data.sa_proof || { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }));

  // SalviumZeroAudit-specific fields
  if (data.salvium_data_type === 1) {
    // cz_proof (96 bytes)
    chunks.push(serializeZkProof(data.cz_proof || { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }));

    // input_verification_data (vector)
    const ivd = data.input_verification_data || [];
    chunks.push(encodeVarint(ivd.length));
    for (const item of ivd) {
      chunks.push(typeof item === 'string' ? hexToBytes(item) : item);
    }

    // spend_pubkey (32 bytes)
    const spk = data.spend_pubkey || new Uint8Array(32);
    chunks.push(typeof spk === 'string' ? hexToBytes(spk) : spk);

    // enc_view_privkey_str (length-prefixed string)
    const evpStr = data.enc_view_privkey_str || '';
    const evpBytes = new TextEncoder().encode(evpStr);
    chunks.push(encodeVarint(evpBytes.length));
    if (evpBytes.length > 0) chunks.push(evpBytes);
  }

  return concatBytes(chunks);
}

/**
 * Serialize RingCT base (type + fee)
 *
 * @param {Object} rct - RingCT data
 * @param {number} rct.type - RCT type
 * @param {bigint|number} rct.fee - Transaction fee
 * @returns {Uint8Array} Serialized RCT base
 */
export function serializeRctBase(rct) {
  const chunks = [];

  // Type (1 byte)
  chunks.push(new Uint8Array([rct.type]));

  // C++: if (type == RCTTypeNull) return ar.good();
  // Null type only has the type byte — no fee, no data
  if (rct.type === RCT_TYPE.Null) {
    return concatBytes(chunks);
  }

  // Fee (varint)
  chunks.push(encodeVarint(rct.fee || 0n));

  // ecdhInfo (8 bytes per output — compact format for BP+ types)
  if (rct.ecdhInfo) {
    chunks.push(serializeEcdhInfo(rct.ecdhInfo));
  }

  // outPk (32 bytes per output)
  if (rct.outPk) {
    chunks.push(serializeOutPk(rct.outPk));
  }

  // p_r (32 bytes) — always present in Salvium
  const pR = rct.p_r
    ? (typeof rct.p_r === 'string' ? hexToBytes(rct.p_r) : rct.p_r)
    : new Uint8Array(32);
  chunks.push(pR);

  // salvium_data — depends on RCT type
  const rctType = rct.type;
  if (rctType === 8 || rctType === 9) {
    chunks.push(serializeSalviumData(rct.salvium_data || {
      salvium_data_type: 0,
      pr_proof: { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) },
      sa_proof: { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }
    }));
  } else if (rctType === 7) {
    const sd = rct.salvium_data || {};
    chunks.push(serializeZkProof(sd.pr_proof || { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }));
    chunks.push(serializeZkProof(sd.sa_proof || { R: new Uint8Array(32), z1: new Uint8Array(32), z2: new Uint8Array(32) }));
  }

  return concatBytes(chunks);
}

/**
 * Serialize encrypted amounts (ecdhInfo)
 *
 * @param {Array<Uint8Array>} encryptedAmounts - 8-byte encrypted amounts
 * @returns {Uint8Array} Serialized encrypted amounts
 */
export function serializeEcdhInfo(encryptedAmounts) {
  const chunks = [];
  for (const ea of encryptedAmounts) {
    const bytes = typeof ea === 'string' ? hexToBytes(ea) : ea;
    // V2+ compact format: just 8 bytes
    chunks.push(bytes.slice(0, 8));
  }
  return concatBytes(chunks);
}

/**
 * Serialize output commitments
 *
 * @param {Array<Uint8Array>} commitments - 32-byte Pedersen commitments
 * @returns {Uint8Array} Serialized commitments
 */
export function serializeOutPk(commitments) {
  const chunks = [];
  for (const c of commitments) {
    chunks.push(typeof c === 'string' ? hexToBytes(c) : c);
  }
  return concatBytes(chunks);
}

// =============================================================================
// COMPLETE TRANSACTION SERIALIZATION
// =============================================================================

/**
 * Serialize a complete transaction to bytes
 *
 * @param {Object} tx - Transaction object
 * @returns {Uint8Array} Serialized transaction bytes
 */
export function serializeTransaction(tx) {
  // Adapt prefix structure for serializeTxPrefix
  // (buildTransaction uses vin/vout, serializeTxPrefix expects inputs/outputs)
  const prefixForSerialization = {
    ...tx.prefix,
    inputs: tx.prefix.vin,
    outputs: tx.prefix.vout
  };

  const chunks = [];

  // 1. TX prefix
  chunks.push(serializeTxPrefix(prefixForSerialization));

  // 2. RCT base: type + fee + ecdhInfo + outPk + p_r + salvium_data
  //    (matches Salvium serialize_rctsig_base)
  chunks.push(serializeRctBase(tx.rct));

  // 3. RCT prunable: BP+ proofs, signatures, pseudoOuts
  //    (matches Salvium serialize_rctsig_prunable)

  // BP+ proofs (varint count + proof data)
  if (tx.rct.bulletproofPlus && tx.rct.bulletproofPlus.serialized) {
    chunks.push(encodeVarint(1)); // number of BP+ proofs (always 1 aggregated)
    chunks.push(tx.rct.bulletproofPlus.serialized);
  } else {
    chunks.push(encodeVarint(0));
  }

  // Ring signatures: TCLSAG for SalviumOne (9), CLSAG for all others
  if (tx.rct.type === 9 && tx.rct.TCLSAGs) {
    for (const sig of tx.rct.TCLSAGs) {
      chunks.push(serializeTCLSAG(sig));
    }
  } else if (tx.rct.CLSAGs) {
    for (const sig of tx.rct.CLSAGs) {
      chunks.push(serializeCLSAG(sig));
    }
  }

  // pseudoOuts (in prunable section for BP+ types)
  if (tx.rct.pseudoOuts) {
    for (const po of tx.rct.pseudoOuts) {
      chunks.push(typeof po === 'string' ? hexToBytes(po) : po);
    }
  }

  return concatBytes(chunks);
}
