/**
 * Block Serialization Module
 *
 * Handles serialization of blocks and block components:
 * - Block headers
 * - Pricing records (oracle data)
 * - Block hashing
 * - Merkle tree computation
 *
 * @module block/serialization
 */

import { keccak256, cnFastHash } from '../keccak.js';
import { encodeVarint, serializeTxPrefix, serializeRctBase } from '../transaction/serialization.js';
import { HF_VERSION_ENABLE_ORACLE } from '../transaction/constants.js';

// Re-export HF_VERSION_ENABLE_ORACLE for convenience
export { HF_VERSION_ENABLE_ORACLE };

// =============================================================================
// PRICING RECORD SERIALIZATION
// =============================================================================

/**
 * Serialize a pricing record supply_data structure
 * @param {Object} supply - { sal: bigint, vsd: bigint }
 * @returns {Uint8Array} Serialized supply data
 */
export function serializeSupplyData(supply) {
  const parts = [];
  parts.push(encodeVarint(BigInt(supply.sal || 0)));
  parts.push(encodeVarint(BigInt(supply.vsd || 0)));

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a pricing record asset_data structure
 * @param {Object} asset - { asset_type: string, spot_price: bigint, ma_price: bigint }
 * @returns {Uint8Array} Serialized asset data
 */
export function serializeAssetData(asset) {
  const parts = [];

  // asset_type as string (length-prefixed)
  const assetType = asset.asset_type || '';
  const assetTypeBytes = new TextEncoder().encode(assetType);
  parts.push(encodeVarint(BigInt(assetTypeBytes.length)));
  parts.push(assetTypeBytes);

  // spot_price and ma_price as varints
  parts.push(encodeVarint(BigInt(asset.spot_price || 0)));
  parts.push(encodeVarint(BigInt(asset.ma_price || 0)));

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Serialize a pricing_record structure
 * @param {Object} pricingRecord - Pricing record object
 * @returns {Uint8Array} Serialized pricing record
 */
export function serializePricingRecord(pricingRecord) {
  const parts = [];

  // pr_version (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.pr_version || 0)));

  // height (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.height || 0)));

  // supply (supply_data)
  parts.push(serializeSupplyData(pricingRecord.supply || { sal: 0, vsd: 0 }));

  // assets (vector of asset_data)
  const assets = pricingRecord.assets || [];
  parts.push(encodeVarint(BigInt(assets.length)));
  for (const asset of assets) {
    parts.push(serializeAssetData(asset));
  }

  // timestamp (varint)
  parts.push(encodeVarint(BigInt(pricingRecord.timestamp || 0)));

  // signature (vector of uint8)
  const signature = pricingRecord.signature || new Uint8Array(0);
  parts.push(encodeVarint(BigInt(signature.length)));
  parts.push(signature);

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// =============================================================================
// BLOCK HEADER SERIALIZATION
// =============================================================================

/**
 * Serialize a block header
 * @param {Object} header - Block header object
 * @returns {Uint8Array} Serialized block header
 */
export function serializeBlockHeader(header) {
  const parts = [];

  // major_version (varint)
  const majorVersion = header.major_version || 0;
  parts.push(encodeVarint(BigInt(majorVersion)));

  // minor_version (varint)
  parts.push(encodeVarint(BigInt(header.minor_version || 0)));

  // timestamp (varint)
  parts.push(encodeVarint(BigInt(header.timestamp || 0)));

  // prev_id (32-byte hash)
  const prevId = header.prev_id || new Uint8Array(32);
  if (prevId.length !== 32) {
    throw new Error('prev_id must be 32 bytes');
  }
  parts.push(prevId);

  // nonce (4 bytes, little-endian)
  const nonce = header.nonce || 0;
  const nonceBytes = new Uint8Array(4);
  nonceBytes[0] = nonce & 0xff;
  nonceBytes[1] = (nonce >>> 8) & 0xff;
  nonceBytes[2] = (nonce >>> 16) & 0xff;
  nonceBytes[3] = (nonce >>> 24) & 0xff;
  parts.push(nonceBytes);

  // pricing_record (only if major_version >= HF_VERSION_ENABLE_ORACLE)
  if (majorVersion >= HF_VERSION_ENABLE_ORACLE && header.pricing_record) {
    parts.push(serializePricingRecord(header.pricing_record));
  }

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// =============================================================================
// COMPLETE BLOCK SERIALIZATION
// =============================================================================

/**
 * Serialize a complete block
 * @param {Object} block - Block object containing header and transactions
 * @returns {Uint8Array} Serialized block
 */
export function serializeBlock(block) {
  const parts = [];

  // Block header fields
  parts.push(serializeBlockHeader(block));

  // miner_tx (full transaction - use existing serialization)
  // We need to serialize the full transaction including RingCT
  if (block.miner_tx) {
    // For coinbase transactions, we serialize prefix + RCT
    const minerTxPrefix = serializeTxPrefix(block.miner_tx);
    parts.push(minerTxPrefix);

    // RCT signature for miner_tx (usually RCTTypeNull for coinbase)
    if (block.miner_tx.rct_signatures) {
      parts.push(serializeRctBase(block.miner_tx.rct_signatures, block.miner_tx.vout?.length || 0));
    }
  }

  // protocol_tx (Salvium-specific)
  if (block.protocol_tx) {
    const protocolTxPrefix = serializeTxPrefix(block.protocol_tx);
    parts.push(protocolTxPrefix);

    if (block.protocol_tx.rct_signatures) {
      parts.push(serializeRctBase(block.protocol_tx.rct_signatures, block.protocol_tx.vout?.length || 0));
    }
  }

  // tx_hashes (vector of 32-byte hashes)
  const txHashes = block.tx_hashes || [];
  parts.push(encodeVarint(BigInt(txHashes.length)));
  for (const hash of txHashes) {
    if (hash.length !== 32) {
      throw new Error('tx_hash must be 32 bytes');
    }
    parts.push(hash);
  }

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

// =============================================================================
// BLOCK HASHING
// =============================================================================

/**
 * Compute merkle root of transaction hashes
 * @param {Array<Uint8Array>} hashes - Array of 32-byte hashes
 * @returns {Uint8Array} 32-byte merkle root
 */
export function computeMerkleRoot(hashes) {
  if (hashes.length === 0) {
    return new Uint8Array(32); // Empty merkle root
  }

  if (hashes.length === 1) {
    return hashes[0];
  }

  // Build merkle tree
  let layer = [...hashes];

  while (layer.length > 1) {
    const nextLayer = [];

    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        // Hash pair
        const combined = new Uint8Array(64);
        combined.set(layer[i], 0);
        combined.set(layer[i + 1], 32);
        nextLayer.push(cnFastHash(combined));
      } else {
        // Odd one out - just pass through
        nextLayer.push(layer[i]);
      }
    }

    layer = nextLayer;
  }

  return layer[0];
}

/**
 * Compute the block hash (hash of serialized block header)
 * @param {Object} block - Block object
 * @returns {Uint8Array} 32-byte block hash
 */
export function getBlockHash(block) {
  // Block hash is computed from the "hashing blob"
  // which includes: header + miner_tx_hash + tx_merkle_root
  const headerBytes = serializeBlockHeader(block);

  // Compute miner_tx hash if present
  let minerTxHash = new Uint8Array(32);
  if (block.miner_tx) {
    const minerTxPrefix = serializeTxPrefix(block.miner_tx);
    minerTxHash = cnFastHash(minerTxPrefix);
  }

  // Compute merkle root of tx_hashes (including protocol_tx if present)
  let allHashes = [];

  // Add protocol_tx hash if present
  if (block.protocol_tx) {
    const protocolTxPrefix = serializeTxPrefix(block.protocol_tx);
    allHashes.push(cnFastHash(protocolTxPrefix));
  }

  // Add all tx_hashes
  if (block.tx_hashes) {
    allHashes = allHashes.concat(block.tx_hashes);
  }

  // Compute merkle root
  const merkleRoot = computeMerkleRoot(allHashes);

  // Combine: header_hash, miner_tx_hash, merkle_root
  const combined = new Uint8Array(headerBytes.length + 32 + 32);
  combined.set(headerBytes, 0);
  combined.set(minerTxHash, headerBytes.length);
  combined.set(merkleRoot, headerBytes.length + 32);

  return cnFastHash(combined);
}
