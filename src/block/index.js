/**
 * Block Module Index
 *
 * Re-exports all block-related functionality from submodules.
 *
 * @module block
 */

// Block Serialization
export {
  HF_VERSION_ENABLE_ORACLE,
  serializeSupplyData,
  serializeAssetData,
  serializePricingRecord,
  serializeBlockHeader,
  serializeBlock,
  computeMerkleRoot,
  getBlockHash
} from './serialization.js';
