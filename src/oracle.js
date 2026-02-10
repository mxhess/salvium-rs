/**
 * Oracle/Pricing Implementation for Salvium
 *
 * Faithful JavaScript port of Salvium's oracle pricing system.
 * Handles pricing records, signature verification, and conversion rates.
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h
 *            ~/github/salvium/src/oracle/pricing_record.cpp
 *            ~/github/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp
 *
 * @module oracle
 */

import { verifySignature } from './crypto/provider.js';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * COIN constant - atomic units per SAL (10^8)
 * Same as Monero: 1 SAL = 100,000,000 atomic units
 */
export const COIN = 100000000n;

/**
 * Pricing record validity window in blocks
 * A pricing record is valid for this many blocks after its height
 */
export const PRICING_RECORD_VALID_BLOCKS = 10;

/**
 * Maximum time difference (seconds) between pricing record and block timestamp
 * Record timestamp must be <= block_timestamp + this value
 */
export const PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK = 120;

/**
 * Conversion rate rounding - rates are rounded down to nearest 10000
 */
export const CONVERSION_RATE_ROUNDING = 10000n;

/**
 * Valid asset types in Salvium
 */
export const ASSET_TYPES = ['SAL', 'SAL1', 'BURN'];

/**
 * Hard fork version when oracle is enabled
 * Currently set to 255 (not yet enabled)
 */
export const HF_VERSION_ENABLE_ORACLE = 255;
export const HF_VERSION_SLIPPAGE_YIELD = 255;

/**
 * Oracle server URLs (mainnet)
 */
export const ORACLE_URLS = [
  'https://oracle.salvium.io:8443',
  'https://oracle.salvium.io:8443',
  'https://oracle.salvium.io:8443'
];

/**
 * Oracle public key for mainnet (DSA format)
 * Used to verify pricing record signatures
 *
 * Reference: ~/github/salvium/src/cryptonote_config.h
 */
export const ORACLE_PUBLIC_KEY_MAINNET = `-----BEGIN PUBLIC KEY-----
MIIDRDCCAjYGByqGSM44BAEwggIpAoIBAQCZP7IJ5PcNvGbWiEqAioKF9wViVxEN
ZBDHvhr8IR6KoSYUXMU154DC6NDiSr6FtPBWuw9LcXlfWdG0l3hd6zObg0GpEQig
jEeOEeBm45ug9lMBSZiaiCHeU8ats1YIQBYDO8m7iAj9Q9/N1nJHDpypsVu5WGLm
+xSmcNULTbqwJ4Sr49TD++sv2MZEJeYRwmmxlqeFFtZlxguwJ90Y5U7aSi4w4vaU
pu/Ce6EWi8pVhUlM5xBBk3tc+Z6FMMgKFN/kHyu3SbxFaRQppbsTo0N3yDAr3sN3
4JmXpRmDidd3czfKlFko11YwK9lohjrgBnStuFRBxDACx4NRfvRfwPqnAh0AhKyn
pbe2No+7lLGSWuQvIEz+2o6coQ3ZWPbxqQKCAQEAkErfS61wvKxbMwPuuqhCpZG/
uQ+WYHwRwyxpU7ImKiH6ubqModIvZoHrRD8MIJhbRmBlA58SSnBWrEcAUIaaDM6Z
xX/VyOFy2mJH3TJJa83oZe275w1JMVrVq1ZybXSYF595zAHNiJcYsskqTbZP8S30
i3Bq//HMUaRhmB60BLmPpmgF3FVsRkCyEL/yH9cUQWdUcuxIG3C7EzgxGUCaR42J
cu+NN8z6W/m/joEe6QkFT3tLh1yXIFBK1MamWC0EZ6YCMcozZfGQ15P3rMrGptKN
+YQRNusTDSqBky+f40dLiYcT28ePQWNPLdsZTqoGWGawqCyWWCh5eWJZSqJPfQOC
AQYAAoIBAQCE+8kHJmagnDPQWiuHziNha5yia7viwasxcsKhYGx+Z3wVbMrDPwLo
CUgljEEsOKXLZsg/EmfVQu9nYoTcMa0hNq0/0bEV9oZ0t4O8gLp2Y4URLngR9zxE
WaVgFLlNtndHUQA2kquP3XLkv/TZVQaqne6tO6p4gLC4ky0YH0vZhWXMOH/4Xfgf
FZHC7SBC3oYsK9UKX3tJoibcL9L18GOe27pIw70x0280IB/C+TBnAXjslNgJe5ZU
rSdr1h2nXji0rXL9DoypVC40QGIzzjCGMsSBnSYgVuITeqX8/o/w5LBK8Dl5wXFt
F9dg9A0deyw/3CA3gwB32zkfi4MEH+il
-----END PUBLIC KEY-----`;

/**
 * Oracle public key for testnet/stagenet (ECDSA format)
 */
export const ORACLE_PUBLIC_KEY_TESTNET = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5YBxWx1AZCA9jTUk8Pr2uZ9jpfRt
KWv3Vo1/Gny+1vfaxsXhBQiG1KlHkafNGarzoL0WHW4ocqaaqF5iv8i35A==
-----END PUBLIC KEY-----`;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * Asset data structure for individual asset pricing
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h (struct asset_data)
 *
 * @typedef {Object} AssetData
 * @property {string} assetType - Asset identifier ('SAL', 'SAL1', 'BURN')
 * @property {bigint} spotPrice - Current spot price (COIN units)
 * @property {bigint} maPrice - Moving average price (COIN units)
 */

/**
 * Supply data structure for circulating supply tracking
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h (struct supply_data)
 *
 * @typedef {Object} SupplyData
 * @property {bigint} sal - SAL circulating supply (atomic units)
 * @property {bigint} vsd - VSD circulating supply (atomic units)
 */

/**
 * Pricing record structure
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h (struct pricing_record)
 *
 * @typedef {Object} PricingRecord
 * @property {number} prVersion - Pricing record version
 * @property {number} height - Block height when record was generated
 * @property {SupplyData} supply - Current supply of SAL and VSD
 * @property {AssetData[]} assets - Array of asset prices
 * @property {number} timestamp - Record timestamp (Unix seconds)
 * @property {Uint8Array} signature - ECDSA/DSA signature (binary)
 */

/**
 * Create an empty pricing record
 *
 * @returns {PricingRecord} Empty pricing record
 */
export function createEmptyPricingRecord() {
  return {
    prVersion: 0,
    height: 0,
    supply: {
      sal: 0n,
      vsd: 0n
    },
    assets: [],
    timestamp: 0,
    signature: new Uint8Array(0)
  };
}

/**
 * Check if a pricing record is empty
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.cpp (empty() method)
 *
 * @param {PricingRecord} pr - Pricing record to check
 * @returns {boolean} True if empty
 */
export function isPricingRecordEmpty(pr) {
  return (
    pr.prVersion === 0 &&
    pr.height === 0 &&
    pr.supply.sal === 0n &&
    pr.supply.vsd === 0n &&
    pr.assets.length === 0 &&
    pr.timestamp === 0 &&
    pr.signature.length === 0
  );
}

/**
 * Get price for a specific asset from pricing record
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.h (operator[] overload)
 *
 * @param {PricingRecord} pr - Pricing record
 * @param {string} assetType - Asset type to look up
 * @returns {bigint} Spot price for the asset (0 if not found)
 */
export function getAssetPrice(pr, assetType) {
  const asset = pr.assets.find(a => a.assetType === assetType);
  return asset ? asset.spotPrice : 0n;
}

/**
 * Get moving average price for a specific asset
 *
 * @param {PricingRecord} pr - Pricing record
 * @param {string} assetType - Asset type to look up
 * @returns {bigint} Moving average price for the asset (0 if not found)
 */
export function getAssetMaPrice(pr, assetType) {
  const asset = pr.assets.find(a => a.assetType === assetType);
  return asset ? asset.maPrice : 0n;
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

/**
 * Convert PEM-encoded public key to DER bytes.
 * Strips the -----BEGIN/END PUBLIC KEY----- headers and base64-decodes.
 *
 * @param {string} pem - PEM-encoded public key
 * @returns {Uint8Array} DER-encoded SPKI public key
 */
function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s+/g, '');
  return _base64Decode(b64);
}

/** Decode base64 string to Uint8Array (works on QuickJS, browsers, Node.js) */
function _base64Decode(b64) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  // Manual base64 decoder for QuickJS and other minimal runtimes
  const lookup = new Uint8Array(128);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < chars.length; i++) lookup[chars.charCodeAt(i)] = i;
  const len = b64.length;
  let pad = 0;
  if (b64[len - 1] === '=') pad++;
  if (b64[len - 2] === '=') pad++;
  const outLen = (len * 3 / 4) - pad;
  const bytes = new Uint8Array(outLen);
  let j = 0;
  for (let i = 0; i < len; i += 4) {
    const a = lookup[b64.charCodeAt(i)];
    const b = lookup[b64.charCodeAt(i + 1)];
    const c = lookup[b64.charCodeAt(i + 2)];
    const d = lookup[b64.charCodeAt(i + 3)];
    bytes[j++] = (a << 2) | (b >> 4);
    if (j < outLen) bytes[j++] = ((b & 15) << 4) | (c >> 2);
    if (j < outLen) bytes[j++] = ((c & 3) << 6) | d;
  }
  return bytes;
}

/**
 * Build the JSON message that was signed
 *
 * The signature covers a compact JSON (no whitespace) with specific field ordering.
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.cpp (verifySignature)
 *
 * @param {PricingRecord} pr - Pricing record
 * @returns {string} Compact JSON message
 */
export function buildSignatureMessage(pr) {
  // Build assets array
  const assetsJson = pr.assets.map(a => ({
    asset_type: a.assetType,
    spot_price: Number(a.spotPrice),
    ma_price: Number(a.maPrice)
  }));

  // Build the message object matching C++ format
  const message = {
    pr_version: pr.prVersion,
    height: pr.height,
    supply: {
      SAL: Number(pr.supply.sal),
      VSD: Number(pr.supply.vsd)
    },
    assets: assetsJson,
    timestamp: pr.timestamp
  };

  // Return compact JSON (no whitespace)
  return JSON.stringify(message);
}

/**
 * Verify pricing record signature
 *
 * Uses the crypto provider's verifySignature which dispatches to the active
 * backend (Rust FFI, WASM, WebCrypto, or Node.js crypto). No direct
 * dependency on Node.js crypto module.
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.cpp (verifySignature)
 *
 * @param {PricingRecord} pr - Pricing record to verify
 * @param {string} publicKeyPem - Oracle public key in PEM format
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifyPricingRecordSignature(pr, publicKeyPem) {
  if (!pr.signature || pr.signature.length === 0) {
    return false;
  }

  try {
    // Build the message that was signed and encode to UTF-8 bytes
    const message = buildSignatureMessage(pr);
    const messageBytes = new TextEncoder().encode(message);

    // Convert PEM public key to DER bytes for the crypto provider
    const pubkeyDer = pemToDer(publicKeyPem);

    // Verify via crypto provider (backend handles SHA-256 hashing internally)
    return await verifySignature(messageBytes, pr.signature, pubkeyDer);
  } catch (_e) {
    // Signature verification failed
    return false;
  }
}

/**
 * Get the appropriate oracle public key for a network
 *
 * @param {'mainnet'|'testnet'|'stagenet'} network - Network type
 * @returns {string} Oracle public key in PEM format
 */
export function getOraclePublicKey(network = 'mainnet') {
  if (network === 'mainnet') {
    return ORACLE_PUBLIC_KEY_MAINNET;
  }
  return ORACLE_PUBLIC_KEY_TESTNET;
}

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * Validate a pricing record
 *
 * Reference: ~/github/salvium/src/oracle/pricing_record.cpp (valid() method)
 *
 * @param {PricingRecord} pr - Pricing record to validate
 * @param {Object} options - Validation options
 * @param {'mainnet'|'testnet'|'stagenet'} options.network - Network type
 * @param {number} options.hfVersion - Current hard fork version
 * @param {number} options.blockTimestamp - Current block timestamp (Unix seconds)
 * @param {number} options.lastBlockTimestamp - Previous block timestamp
 * @returns {{valid: boolean, error?: string}} Validation result
 */
export async function validatePricingRecord(pr, options = {}) {
  const {
    network = 'mainnet',
    hfVersion = 0,
    blockTimestamp = Math.floor(Date.now() / 1000),
    lastBlockTimestamp = 0
  } = options;

  // Rule 1: Before HF_VERSION_SLIPPAGE_YIELD, pricing records must be empty
  if (hfVersion < HF_VERSION_SLIPPAGE_YIELD) {
    if (!isPricingRecordEmpty(pr)) {
      return { valid: false, error: 'Pricing records not allowed before oracle HF' };
    }
  }

  // Rule 2: Empty pricing records are always valid
  if (isPricingRecordEmpty(pr)) {
    return { valid: true };
  }

  // Rule 3: Signature must be valid
  const publicKey = getOraclePublicKey(network);
  if (!await verifyPricingRecordSignature(pr, publicKey)) {
    return { valid: false, error: 'Invalid pricing record signature' };
  }

  // Rule 4: Record timestamp must not be too far in future
  // Must be: record_timestamp <= block_timestamp + 120 seconds
  if (pr.timestamp > blockTimestamp + PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK) {
    return { valid: false, error: 'Pricing record timestamp too far in future' };
  }

  // Rule 5: Record timestamp must be newer than previous block
  // Must be: record_timestamp > previous_block_timestamp
  if (lastBlockTimestamp > 0 && pr.timestamp <= lastBlockTimestamp) {
    return { valid: false, error: 'Pricing record timestamp not newer than previous block' };
  }

  return { valid: true };
}

// ============================================================================
// CONVERSION RATE CALCULATION
// ============================================================================

/**
 * Get conversion rate between two assets
 *
 * Reference: ~/github/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp (get_conversion_rate)
 *
 * @param {PricingRecord} pr - Pricing record with current prices
 * @param {string} fromAsset - Source asset type ('SAL' or 'VSD')
 * @param {string} toAsset - Destination asset type ('SAL' or 'VSD')
 * @returns {{success: boolean, rate?: bigint, error?: string}} Conversion rate result
 */
export function getConversionRate(pr, fromAsset, toAsset) {
  // Rule 1: Cannot convert to BURN
  if (toAsset === 'BURN') {
    return { success: false, error: 'Cannot convert to BURN' };
  }

  // Rule 2: Same asset = 1:1 conversion
  if (fromAsset === toAsset) {
    return { success: true, rate: COIN };
  }

  // Rule 3: Only SAL<->VSD conversions allowed
  if ((fromAsset === 'SAL' && toAsset !== 'VSD') ||
      (fromAsset === 'VSD' && toAsset !== 'SAL')) {
    return { success: false, error: `Invalid conversion pair: ${fromAsset} -> ${toAsset}` };
  }

  // Get prices
  const fromPrice = getAssetPrice(pr, fromAsset);
  const toPrice = getAssetPrice(pr, toAsset);

  if (fromPrice === 0n || toPrice === 0n) {
    return { success: false, error: 'Missing price data for conversion' };
  }

  // Calculate rate: (fromPrice * COIN) / toPrice
  // Using BigInt for precision (equivalent to C++ uint128_t)
  let rate = (fromPrice * COIN) / toPrice;

  // Round down to nearest 10000
  rate = rate - (rate % CONVERSION_RATE_ROUNDING);

  return { success: true, rate };
}

/**
 * Calculate converted amount given a conversion rate
 *
 * Reference: ~/github/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp (get_converted_amount)
 *
 * @param {bigint} conversionRate - Rate from getConversionRate()
 * @param {bigint} sourceAmount - Amount in source asset (atomic units)
 * @returns {{success: boolean, amount?: bigint, error?: string}} Converted amount result
 */
export function getConvertedAmount(conversionRate, sourceAmount) {
  if (!conversionRate || conversionRate === 0n) {
    return { success: false, error: 'Invalid conversion rate' };
  }
  if (!sourceAmount || sourceAmount === 0n) {
    return { success: false, error: 'Invalid source amount' };
  }

  // Calculate: dest = (source * rate) / COIN
  const destAmount = (sourceAmount * conversionRate) / COIN;

  return { success: true, amount: destAmount };
}

/**
 * Calculate slippage amount for a conversion
 *
 * Slippage is fixed at 1/32 (3.125%) of the converted amount.
 *
 * Reference: ~/github/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp (calculate_conversion)
 *
 * @param {bigint} amount - Amount being converted
 * @returns {bigint} Slippage amount
 */
export function calculateSlippage(amount) {
  // Slippage = amount >> 5 = amount / 32 = 3.125%
  return amount >> 5n;
}

/**
 * Perform a full conversion calculation with slippage
 *
 * Reference: ~/github/salvium/src/cryptonote_core/cryptonote_tx_utils.cpp (calculate_conversion)
 *
 * @param {PricingRecord} pr - Pricing record with current prices
 * @param {string} sourceAsset - Source asset type
 * @param {string} destAsset - Destination asset type
 * @param {bigint} amountBurnt - Amount being converted (burnt from source)
 * @param {bigint} slippageLimit - Maximum acceptable slippage
 * @returns {{success: boolean, amountMinted?: bigint, actualSlippage?: bigint, error?: string}}
 */
export function calculateConversion(pr, sourceAsset, destAsset, amountBurnt, slippageLimit) {
  // Same asset = no conversion needed
  if (sourceAsset === destAsset) {
    return { success: false, error: 'Cannot calculate slippage when source and dest assets are identical' };
  }

  if (!sourceAsset) {
    return { success: false, error: 'Source asset not provided' };
  }

  if (!destAsset) {
    return { success: false, error: 'Destination asset not provided' };
  }

  // Get conversion rate
  const rateResult = getConversionRate(pr, sourceAsset, destAsset);
  if (!rateResult.success) {
    return { success: false, error: rateResult.error };
  }

  // Calculate slippage (1/32 = 3.125%)
  const actualSlippage = calculateSlippage(amountBurnt);

  // Check if slippage exceeds user's limit
  if (actualSlippage > slippageLimit) {
    // Slippage too high - conversion fails, refund case
    return {
      success: true,
      amountMinted: 0n,
      actualSlippage,
      refund: true,
      error: 'Slippage limit exceeded - refund triggered'
    };
  }

  // Calculate minted amount after slippage deduction
  const amountAfterSlippage = amountBurnt - actualSlippage;
  const convertResult = getConvertedAmount(rateResult.rate, amountAfterSlippage);

  if (!convertResult.success) {
    return { success: false, error: convertResult.error };
  }

  return {
    success: true,
    amountMinted: convertResult.amount,
    actualSlippage,
    conversionRate: rateResult.rate
  };
}

// ============================================================================
// SERIALIZATION / PARSING
// ============================================================================

/**
 * Parse a pricing record from JSON (as received from oracle HTTP response)
 *
 * @param {Object} json - JSON object from oracle response
 * @returns {PricingRecord} Parsed pricing record
 */
export function parsePricingRecordFromJson(json) {
  // Parse assets array
  const assets = (json.assets || []).map(a => ({
    assetType: a.asset_type,
    spotPrice: BigInt(a.spot_price || 0),
    maPrice: BigInt(a.ma_price || 0)
  }));

  // Parse supply (handle both uppercase and lowercase field names)
  const supply = {
    sal: BigInt(json.supply?.SAL || json.supply?.sal || 0),
    vsd: BigInt(json.supply?.VSD || json.supply?.vsd || 0)
  };

  // Parse signature from hex string to bytes
  let signature = new Uint8Array(0);
  if (json.signature) {
    if (typeof json.signature === 'string') {
      // Hex string
      const hex = json.signature.replace(/^0x/, '');
      signature = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        signature[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
    } else if (Array.isArray(json.signature)) {
      // Already an array
      signature = new Uint8Array(json.signature);
    }
  }

  return {
    prVersion: json.pr_version || 0,
    height: json.height || 0,
    supply,
    assets,
    timestamp: json.timestamp || 0,
    signature
  };
}

/**
 * Convert a pricing record to JSON format
 *
 * @param {PricingRecord} pr - Pricing record
 * @returns {Object} JSON object
 */
export function pricingRecordToJson(pr) {
  // Convert signature to hex string
  let signatureHex = '';
  if (pr.signature && pr.signature.length > 0) {
    signatureHex = Array.from(pr.signature)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  return {
    pr_version: pr.prVersion,
    height: pr.height,
    supply: {
      SAL: pr.supply.sal.toString(),
      VSD: pr.supply.vsd.toString()
    },
    assets: pr.assets.map(a => ({
      asset_type: a.assetType,
      spot_price: a.spotPrice.toString(),
      ma_price: a.maPrice.toString()
    })),
    timestamp: pr.timestamp,
    signature: signatureHex
  };
}

// ============================================================================
// ORACLE HTTP CLIENT
// ============================================================================

/**
 * Fetch pricing record from oracle server
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp (get_pricing_record)
 *
 * @param {Object} options - Fetch options
 * @param {number} options.height - Block height for pricing
 * @param {bigint} options.salSupply - Current SAL circulating supply
 * @param {bigint} options.vsdSupply - Current VSD circulating supply
 * @param {string} options.url - Oracle URL (optional, uses default)
 * @param {number} options.timeout - Request timeout in ms (default: 10000)
 * @returns {Promise<{success: boolean, pricingRecord?: PricingRecord, error?: string}>}
 */
export async function fetchPricingRecord(options = {}) {
  const {
    height = 0,
    salSupply = 0n,
    vsdSupply = 0n,
    url = ORACLE_URLS[0],
    timeout = 10000
  } = options;

  // Build request URL
  const queryString = [
    `height=${encodeURIComponent(height.toString())}`,
    `sal=${encodeURIComponent(salSupply.toString())}`,
    `vsd=${encodeURIComponent(vsdSupply.toString())}`,
  ].join('&');

  const fullUrl = `${url}/price?${queryString}`;

  try {
    const response = await Promise.race([
      fetch(fullUrl, { method: 'GET' }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Oracle request timed out')), timeout)
      ),
    ]);

    if (!response.ok) {
      return {
        success: false,
        error: `Oracle request failed: ${response.status} ${response.statusText}`
      };
    }

    const json = await response.json();
    const pricingRecord = parsePricingRecordFromJson(json);

    return { success: true, pricingRecord };
  } catch (error) {
    return {
      success: false,
      error: `Oracle fetch error: ${error.message}`
    };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Constants
  COIN,
  PRICING_RECORD_VALID_BLOCKS,
  PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK,
  CONVERSION_RATE_ROUNDING,
  ASSET_TYPES,
  HF_VERSION_ENABLE_ORACLE,
  HF_VERSION_SLIPPAGE_YIELD,
  ORACLE_URLS,
  ORACLE_PUBLIC_KEY_MAINNET,
  ORACLE_PUBLIC_KEY_TESTNET,

  // Data structures
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getAssetMaPrice,

  // Signature verification
  buildSignatureMessage,
  verifyPricingRecordSignature,
  getOraclePublicKey,

  // Validation
  validatePricingRecord,

  // Conversion
  getConversionRate,
  getConvertedAmount,
  calculateSlippage,
  calculateConversion,

  // Serialization
  parsePricingRecordFromJson,
  pricingRecordToJson,

  // HTTP client
  fetchPricingRecord
};
