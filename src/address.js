/**
 * Salvium Address Handling
 *
 * Supports all 18 address types across:
 * - 3 networks: mainnet, testnet, stagenet
 * - 2 formats: legacy (CryptoNote), carrot (CARROT)
 * - 3 types: standard, integrated, subaddress
 */

import {
  NETWORK,
  ADDRESS_TYPE,
  ADDRESS_FORMAT,
  PREFIX_MAP,
  KEY_SIZE,
  PAYMENT_ID_SIZE,
  ADDRESS_DATA_SIZE,
  getPrefix
} from './constants.js';
import { decodeAddress, encodeAddress } from './base58.js';
import {
  cnSubaddress,
  carrotSubaddress,
  generatePaymentId as genPaymentId
} from './subaddress.js';

/**
 * Result of parsing an address
 * @typedef {Object} ParsedAddress
 * @property {boolean} valid - Whether the address is valid
 * @property {string|null} network - Network type (mainnet, testnet, stagenet)
 * @property {string|null} format - Address format (legacy, carrot)
 * @property {string|null} type - Address type (standard, integrated, subaddress)
 * @property {string|null} prefix - Human-readable prefix (e.g., "SaLv", "SC1")
 * @property {Uint8Array|null} spendPublicKey - 32-byte public spend key
 * @property {Uint8Array|null} viewPublicKey - 32-byte public view key
 * @property {Uint8Array|null} paymentId - 8-byte payment ID (integrated addresses only)
 * @property {string|null} error - Error message if invalid
 */

/**
 * Parse and validate a Salvium address
 * @param {string} address - The address string to parse
 * @returns {ParsedAddress} - Parsed address information
 */
export function parseAddress(address) {
  const result = {
    valid: false,
    network: null,
    format: null,
    type: null,
    prefix: null,
    spendPublicKey: null,
    viewPublicKey: null,
    paymentId: null,
    error: null
  };

  // Basic validation
  if (!address || typeof address !== 'string') {
    result.error = 'Address must be a non-empty string';
    return result;
  }

  // Trim whitespace
  address = address.trim();

  // Check length (rough bounds based on possible address types)
  // Standard: ~95-99 chars, Integrated: ~106-110 chars, Subaddress: ~95-99 chars
  // Allow wide range to accommodate all prefix sizes
  if (address.length < 90 || address.length > 150) {
    result.error = 'Invalid address length';
    return result;
  }

  // Decode the address
  let decoded;
  try {
    decoded = decodeAddress(address);
  } catch (e) {
    result.error = e.message;
    return result;
  }

  const { tag, data } = decoded;

  // Look up the prefix
  const prefixInfo = PREFIX_MAP.get(tag);
  if (!prefixInfo) {
    result.error = `Unknown address prefix: 0x${tag.toString(16)}`;
    return result;
  }

  result.network = prefixInfo.network;
  result.format = prefixInfo.format;
  result.type = prefixInfo.type;
  result.prefix = prefixInfo.text;

  // Validate data length based on address type
  const expectedDataSize = ADDRESS_DATA_SIZE[result.type];
  if (data.length !== expectedDataSize) {
    result.error = `Invalid data length: expected ${expectedDataSize} bytes, got ${data.length}`;
    return result;
  }

  // Extract public keys
  result.spendPublicKey = data.slice(0, KEY_SIZE);
  result.viewPublicKey = data.slice(KEY_SIZE, KEY_SIZE * 2);

  // Extract payment ID for integrated addresses
  if (result.type === ADDRESS_TYPE.INTEGRATED) {
    result.paymentId = data.slice(KEY_SIZE * 2, KEY_SIZE * 2 + PAYMENT_ID_SIZE);
  }

  result.isCarrot = result.format === 'carrot';
  result.valid = true;
  return result;
}

/**
 * Validate a Salvium address
 * @param {string} address - The address string to validate
 * @returns {boolean} - True if valid, false otherwise
 */
export function isValidAddress(address) {
  return parseAddress(address).valid;
}

/**
 * Check if an address belongs to a specific network
 * @param {string} address - The address string
 * @param {string} network - Network to check (mainnet, testnet, stagenet)
 * @returns {boolean} - True if address belongs to the specified network
 */
export function isNetwork(address, network) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.network === network;
}

/**
 * Check if an address is a mainnet address
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isMainnet(address) {
  return isNetwork(address, NETWORK.MAINNET);
}

/**
 * Check if an address is a testnet address
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isTestnet(address) {
  return isNetwork(address, NETWORK.TESTNET);
}

/**
 * Check if an address is a stagenet address
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isStagenet(address) {
  return isNetwork(address, NETWORK.STAGENET);
}

/**
 * Check if an address uses the CARROT format
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isCarrot(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.format === ADDRESS_FORMAT.CARROT;
}

/**
 * Check if an address uses the legacy CryptoNote format
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isLegacy(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.format === ADDRESS_FORMAT.LEGACY;
}

/**
 * Check if an address is a standard address
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isStandard(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.type === ADDRESS_TYPE.STANDARD;
}

/**
 * Check if an address is an integrated address
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isIntegrated(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.type === ADDRESS_TYPE.INTEGRATED;
}

/**
 * Check if an address is a subaddress
 * @param {string} address - The address string
 * @returns {boolean}
 */
export function isSubaddress(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.type === ADDRESS_TYPE.SUBADDRESS;
}

/**
 * Get the public spend key from an address
 * @param {string} address - The address string
 * @returns {Uint8Array|null} - 32-byte public spend key or null if invalid
 */
export function getSpendPublicKey(address) {
  const parsed = parseAddress(address);
  return parsed.valid ? parsed.spendPublicKey : null;
}

/**
 * Get the public view key from an address
 * @param {string} address - The address string
 * @returns {Uint8Array|null} - 32-byte public view key or null if invalid
 */
export function getViewPublicKey(address) {
  const parsed = parseAddress(address);
  return parsed.valid ? parsed.viewPublicKey : null;
}

/**
 * Get the payment ID from an integrated address
 * @param {string} address - The address string
 * @returns {Uint8Array|null} - 8-byte payment ID or null if not an integrated address
 */
export function getPaymentId(address) {
  const parsed = parseAddress(address);
  return parsed.valid && parsed.type === ADDRESS_TYPE.INTEGRATED ? parsed.paymentId : null;
}

/**
 * Create an address from components
 * @param {Object} options - Address options
 * @param {string} options.network - Network type
 * @param {string} options.format - Address format
 * @param {string} options.type - Address type
 * @param {Uint8Array} options.spendPublicKey - 32-byte public spend key
 * @param {Uint8Array} options.viewPublicKey - 32-byte public view key
 * @param {Uint8Array} [options.paymentId] - 8-byte payment ID (for integrated addresses)
 * @returns {string|null} - Encoded address or null on error
 */
export function createAddress(options) {
  const { network, format, type, spendPublicKey, viewPublicKey, paymentId } = options;

  // Validate keys
  if (!spendPublicKey) {
    throw new Error('createAddress: spendPublicKey is required');
  }
  if (spendPublicKey.length !== KEY_SIZE) {
    throw new Error(`createAddress: spendPublicKey must be ${KEY_SIZE} bytes, got ${spendPublicKey.length}`);
  }
  if (!viewPublicKey) {
    throw new Error('createAddress: viewPublicKey is required');
  }
  if (viewPublicKey.length !== KEY_SIZE) {
    throw new Error(`createAddress: viewPublicKey must be ${KEY_SIZE} bytes, got ${viewPublicKey.length}`);
  }

  // Get prefix
  const prefix = getPrefix(network, format, type);
  if (prefix === null) {
    throw new Error(`createAddress: invalid network/format/type combination: ${network}/${format}/${type}`);
  }

  // Build data
  let data;
  if (type === ADDRESS_TYPE.INTEGRATED) {
    if (!paymentId) {
      throw new Error('createAddress: paymentId is required for integrated addresses');
    }
    if (paymentId.length !== PAYMENT_ID_SIZE) {
      throw new Error(`createAddress: paymentId must be ${PAYMENT_ID_SIZE} bytes, got ${paymentId.length}`);
    }
    data = new Uint8Array(KEY_SIZE * 2 + PAYMENT_ID_SIZE);
    data.set(spendPublicKey, 0);
    data.set(viewPublicKey, KEY_SIZE);
    data.set(paymentId, KEY_SIZE * 2);
  } else {
    data = new Uint8Array(KEY_SIZE * 2);
    data.set(spendPublicKey, 0);
    data.set(viewPublicKey, KEY_SIZE);
  }

  return encodeAddress(prefix, data);
}

/**
 * Convert a standard address to an integrated address by adding a payment ID
 * @param {string} address - Standard address
 * @param {Uint8Array|string} paymentId - 8-byte payment ID (or 16-char hex string)
 * @returns {string} - Integrated address
 * @throws {Error} If address is invalid or not a standard address
 */
export function toIntegratedAddress(address, paymentId) {
  const parsed = parseAddress(address);

  if (!parsed.valid) {
    throw new Error(`toIntegratedAddress: invalid address - ${parsed.error}`);
  }
  if (parsed.type !== ADDRESS_TYPE.STANDARD) {
    throw new Error(`toIntegratedAddress: address must be a standard address, got ${parsed.type}`);
  }

  // Convert hex string to bytes if needed
  if (typeof paymentId === 'string') {
    if (paymentId.length !== 16) {
      throw new Error(`toIntegratedAddress: payment ID hex string must be 16 characters, got ${paymentId.length}`);
    }
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      bytes[i] = parseInt(paymentId.substr(i * 2, 2), 16);
    }
    paymentId = bytes;
  }

  if (paymentId.length !== PAYMENT_ID_SIZE) {
    throw new Error(`toIntegratedAddress: payment ID must be ${PAYMENT_ID_SIZE} bytes, got ${paymentId.length}`);
  }

  return createAddress({
    network: parsed.network,
    format: parsed.format,
    type: ADDRESS_TYPE.INTEGRATED,
    spendPublicKey: parsed.spendPublicKey,
    viewPublicKey: parsed.viewPublicKey,
    paymentId
  });
}

/**
 * Extract the standard address from an integrated address
 * @param {string} address - Integrated address
 * @returns {string} - Standard address
 * @throws {Error} If address is invalid or not an integrated address
 */
export function toStandardAddress(address) {
  const parsed = parseAddress(address);

  if (!parsed.valid) {
    throw new Error(`toStandardAddress: invalid address - ${parsed.error}`);
  }
  if (parsed.type !== ADDRESS_TYPE.INTEGRATED) {
    throw new Error(`toStandardAddress: address must be an integrated address, got ${parsed.type}`);
  }

  return createAddress({
    network: parsed.network,
    format: parsed.format,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: parsed.spendPublicKey,
    viewPublicKey: parsed.viewPublicKey
  });
}

/**
 * Format address info as a human-readable string
 * @param {string} address - The address string
 * @returns {string} - Human-readable description
 */
export function describeAddress(address) {
  const parsed = parseAddress(address);

  if (!parsed.valid) {
    return `Invalid address: ${parsed.error}`;
  }

  const parts = [
    parsed.network.charAt(0).toUpperCase() + parsed.network.slice(1),
    parsed.format === ADDRESS_FORMAT.CARROT ? 'CARROT' : 'Legacy',
    parsed.type
  ];

  if (parsed.type === ADDRESS_TYPE.INTEGRATED) {
    const paymentIdHex = Array.from(parsed.paymentId)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    parts.push(`(Payment ID: ${paymentIdHex})`);
  }

  return parts.join(' ');
}

/**
 * Convert bytes to hex string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} - Hex string
 */
// Pre-computed hex lookup table — avoids Array.from().map().join() per call
const _hexLUT = /* @__PURE__ */ (() => {
  const t = new Array(256);
  for (let i = 0; i < 256; i++) t[i] = i.toString(16).padStart(2, '0');
  return t;
})();

export function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += _hexLUT[bytes[i]];
  return hex;
}

/**
 * Convert hex string to bytes
 * @param {string} hex - Hex string
 * @returns {Uint8Array} - Bytes
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ============================================================================
// Subaddress Generation
// ============================================================================

/**
 * Generate a CryptoNote (Legacy) subaddress
 * @param {Object} options - Subaddress options
 * @param {string} options.network - Network type (mainnet, testnet, stagenet)
 * @param {Uint8Array} options.spendPublicKey - 32-byte main spend public key
 * @param {Uint8Array} options.viewSecretKey - 32-byte view secret key
 * @param {number} options.major - Major index (account)
 * @param {number} options.minor - Minor index (address within account)
 * @returns {Object} { address, spendPublicKey, viewPublicKey }
 */
export function generateCNSubaddress(options) {
  const { network, spendPublicKey, viewSecretKey, major, minor } = options;

  // Generate subaddress keys
  const keys = cnSubaddress(spendPublicKey, viewSecretKey, major, minor);

  // Create the address string
  const address = createAddress({
    network,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.SUBADDRESS,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });

  return {
    address,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey,
    major,
    minor
  };
}

/**
 * Generate a CARROT subaddress
 * @param {Object} options - Subaddress options
 * @param {string} options.network - Network type (mainnet, testnet, stagenet)
 * @param {Uint8Array} options.accountSpendPubkey - K_s (32 bytes)
 * @param {Uint8Array} options.accountViewPubkey - K_v = k_vi × K_s (32 bytes)
 * @param {Uint8Array} options.generateAddressSecret - s_ga (32 bytes)
 * @param {number} options.major - Major index
 * @param {number} options.minor - Minor index
 * @returns {Object} { address, spendPublicKey, viewPublicKey, isMainAddress }
 */
export function generateCarrotSubaddress(options) {
  const { network, accountSpendPubkey, accountViewPubkey, generateAddressSecret, major, minor } = options;

  // Generate subaddress keys
  const keys = carrotSubaddress(accountSpendPubkey, accountViewPubkey, generateAddressSecret, major, minor);

  // For main address (0,0), use standard type; otherwise subaddress type
  const addressType = keys.isMainAddress ? ADDRESS_TYPE.STANDARD : ADDRESS_TYPE.SUBADDRESS;

  // Create the address string
  const address = createAddress({
    network,
    format: ADDRESS_FORMAT.CARROT,
    type: addressType,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });

  return {
    address,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey,
    isMainAddress: keys.isMainAddress,
    major,
    minor
  };
}

/**
 * Generate a random 8-byte payment ID
 * @returns {Uint8Array} 8-byte payment ID
 */
export function generateRandomPaymentId() {
  return genPaymentId();
}

/**
 * Create an integrated address with a random payment ID
 * @param {string} address - Standard address
 * @returns {Object} { address, paymentId, paymentIdHex } - Integrated address and its payment ID
 * @throws {Error} If address is invalid or not a standard address
 */
export function createIntegratedAddressWithRandomId(address) {
  const paymentId = genPaymentId();
  const integratedAddress = toIntegratedAddress(address, paymentId);

  return {
    address: integratedAddress,
    paymentId,
    paymentIdHex: bytesToHex(paymentId)
  };
}

export default {
  parseAddress,
  isValidAddress,
  isNetwork,
  isMainnet,
  isTestnet,
  isStagenet,
  isCarrot,
  isLegacy,
  isStandard,
  isIntegrated,
  isSubaddress,
  getSpendPublicKey,
  getViewPublicKey,
  getPaymentId,
  createAddress,
  toIntegratedAddress,
  toStandardAddress,
  describeAddress,
  bytesToHex,
  hexToBytes,
  // Subaddress generation
  generateCNSubaddress,
  generateCarrotSubaddress,
  generateRandomPaymentId,
  createIntegratedAddressWithRandomId
};
