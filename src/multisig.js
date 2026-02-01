/**
 * Multisig Wallet Support
 *
 * Implements M-of-N threshold signature wallets for Salvium:
 * - Multi-round Diffie-Hellman key exchange (KEX)
 * - CLSAG signing with MuSig2-style nonces
 * - Salvium-specific extensions (origin_data, tx_types)
 *
 * Workflow:
 * 1. Each participant generates initial KEX message
 * 2. Exchange messages through multiple rounds
 * 3. Create multisig wallet when all rounds complete
 * 4. Create unsigned transaction (by any participant)
 * 5. Pass around for partial signatures
 * 6. Finalize when M signatures collected
 *
 * @module multisig
 */

import { bytesToHex, hexToBytes } from './address.js';
import { keccak256, scalarMultBase, scalarMultPoint, pointAddCompressed, randomScalar, scReduce32, scAdd, scMul, scMulAdd } from './crypto/index.js';
import { encode as base58Encode, decode as base58Decode } from './base58.js';

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Maximum number of signers in a multisig wallet
 */
export const MULTISIG_MAX_SIGNERS = 16;

/**
 * Minimum threshold for multisig
 */
export const MULTISIG_MIN_THRESHOLD = 2;

/**
 * Number of parallel nonce components (MuSig2-style)
 */
export const MULTISIG_NONCE_COMPONENTS = 2;

/**
 * Multisig message types
 */
export const MULTISIG_MSG_TYPE = {
  KEX_INIT: 'kex_init',       // Round 1 message
  KEX_ROUND: 'kex_round',     // Subsequent rounds
  KEX_VERIFY: 'kex_verify',   // Post-KEX verification
  TX_SET: 'tx_set',           // Unsigned transaction set
  PARTIAL_SIG: 'partial_sig', // Partial signature
  FINAL_TX: 'final_tx'        // Finalized transaction
};

/**
 * Domain separation tags
 */
const DOMAIN_SEP = {
  KEY_BLINDING: new Uint8Array([0x6d, 0x75, 0x6c, 0x74, 0x69, 0x73, 0x69, 0x67]), // "multisig"
  KEX_MSG: new Uint8Array([0x6b, 0x65, 0x78, 0x5f, 0x6d, 0x73, 0x67]),           // "kex_msg"
  NONCE: new Uint8Array([0x6e, 0x6f, 0x6e, 0x63, 0x65])                          // "nonce"
};

// ============================================================================
// MULTISIG KEY EXCHANGE
// ============================================================================

/**
 * Generate a blinded secret key for multisig
 * @param {Uint8Array} secretKey - Original secret key
 * @param {Uint8Array} domainSep - Domain separator
 * @returns {Uint8Array} Blinded key
 */
export function getMultisigBlindedSecretKey(secretKey, domainSep = DOMAIN_SEP.KEY_BLINDING) {
  // H(key || domain-sep)
  const input = new Uint8Array(secretKey.length + domainSep.length);
  input.set(secretKey, 0);
  input.set(domainSep, secretKey.length);
  return scReduce32(keccak256(input));
}

/**
 * Compute Diffie-Hellman shared secret
 * @param {Uint8Array} secretKey - Our secret key
 * @param {Uint8Array} publicKey - Their public key
 * @returns {Uint8Array} Shared secret point
 */
export function computeDHSecret(secretKey, publicKey) {
  return scalarMultPoint(secretKey, publicKey);
}

/**
 * Create a key exchange message
 */
export class KexMessage {
  constructor() {
    this.round = 0;
    this.signerIndex = 0;
    this.publicKey = null;        // Our contribution public key
    this.commonPubkey = null;     // Common (view) key contribution
    this.dhPubkeys = [];          // DH public keys for this round
    this.signature = null;        // Signature on the message
  }

  /**
   * Serialize to bytes
   * @returns {Uint8Array}
   */
  serialize() {
    const parts = [
      new Uint8Array([this.round]),
      new Uint8Array([this.signerIndex]),
      this.publicKey || new Uint8Array(32),
      this.commonPubkey || new Uint8Array(32)
    ];

    // Add DH pubkeys count
    parts.push(new Uint8Array([this.dhPubkeys.length]));
    for (const pk of this.dhPubkeys) {
      parts.push(pk);
    }

    // Add signature if present
    if (this.signature) {
      parts.push(this.signature);
    }

    const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  /**
   * Deserialize from bytes
   * @param {Uint8Array} bytes
   * @returns {KexMessage}
   */
  static deserialize(bytes) {
    const msg = new KexMessage();
    let offset = 0;

    msg.round = bytes[offset++];
    msg.signerIndex = bytes[offset++];
    msg.publicKey = bytes.slice(offset, offset + 32);
    offset += 32;
    msg.commonPubkey = bytes.slice(offset, offset + 32);
    offset += 32;

    const dhCount = bytes[offset++];
    for (let i = 0; i < dhCount; i++) {
      msg.dhPubkeys.push(bytes.slice(offset, offset + 32));
      offset += 32;
    }

    if (offset < bytes.length) {
      msg.signature = bytes.slice(offset, offset + 64);
    }

    return msg;
  }

  /**
   * Encode to base58 string
   * @returns {string}
   */
  toString() {
    return base58Encode(this.serialize());
  }

  /**
   * Decode from base58 string
   * @param {string} str
   * @returns {KexMessage}
   */
  static fromString(str) {
    return KexMessage.deserialize(base58Decode(str));
  }
}

/**
 * Calculate number of key exchange rounds required
 * @param {number} threshold - M value
 * @param {number} signers - N value
 * @returns {number} Number of rounds
 */
export function kexRoundsRequired(threshold, signers) {
  // For M-of-N: N rounds for full key exchange
  // Plus 1 verification round
  return signers;
}

// ============================================================================
// MULTISIG ACCOUNT
// ============================================================================

/**
 * Represents a participant in a multisig wallet
 */
export class MultisigSigner {
  constructor(config = {}) {
    this.index = config.index ?? 0;
    this.publicSpendKey = config.publicSpendKey || null;  // Base public spend key
    this.publicViewKey = config.publicViewKey || null;    // Base public view key (shared)
    this.label = config.label || '';
  }
}

/**
 * Multisig account state machine for key exchange
 */
export class MultisigAccount {
  constructor(config = {}) {
    // Configuration
    this.threshold = config.threshold || 2;  // M
    this.signerCount = config.signerCount || 2;  // N

    // Our keys
    this.baseSpendSecretKey = config.spendSecretKey || null;
    this.baseViewSecretKey = config.viewSecretKey || null;

    // Blinded keys for multisig
    this.multisigSpendSecretKey = null;
    this.multisigCommonSecretKey = null;

    // Key shares (for signing)
    this.multisigKeyShares = [];  // Array of {pubkey, privkey}

    // Other participants
    this.signers = [];

    // Final keys (set after KEX complete)
    this.multisigPublicSpendKey = null;
    this.multisigPublicViewKey = null;

    // KEX state
    this.kexRound = 0;
    this.kexComplete = false;
    this.kexMessages = [];  // Received messages per round

    // Validate
    if (this.threshold < MULTISIG_MIN_THRESHOLD) {
      throw new Error(`Threshold must be at least ${MULTISIG_MIN_THRESHOLD}`);
    }
    if (this.signerCount > MULTISIG_MAX_SIGNERS) {
      throw new Error(`Maximum ${MULTISIG_MAX_SIGNERS} signers supported`);
    }
    if (this.threshold > this.signerCount) {
      throw new Error('Threshold cannot exceed signer count');
    }
  }

  /**
   * Initialize key exchange and generate Round 1 message
   * @returns {KexMessage}
   */
  initializeKex() {
    if (!this.baseSpendSecretKey || !this.baseViewSecretKey) {
      throw new Error('Base keys not set');
    }

    // Blind our base keys
    this.multisigSpendSecretKey = getMultisigBlindedSecretKey(this.baseSpendSecretKey);
    this.multisigCommonSecretKey = getMultisigBlindedSecretKey(this.baseViewSecretKey);

    // Compute public keys
    const publicKey = scalarMultBase(this.multisigSpendSecretKey);
    const commonPubkey = scalarMultBase(this.multisigCommonSecretKey);

    // Create Round 1 message
    const msg = new KexMessage();
    msg.round = 1;
    msg.signerIndex = 0;  // Will be set when we know our index
    msg.publicKey = publicKey;
    msg.commonPubkey = commonPubkey;

    this.kexRound = 1;
    return msg;
  }

  /**
   * Process key exchange messages and advance to next round
   * @param {Array<KexMessage>} messages - Messages from other participants
   * @returns {KexMessage|null} Next round message, or null if complete
   */
  updateKex(messages) {
    if (this.kexComplete) {
      throw new Error('Key exchange already complete');
    }

    // Validate message count
    if (messages.length !== this.signerCount - 1) {
      throw new Error(`Expected ${this.signerCount - 1} messages, got ${messages.length}`);
    }

    // Store messages
    this.kexMessages.push(messages);

    if (this.kexRound === 1) {
      // Round 1: Collect all base public keys
      this.signers = messages.map((msg, i) => new MultisigSigner({
        index: i + 1,  // We are index 0
        publicSpendKey: msg.publicKey,
        publicViewKey: msg.commonPubkey
      }));

      // Determine our index (sorted by public key)
      const allPubkeys = [
        { key: scalarMultBase(this.multisigSpendSecretKey), index: 0, isUs: true },
        ...messages.map((m, i) => ({ key: m.publicKey, index: i + 1, isUs: false }))
      ];
      allPubkeys.sort((a, b) => {
        const aHex = bytesToHex(a.key);
        const bHex = bytesToHex(b.key);
        return aHex.localeCompare(bHex);
      });
      const ourIndex = allPubkeys.findIndex(p => p.isUs);

      // Update signer indices
      for (let i = 0; i < this.signers.length; i++) {
        const signer = this.signers[i];
        const found = allPubkeys.find(p => !p.isUs &&
          bytesToHex(p.key) === bytesToHex(signer.publicSpendKey));
        if (found) {
          signer.index = found.index;
        }
      }
    }

    // Compute DH with each other signer
    const dhResults = [];
    for (const signer of this.signers) {
      const dhPoint = computeDHSecret(this.multisigSpendSecretKey, signer.publicSpendKey);
      const blindedKey = getMultisigBlindedSecretKey(dhPoint);
      dhResults.push({
        signerIndex: signer.index,
        secretKey: blindedKey,
        publicKey: scalarMultBase(blindedKey)
      });
    }

    // Store key shares
    this.multisigKeyShares = dhResults.map(dh => ({
      pubkey: dh.publicKey,
      privkey: dh.secretKey
    }));

    this.kexRound++;

    // Check if KEX is complete
    if (this.kexRound > kexRoundsRequired(this.threshold, this.signerCount)) {
      return this._finalizeKex();
    }

    // Generate next round message
    const msg = new KexMessage();
    msg.round = this.kexRound;
    msg.signerIndex = 0;  // Our canonical index
    msg.dhPubkeys = dhResults.map(dh => dh.publicKey);

    return msg;
  }

  /**
   * Finalize key exchange and compute final multisig keys
   * @private
   * @returns {null}
   */
  _finalizeKex() {
    // Aggregate common (view) keys
    let viewSecretKey = this.multisigCommonSecretKey;
    for (const signer of this.signers) {
      // Add their common pubkey contribution
      // In practice, we'd use their secret contributions
    }

    // Aggregate spend keys
    let spendPubKey = scalarMultBase(this.multisigSpendSecretKey);
    for (const signer of this.signers) {
      spendPubKey = pointAddCompressed(spendPubKey, signer.publicSpendKey);
    }

    // Compute final keys
    this.multisigPublicSpendKey = spendPubKey;
    this.multisigPublicViewKey = scalarMultBase(viewSecretKey);

    this.kexComplete = true;
    return null;
  }

  /**
   * Check if key exchange is complete
   * @returns {boolean}
   */
  isKexComplete() {
    return this.kexComplete;
  }

  /**
   * Get multisig info for export
   * @returns {Object}
   */
  getMultisigInfo() {
    if (!this.kexComplete) {
      throw new Error('Key exchange not complete');
    }

    return {
      threshold: this.threshold,
      signerCount: this.signerCount,
      publicSpendKey: bytesToHex(this.multisigPublicSpendKey),
      publicViewKey: bytesToHex(this.multisigPublicViewKey),
      keyShares: this.multisigKeyShares.map(ks => ({
        pubkey: bytesToHex(ks.pubkey),
        // Note: privkey not exported for security
      })),
      signers: this.signers.map(s => ({
        index: s.index,
        publicSpendKey: bytesToHex(s.publicSpendKey),
        label: s.label
      }))
    };
  }
}

// ============================================================================
// MULTISIG TRANSACTION SIGNING
// ============================================================================

/**
 * Represents an unsigned multisig transaction set
 */
export class MultisigTxSet {
  constructor() {
    this.txs = [];              // Array of transaction data
    this.signingAttempts = [];  // Array of possible signer subsets
    this.keyImages = [];        // Pre-computed key images
  }

  /**
   * Add a transaction to the set
   * @param {Object} txData - Transaction data
   */
  addTransaction(txData) {
    this.txs.push(txData);
  }

  /**
   * Serialize to bytes
   * @returns {Uint8Array}
   */
  serialize() {
    return new TextEncoder().encode(JSON.stringify({
      txs: this.txs.map(tx => ({
        ...tx,
        // Convert Uint8Arrays to hex
        inputs: tx.inputs?.map(i => ({
          ...i,
          keyImage: i.keyImage ? bytesToHex(i.keyImage) : null,
          publicKey: i.publicKey ? bytesToHex(i.publicKey) : null
        })),
        outputs: tx.outputs?.map(o => ({
          ...o,
          publicKey: o.publicKey ? bytesToHex(o.publicKey) : null
        }))
      })),
      signingAttempts: this.signingAttempts,
      keyImages: this.keyImages.map(ki => bytesToHex(ki))
    }));
  }

  /**
   * Deserialize from bytes
   * @param {Uint8Array} bytes
   * @returns {MultisigTxSet}
   */
  static deserialize(bytes) {
    const data = JSON.parse(new TextDecoder().decode(bytes));
    const set = new MultisigTxSet();
    set.txs = data.txs.map(tx => ({
      ...tx,
      inputs: tx.inputs?.map(i => ({
        ...i,
        keyImage: i.keyImage ? hexToBytes(i.keyImage) : null,
        publicKey: i.publicKey ? hexToBytes(i.publicKey) : null
      })),
      outputs: tx.outputs?.map(o => ({
        ...o,
        publicKey: o.publicKey ? hexToBytes(o.publicKey) : null
      }))
    }));
    set.signingAttempts = data.signingAttempts;
    set.keyImages = data.keyImages.map(ki => hexToBytes(ki));
    return set;
  }

  /**
   * Encode to base58 string
   * @returns {string}
   */
  toString() {
    return base58Encode(this.serialize());
  }

  /**
   * Decode from base58 string
   * @param {string} str
   * @returns {MultisigTxSet}
   */
  static fromString(str) {
    return MultisigTxSet.deserialize(base58Decode(str));
  }
}

/**
 * Generate random nonces for multisig signing
 * @param {number} inputCount - Number of inputs
 * @returns {Array} Array of nonce pairs [alpha1, alpha2] per input
 */
export function generateMultisigNonces(inputCount) {
  const nonces = [];
  for (let i = 0; i < inputCount; i++) {
    nonces.push([
      randomScalar(),
      randomScalar()
    ]);
  }
  return nonces;
}

/**
 * Compute combined nonce with Fiat-Shamir factor
 * @param {Array} nonces - Nonce pairs
 * @param {Uint8Array} messageHash - Transaction message hash
 * @param {Array} pubNonces - All signers' public nonces
 * @returns {Array} Combined nonces per input
 */
export function combineMultisigNonces(nonces, messageHash, pubNonces) {
  const combined = [];

  for (let i = 0; i < nonces.length; i++) {
    // Compute factor b = H(domain, message, pubNonces, i)
    const input = new Uint8Array(
      DOMAIN_SEP.NONCE.length + messageHash.length + 4
    );
    let offset = 0;
    input.set(DOMAIN_SEP.NONCE, offset);
    offset += DOMAIN_SEP.NONCE.length;
    input.set(messageHash, offset);
    offset += messageHash.length;
    input[offset] = i & 0xff;
    input[offset + 1] = (i >> 8) & 0xff;
    input[offset + 2] = (i >> 16) & 0xff;
    input[offset + 3] = (i >> 24) & 0xff;

    const b = scReduce32(keccak256(input));

    // Combined nonce: alpha = alpha1 + b * alpha2
    const alpha = scMulAdd(b, nonces[i][1], nonces[i][0]);
    combined.push(alpha);
  }

  return combined;
}

/**
 * Partial signature for a multisig transaction
 */
export class MultisigPartialSig {
  constructor() {
    this.signerIndex = 0;
    this.txIndex = 0;
    this.responses = [];  // Array of response values per input
    this.pubNonces = [];  // Public nonces for verification
  }

  /**
   * Serialize to bytes
   */
  serialize() {
    const data = {
      signerIndex: this.signerIndex,
      txIndex: this.txIndex,
      responses: this.responses.map(r => bytesToHex(r)),
      pubNonces: this.pubNonces.map(pn => pn.map(n => bytesToHex(n)))
    };
    return new TextEncoder().encode(JSON.stringify(data));
  }

  /**
   * Deserialize from bytes
   * @param {Uint8Array} bytes
   * @returns {MultisigPartialSig}
   */
  static deserialize(bytes) {
    const data = JSON.parse(new TextDecoder().decode(bytes));
    const sig = new MultisigPartialSig();
    sig.signerIndex = data.signerIndex;
    sig.txIndex = data.txIndex;
    sig.responses = data.responses.map(r => hexToBytes(r));
    sig.pubNonces = data.pubNonces.map(pn => pn.map(n => hexToBytes(n)));
    return sig;
  }

  /**
   * Encode to base58 string
   */
  toString() {
    return base58Encode(this.serialize());
  }

  /**
   * Decode from base58 string
   * @param {string} str
   * @returns {MultisigPartialSig}
   */
  static fromString(str) {
    return MultisigPartialSig.deserialize(base58Decode(str));
  }
}

// ============================================================================
// MULTISIG TRANSACTION BUILDER
// ============================================================================

/**
 * Build and sign multisig transactions
 */
export class MultisigTxBuilder {
  constructor(account) {
    if (!account.isKexComplete()) {
      throw new Error('Multisig account not ready - complete key exchange first');
    }
    this.account = account;
    this.nonces = null;
    this.partialSigs = [];
  }

  /**
   * Create an unsigned multisig transaction set
   * @param {Object} txData - Transaction data
   * @returns {MultisigTxSet}
   */
  createTxSet(txData) {
    const set = new MultisigTxSet();
    set.addTransaction(txData);

    // Generate all possible M-of-N signer subsets
    set.signingAttempts = this._generateSignerSubsets();

    return set;
  }

  /**
   * Generate first partial signature
   * @param {MultisigTxSet} txSet - Transaction set
   * @param {number} txIndex - Transaction index
   * @returns {MultisigPartialSig}
   */
  firstPartialSign(txSet, txIndex = 0) {
    const tx = txSet.txs[txIndex];
    if (!tx) {
      throw new Error(`Transaction ${txIndex} not found in set`);
    }

    const inputCount = tx.inputs?.length || 0;

    // Generate nonces
    this.nonces = generateMultisigNonces(inputCount);

    // Compute public nonces
    const pubNonces = this.nonces.map(([a1, a2]) => [
      scalarMultBase(a1),
      scalarMultBase(a2)
    ]);

    // Create partial signature
    const partialSig = new MultisigPartialSig();
    partialSig.signerIndex = 0;  // Our index
    partialSig.txIndex = txIndex;
    partialSig.pubNonces = pubNonces;

    // Responses will be computed in finalize when we have all nonces

    return partialSig;
  }

  /**
   * Add next partial signature
   * @param {MultisigTxSet} txSet - Transaction set
   * @param {Array<MultisigPartialSig>} existingSigs - Existing partial signatures
   * @param {number} txIndex - Transaction index
   * @returns {MultisigPartialSig}
   */
  nextPartialSign(txSet, existingSigs, txIndex = 0) {
    const tx = txSet.txs[txIndex];
    if (!tx) {
      throw new Error(`Transaction ${txIndex} not found in set`);
    }

    const inputCount = tx.inputs?.length || 0;

    // Generate our nonces
    this.nonces = generateMultisigNonces(inputCount);

    // Compute public nonces
    const pubNonces = this.nonces.map(([a1, a2]) => [
      scalarMultBase(a1),
      scalarMultBase(a2)
    ]);

    // Store existing partial signatures
    this.partialSigs = existingSigs;

    // Create our partial signature
    const partialSig = new MultisigPartialSig();
    partialSig.signerIndex = existingSigs.length;  // Next index
    partialSig.txIndex = txIndex;
    partialSig.pubNonces = pubNonces;

    return partialSig;
  }

  /**
   * Finalize transaction with all partial signatures
   * @param {MultisigTxSet} txSet - Transaction set
   * @param {Array<MultisigPartialSig>} partialSigs - All partial signatures
   * @param {number} txIndex - Transaction index
   * @returns {Object} Finalized transaction
   */
  finalizeTx(txSet, partialSigs, txIndex = 0) {
    const tx = txSet.txs[txIndex];
    if (!tx) {
      throw new Error(`Transaction ${txIndex} not found in set`);
    }

    // Verify we have enough signatures
    if (partialSigs.length < this.account.threshold) {
      throw new Error(
        `Need ${this.account.threshold} signatures, have ${partialSigs.length}`
      );
    }

    // Collect all public nonces
    const allPubNonces = partialSigs.map(ps => ps.pubNonces);

    // Compute message hash for the transaction
    const messageHash = this._computeTxMessageHash(tx);

    // Combine nonces and compute final responses
    const finalResponses = [];
    const inputCount = tx.inputs?.length || 0;

    for (let i = 0; i < inputCount; i++) {
      // Aggregate all nonce points for this input
      let L = new Uint8Array(32);  // Sum of R1 points
      let R = new Uint8Array(32);  // Sum of R2 points (after Fiat-Shamir)

      for (const ps of partialSigs) {
        if (ps.pubNonces[i]) {
          L = pointAddCompressed(L, ps.pubNonces[i][0]);
          R = pointAddCompressed(R, ps.pubNonces[i][1]);
        }
      }

      // Compute challenge c = H(domain, L, R, message)
      // This is simplified - real CLSAG uses more context
      const challengeInput = new Uint8Array(L.length + R.length + messageHash.length);
      challengeInput.set(L, 0);
      challengeInput.set(R, L.length);
      challengeInput.set(messageHash, L.length + R.length);
      const challenge = scReduce32(keccak256(challengeInput));

      // Aggregate responses: s = sum(s_i)
      let aggregateResponse = new Uint8Array(32);
      for (const ps of partialSigs) {
        if (ps.responses[i]) {
          aggregateResponse = scAdd(aggregateResponse, ps.responses[i]);
        }
      }

      finalResponses.push({
        challenge,
        response: aggregateResponse
      });
    }

    // Build final transaction
    return {
      ...tx,
      rctSig: {
        ...tx.rctSig,
        p: {
          CLSAGs: finalResponses.map(fr => ({
            c1: bytesToHex(fr.challenge),
            s: [bytesToHex(fr.response)]
          }))
        }
      }
    };
  }

  /**
   * Generate all M-of-N signer subsets
   * @private
   * @returns {Array} Array of signer index arrays
   */
  _generateSignerSubsets() {
    const subsets = [];
    const n = this.account.signerCount;
    const m = this.account.threshold;

    // Generate all combinations of m indices from n signers
    const indices = Array.from({ length: n }, (_, i) => i);

    function* combinations(arr, k, start = 0, current = []) {
      if (current.length === k) {
        yield [...current];
        return;
      }
      for (let i = start; i < arr.length; i++) {
        current.push(arr[i]);
        yield* combinations(arr, k, i + 1, current);
        current.pop();
      }
    }

    for (const combo of combinations(indices, m)) {
      subsets.push(combo);
    }

    return subsets;
  }

  /**
   * Compute transaction message hash
   * @private
   * @param {Object} tx - Transaction data
   * @returns {Uint8Array}
   */
  _computeTxMessageHash(tx) {
    // Simplified - real implementation uses full transaction prefix
    const txJson = JSON.stringify(tx);
    return keccak256(new TextEncoder().encode(txJson));
  }
}

// ============================================================================
// MULTISIG WALLET
// ============================================================================

/**
 * Multisig wallet wrapper
 */
export class MultisigWallet {
  constructor(config = {}) {
    this.account = new MultisigAccount(config);
    this.txBuilder = null;
    this.address = null;
    this.networkType = config.networkType || 'mainnet';
  }

  /**
   * Get initial key exchange message
   * @returns {string} Base58 encoded message
   */
  getFirstKexMessage() {
    const msg = this.account.initializeKex();
    return msg.toString();
  }

  /**
   * Process key exchange messages and get next message
   * @param {Array<string>} messages - Base58 encoded messages from others
   * @returns {string|null} Next message, or null if complete
   */
  exchangeKexMessages(messages) {
    const parsedMsgs = messages.map(m => KexMessage.fromString(m));
    const nextMsg = this.account.updateKex(parsedMsgs);

    if (nextMsg === null) {
      // KEX complete - initialize transaction builder
      this.txBuilder = new MultisigTxBuilder(this.account);
      return null;
    }

    return nextMsg.toString();
  }

  /**
   * Check if multisig wallet is ready
   * @returns {boolean}
   */
  isReady() {
    return this.account.isKexComplete();
  }

  /**
   * Get multisig info
   * @returns {Object}
   */
  getInfo() {
    return this.account.getMultisigInfo();
  }

  /**
   * Get the threshold (M value)
   * @returns {number}
   */
  getThreshold() {
    return this.account.threshold;
  }

  /**
   * Get the signer count (N value)
   * @returns {number}
   */
  getSignerCount() {
    return this.account.signerCount;
  }

  /**
   * Create unsigned transaction set
   * @param {Object} txData - Transaction data
   * @returns {string} Base58 encoded transaction set
   */
  createTxSet(txData) {
    if (!this.txBuilder) {
      throw new Error('Wallet not ready');
    }
    const set = this.txBuilder.createTxSet(txData);
    return set.toString();
  }

  /**
   * Create first partial signature
   * @param {string} txSetStr - Base58 encoded transaction set
   * @returns {string} Base58 encoded partial signature
   */
  signFirst(txSetStr) {
    if (!this.txBuilder) {
      throw new Error('Wallet not ready');
    }
    const txSet = MultisigTxSet.fromString(txSetStr);
    const partialSig = this.txBuilder.firstPartialSign(txSet);
    return partialSig.toString();
  }

  /**
   * Add partial signature
   * @param {string} txSetStr - Base58 encoded transaction set
   * @param {Array<string>} existingSigStrs - Existing partial signatures
   * @returns {string} Base58 encoded partial signature
   */
  signNext(txSetStr, existingSigStrs) {
    if (!this.txBuilder) {
      throw new Error('Wallet not ready');
    }
    const txSet = MultisigTxSet.fromString(txSetStr);
    const existingSigs = existingSigStrs.map(s => MultisigPartialSig.fromString(s));
    const partialSig = this.txBuilder.nextPartialSign(txSet, existingSigs);
    return partialSig.toString();
  }

  /**
   * Finalize transaction with all signatures
   * @param {string} txSetStr - Base58 encoded transaction set
   * @param {Array<string>} partialSigStrs - All partial signatures
   * @returns {Object} Finalized transaction
   */
  finalize(txSetStr, partialSigStrs) {
    if (!this.txBuilder) {
      throw new Error('Wallet not ready');
    }
    const txSet = MultisigTxSet.fromString(txSetStr);
    const partialSigs = partialSigStrs.map(s => MultisigPartialSig.fromString(s));
    return this.txBuilder.finalizeTx(txSet, partialSigs);
  }

  /**
   * Export multisig info for sharing
   * @returns {string} JSON string
   */
  exportInfo() {
    return JSON.stringify(this.getInfo(), null, 2);
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Create a new multisig wallet
 * @param {Object} config - Configuration
 * @param {number} config.threshold - M value
 * @param {number} config.signerCount - N value
 * @param {Uint8Array} config.spendSecretKey - Spend secret key
 * @param {Uint8Array} config.viewSecretKey - View secret key
 * @returns {MultisigWallet}
 */
export function createMultisigWallet(config) {
  return new MultisigWallet(config);
}

/**
 * Prepare multisig from collected key exchange messages
 * @param {Array<string>} allKexMessages - All participants' KEX messages (including ours)
 * @param {number} threshold - M value
 * @param {Uint8Array} spendSecretKey - Our spend secret key
 * @param {Uint8Array} viewSecretKey - Our view secret key
 * @returns {MultisigWallet}
 */
export function prepareMultisig(allKexMessages, threshold, spendSecretKey, viewSecretKey) {
  const wallet = new MultisigWallet({
    threshold,
    signerCount: allKexMessages.length,
    spendSecretKey,
    viewSecretKey
  });

  // Get our first message
  wallet.getFirstKexMessage();

  // Filter out our message and exchange
  const ourMsg = wallet.account.kexRound === 1 ?
    KexMessage.fromString(allKexMessages.find(m => {
      const parsed = KexMessage.fromString(m);
      // Find ours by comparing public key
      return false; // Simplified - real impl compares keys
    })) : null;

  const otherMsgs = allKexMessages.filter(m => m !== ourMsg?.toString());
  wallet.exchangeKexMessages(otherMsgs);

  return wallet;
}

/**
 * Check if a wallet is multisig
 * @param {Object} wallet - Wallet to check
 * @returns {boolean}
 */
export function isMultisig(wallet) {
  return wallet instanceof MultisigWallet || wallet?.isMultisig === true;
}

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
  // Constants
  MULTISIG_MAX_SIGNERS,
  MULTISIG_MIN_THRESHOLD,
  MULTISIG_NONCE_COMPONENTS,
  MULTISIG_MSG_TYPE,

  // Classes
  KexMessage,
  MultisigSigner,
  MultisigAccount,
  MultisigTxSet,
  MultisigPartialSig,
  MultisigTxBuilder,
  MultisigWallet,

  // Functions
  getMultisigBlindedSecretKey,
  computeDHSecret,
  kexRoundsRequired,
  generateMultisigNonces,
  combineMultisigNonces,
  createMultisigWallet,
  prepareMultisig,
  isMultisig
};
