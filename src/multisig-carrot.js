/**
 * Multisig CARROT Integration
 *
 * Extends generic multisig support with CARROT-specific key derivation,
 * payment proposals, and transaction proposal structures.
 *
 * Note: The Salvium C++ source has multisig+CARROT integration STUBBED
 * (assert(false) in multisig_tx_builder_ringct.cpp). This module implements
 * the key derivation and proposal infrastructure that IS mathematically
 * defined, and stubs protocol-dependent operations with clear errors.
 *
 * @module multisig-carrot
 */

import { bytesToHex, hexToBytes } from './address.js';
import {
  keccak256, scalarMultBase, scalarMultPoint, pointAddCompressed, scAdd,
  computeCarrotSpendPubkey, computeCarrotMainAddressViewPubkey, computeCarrotAccountViewPubkey,
} from './crypto/index.js';
import { MultisigAccount } from './multisig.js';
import {
  makeViewBalanceSecret,
  makeViewIncomingKey,
  makeProveSpendKey,
  makeGenerateImageKey,
  makeGenerateAddressSecret
} from './carrot.js';
import { createAddress, generateCarrotSubaddress } from './address.js';

// =============================================================================
// ENOTE TYPES (from C++ carrot_core/carrot_enote_types.h)
// =============================================================================

export const CARROT_ENOTE_TYPE = {
  PAYMENT: 0,
  CHANGE: 1,
  SELF_SPEND: 2
};

// =============================================================================
// PAYMENT PROPOSAL
// =============================================================================

/**
 * A CARROT payment proposal - specifies a single output.
 * Matches C++ CarrotPaymentProposalV1.
 */
export class CarrotPaymentProposal {
  /**
   * @param {Object} config
   * @param {string} config.destination - CARROT address string
   * @param {bigint} config.amount - Amount in atomic units
   * @param {string} [config.assetType='SAL'] - Asset type
   * @param {boolean} [config.isSubaddress=false] - Whether destination is a subaddress
   */
  constructor(config = {}) {
    this.destination = config.destination || '';
    this.amount = config.amount ?? 0n;
    this.assetType = config.assetType || 'SAL';
    this.isSubaddress = config.isSubaddress ?? false;
  }

  /**
   * Serialize to JSON-compatible object
   * @returns {Object}
   */
  toJSON() {
    return {
      destination: this.destination,
      amount: this.amount.toString(),
      assetType: this.assetType,
      isSubaddress: this.isSubaddress
    };
  }

  /**
   * Deserialize from JSON-compatible object
   * @param {Object} json
   * @returns {CarrotPaymentProposal}
   */
  static fromJSON(json) {
    return new CarrotPaymentProposal({
      destination: json.destination,
      amount: BigInt(json.amount),
      assetType: json.assetType,
      isSubaddress: json.isSubaddress
    });
  }
}

// =============================================================================
// TRANSACTION PROPOSAL
// =============================================================================

/**
 * A CARROT transaction proposal - complete unsigned transaction specification.
 * Matches C++ CarrotTransactionProposalV1.
 *
 * This structure is passed between multisig signers so each can verify
 * what they're signing before producing partial signatures.
 */
export class CarrotTransactionProposal {
  constructor() {
    this.paymentProposals = [];
    this.selfSendProposals = [];
    this.fee = 0n;
    this.txType = 3; // TX_TYPE.TRANSFER default
    this.extra = new Uint8Array(0);
  }

  /**
   * Add a normal payment output
   * @param {string} destination - CARROT address
   * @param {bigint} amount - Amount in atomic units
   * @param {string} [assetType='SAL']
   * @param {boolean} [isSubaddress=false]
   */
  addPayment(destination, amount, assetType = 'SAL', isSubaddress = false) {
    this.paymentProposals.push(new CarrotPaymentProposal({
      destination,
      amount,
      assetType,
      isSubaddress
    }));
  }

  /**
   * Add a self-send output (change or self-spend)
   * @param {string} destination - Own CARROT address
   * @param {bigint} amount - Amount in atomic units
   * @param {number} [enoteType=CARROT_ENOTE_TYPE.CHANGE]
   */
  addSelfSend(destination, amount, enoteType = CARROT_ENOTE_TYPE.CHANGE) {
    this.selfSendProposals.push(new CarrotPaymentProposal({
      destination,
      amount,
      assetType: 'SAL',
      isSubaddress: false,
      enoteType
    }));
  }

  /**
   * Get total output amount (excluding fee)
   * @returns {bigint}
   */
  getTotalAmount() {
    let total = 0n;
    for (const p of this.paymentProposals) total += p.amount;
    for (const p of this.selfSendProposals) total += p.amount;
    return total;
  }

  /**
   * Compute deterministic hash for signing
   * All signers compute the same hash from the same proposal.
   * @returns {Uint8Array} 32-byte signable hash
   */
  getSignableHash() {
    const data = JSON.stringify(this.toJSON());
    return keccak256(new TextEncoder().encode(data));
  }

  /**
   * Serialize to JSON-compatible object
   * @returns {Object}
   */
  toJSON() {
    return {
      paymentProposals: this.paymentProposals.map(p => p.toJSON()),
      selfSendProposals: this.selfSendProposals.map(p => p.toJSON()),
      fee: this.fee.toString(),
      txType: this.txType,
      extra: bytesToHex(this.extra)
    };
  }

  /**
   * Deserialize from JSON-compatible object
   * @param {Object} json
   * @returns {CarrotTransactionProposal}
   */
  static fromJSON(json) {
    const proposal = new CarrotTransactionProposal();
    proposal.paymentProposals = json.paymentProposals.map(p => CarrotPaymentProposal.fromJSON(p));
    proposal.selfSendProposals = json.selfSendProposals.map(p => CarrotPaymentProposal.fromJSON(p));
    proposal.fee = BigInt(json.fee);
    proposal.txType = json.txType;
    proposal.extra = json.extra ? hexToBytes(json.extra) : new Uint8Array(0);
    return proposal;
  }
}

// =============================================================================
// MULTISIG CARROT ACCOUNT
// =============================================================================

/**
 * CARROT-specific multisig account.
 * Extends MultisigAccount with CARROT key derivation after KEX completes.
 *
 * After key exchange is finalized, each participant derives CARROT keys
 * from the shared multisig base keys, enabling CARROT address generation.
 */
export class MultisigCarrotAccount extends MultisigAccount {
  constructor(config = {}) {
    super(config);

    // CARROT keys (derived after KEX)
    this.carrotKeys = null;
  }

  /**
   * Derive CARROT keys from the multisig base keys.
   * Must be called after key exchange is complete.
   *
   * Each participant derives the same CARROT keys because they share
   * the same multisig spend/view secret keys after KEX.
   *
   * @returns {Object} Derived CARROT keys
   */
  deriveCarrotKeys() {
    if (!this.kexComplete) {
      throw new Error('Key exchange must be complete before deriving CARROT keys');
    }
    if (!this.multisigSpendSecretKey) {
      throw new Error('Multisig spend secret key not available');
    }

    // The multisig spend secret key serves as the CARROT master secret
    const masterSecret = this.multisigSpendSecretKey;

    // Derive CARROT key hierarchy
    const viewBalanceSecret = makeViewBalanceSecret(masterSecret);
    const proveSpendKey = makeProveSpendKey(masterSecret);
    const viewIncomingKey = makeViewIncomingKey(viewBalanceSecret);
    const generateImageKey = makeGenerateImageKey(viewBalanceSecret);
    const generateAddressSecret = makeGenerateAddressSecret(viewBalanceSecret);

    // Compute account pubkeys
    // K_s = k_gi * G + k_ps * T
    const accountSpendPubkey = computeCarrotSpendPubkey(generateImageKey, proveSpendKey);
    // K^0_v = k_vi * G
    const primaryAddressViewPubkey = computeCarrotMainAddressViewPubkey(viewIncomingKey);
    // K_v = k_vi * K_s
    const accountViewPubkey = computeCarrotAccountViewPubkey(viewIncomingKey, accountSpendPubkey);

    this.carrotKeys = {
      viewBalanceSecret,
      proveSpendKey,
      viewIncomingKey,
      generateImageKey,
      generateAddressSecret,
      accountSpendPubkey,
      primaryAddressViewPubkey,
      accountViewPubkey
    };

    return {
      proveSpendKey: bytesToHex(proveSpendKey),
      viewIncomingKey: bytesToHex(viewIncomingKey),
      generateImageKey: bytesToHex(generateImageKey),
      generateAddressSecret: bytesToHex(generateAddressSecret),
      accountSpendPubkey: bytesToHex(accountSpendPubkey),
      primaryAddressViewPubkey: bytesToHex(primaryAddressViewPubkey),
      accountViewPubkey: bytesToHex(accountViewPubkey)
    };
  }

  /**
   * Get the multisig wallet's CARROT address
   * @param {string} [network='mainnet'] - Network type
   * @returns {string} CARROT address string
   */
  getCarrotAddress(network = 'mainnet') {
    if (!this.carrotKeys) {
      throw new Error('CARROT keys not derived. Call deriveCarrotKeys() first');
    }

    return createAddress({
      network,
      format: 'carrot',
      type: 'standard',
      spendPublicKey: this.carrotKeys.accountSpendPubkey,
      viewPublicKey: this.carrotKeys.primaryAddressViewPubkey
    });
  }

  /**
   * Get a CARROT subaddress for the multisig wallet
   * @param {string} [network='mainnet'] - Network type
   * @param {number} [major=0] - Account index
   * @param {number} [minor=1] - Address index
   * @returns {Object} Subaddress object with address string
   */
  getCarrotSubaddress(network = 'mainnet', major = 0, minor = 1) {
    if (!this.carrotKeys) {
      throw new Error('CARROT keys not derived. Call deriveCarrotKeys() first');
    }

    return generateCarrotSubaddress({
      network,
      accountSpendPubkey: this.carrotKeys.accountSpendPubkey,
      accountViewPubkey: this.carrotKeys.accountViewPubkey,
      generateAddressSecret: this.carrotKeys.generateAddressSecret,
      major,
      minor
    });
  }
}

// =============================================================================
// MULTISIG CARROT TRANSACTION BUILDING (ASPIRATIONAL)
// =============================================================================

/**
 * Build an unsigned CARROT transaction from a proposal using multisig keys.
 *
 * NOTE: This is ASPIRATIONAL. The Salvium C++ source has this functionality
 * STUBBED with `assert(false)` in multisig_tx_builder_ringct.cpp.
 * This function documents the expected interface for when the protocol
 * is fully defined.
 *
 * @param {CarrotTransactionProposal} proposal - Transaction proposal
 * @param {MultisigCarrotAccount} account - Multisig CARROT account
 * @throws {Error} Always - protocol not yet finalized
 */
export function buildMultisigCarrotTx(proposal, account) {
  if (!(proposal instanceof CarrotTransactionProposal)) {
    throw new Error('Expected CarrotTransactionProposal');
  }
  if (!(account instanceof MultisigCarrotAccount)) {
    throw new Error('Expected MultisigCarrotAccount');
  }
  if (!account.carrotKeys) {
    throw new Error('CARROT keys not derived');
  }

  // The following operations would be needed:
  // 1. Generate CARROT enote ephemeral keys (requires coordinator)
  // 2. Compute one-time addresses for each output
  // 3. Build commitment masks from shared secrets
  // 4. Construct RingCT base with pseudo-output commitments
  // 5. Create unsigned transaction structure for partial signing
  //
  // This requires protocol-level support that is not yet implemented
  // in the Salvium C++ codebase (multisig_tx_builder_ringct.cpp has
  // assert(false) for CARROT integration).

  throw new Error(
    'Multisig CARROT transaction building requires protocol support ' +
    'not yet finalized in Salvium. Use CarrotTransactionProposal to ' +
    'prepare proposals for when the protocol is implemented.'
  );
}

/**
 * Generate a multisig CARROT key image for an owned output.
 *
 * NOTE: ASPIRATIONAL - requires aggregation of k_gi key shares
 * across M-of-N participants.
 *
 * @param {MultisigCarrotAccount} account - Multisig account
 * @param {Uint8Array} onetimeAddress - Output one-time address
 * @throws {Error} Always - protocol not yet finalized
 */
export function generateMultisigCarrotKeyImage(account, onetimeAddress) {
  // Would compute: KI = (k_gi * k_subscal + sender_extension_g) * H_p(K_o)
  // With multisig: each participant computes partial KI, then aggregate
  throw new Error(
    'Multisig CARROT key image generation requires protocol support ' +
    'not yet finalized in Salvium.'
  );
}
