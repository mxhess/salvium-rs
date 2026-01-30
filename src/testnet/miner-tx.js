/**
 * Miner Transaction Construction
 *
 * Ports construct_miner_tx() from cryptonote_tx_utils.cpp
 * Creates coinbase transactions that pay block rewards to the miner.
 * Supports both legacy CryptoNote (HF < 10) and CARROT (HF >= 10) formats.
 *
 * Also provides createEmptyProtocolTransaction() for the required
 * protocol TX in each Salvium block.
 *
 * @module testnet/miner-tx
 */

import { randomScalar, scalarMultBase } from '../ed25519.js';
import { generateKeyDerivation, derivePublicKey, deriveViewTag } from '../scanning.js';
import { cnFastHash } from '../keccak.js';
import { serializeTxPrefix, encodeVarint } from '../transaction/serialization.js';
import { bytesToHex, hexToBytes } from '../address.js';
import { TX_TYPE, RCT_TYPE } from '../transaction/constants.js';
import { CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, HF_VERSION } from '../consensus.js';
import { createCarrotOutput, buildCoinbaseInputContext } from '../transaction/carrot-output.js';
import { makeInputContextCoinbase } from '../carrot-scanning.js';

/**
 * Create a miner (coinbase) transaction
 *
 * Port of construct_miner_tx() from cryptonote_tx_utils.cpp:460-633
 * Uses CARROT output format for HF >= 10, legacy CryptoNote otherwise.
 *
 * @param {number} height - Block height
 * @param {bigint} reward - Block reward in atomic units
 * @param {string} viewPublicKey - Miner's view public key (hex) - legacy K_v or CARROT K^0_v
 * @param {string} spendPublicKey - Miner's spend public key (hex) - legacy B or CARROT K_s
 * @param {number} hfVersion - Hard fork version active at this height
 * @returns {{ tx: Object, txHash: Uint8Array, txSecretKey: Uint8Array }}
 */
export function createMinerTransaction(height, reward, viewPublicKey, spendPublicKey, hfVersion) {
  // Stake deduction: 20% of reward burnt (post-genesis)
  const amountBurnt = height > 0 ? reward / 5n : 0n;
  const outputAmount = reward - amountBurnt;

  if (hfVersion >= HF_VERSION.CARROT) {
    return _createCarrotMinerTx(height, outputAmount, amountBurnt, viewPublicKey, spendPublicKey);
  }
  return _createLegacyMinerTx(height, outputAmount, amountBurnt, viewPublicKey, spendPublicKey);
}

/**
 * Create legacy CryptoNote-style coinbase TX (HF < 10)
 * @private
 */
function _createLegacyMinerTx(height, outputAmount, amountBurnt, viewPublicKey, spendPublicKey) {
  const txSecretKey = randomScalar();
  const txPubKeyBytes = scalarMultBase(txSecretKey);
  const txPubKeyHex = bytesToHex(new Uint8Array(txPubKeyBytes));

  // Derive one-time output key: P = H_s(8*r*V, 0)*G + S
  const txSecretKeyHex = bytesToHex(new Uint8Array(txSecretKey));
  const senderDerivation = generateKeyDerivation(viewPublicKey, txSecretKeyHex);
  const outputKey = derivePublicKey(senderDerivation, 0, spendPublicKey);
  const viewTag = deriveViewTag(senderDerivation, 0);

  const tx = {
    version: 2,
    unlockTime: BigInt(height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW),
    txType: TX_TYPE.MINER,
    inputs: [{ type: 'gen', height }],
    outputs: [{
      amount: outputAmount,
      target: bytesToHex(outputKey),
      viewTag,
    }],
    extra: { txPubKey: txPubKeyHex },
    amount_burnt: amountBurnt,
    source_asset_type: 'SAL',
    destination_asset_type: 'SAL',
  };

  const prefixBytes = serializeTxPrefix(tx);
  const txHash = cnFastHash(prefixBytes);
  tx.rct_signatures = { type: RCT_TYPE.Null };
  tx._isCarrot = false;

  return { tx, txHash, txSecretKey: new Uint8Array(txSecretKey) };
}

/**
 * Create CARROT-format coinbase TX (HF >= 10)
 *
 * Port of the CARROT path in construct_miner_tx() (cryptonote_tx_utils.cpp:483-553)
 * Uses createCarrotOutput() with coinbase input context.
 *
 * @private
 */
function _createCarrotMinerTx(height, outputAmount, amountBurnt, viewPublicKey, spendPublicKey) {
  // Build coinbase input context: 'C' || block_height (33 bytes, matching scanning side)
  const inputContext = makeInputContextCoinbase(height);

  const addressSpendPubkey = hexToBytes(spendPublicKey);
  const addressViewPubkey = hexToBytes(viewPublicKey);

  // Create CARROT output
  const carrotOutput = createCarrotOutput({
    addressSpendPubkey,
    addressViewPubkey,
    amount: outputAmount,
    inputContext,
    isSubaddress: false,
    isCoinbase: true,
  });

  // Build the transaction (version 4 for CARROT)
  const ephPubHex = bytesToHex(carrotOutput.ephemeralPubkey);
  const onetimeHex = bytesToHex(carrotOutput.onetimeAddress);
  const viewTagHex = bytesToHex(carrotOutput.viewTag);
  const anchorEncHex = bytesToHex(carrotOutput.anchorEncrypted);

  const tx = {
    version: 4,
    unlockTime: BigInt(height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW),
    txType: TX_TYPE.MINER,
    inputs: [{ type: 'gen', height }],
    outputs: [{
      amount: outputAmount,
      target: onetimeHex,
      viewTag: carrotOutput.viewTag, // 3-byte Uint8Array for CARROT
      anchorEncrypted: anchorEncHex,
      isCarrot: true,
    }],
    extra: { txPubKey: ephPubHex },
    amount_burnt: amountBurnt,
    source_asset_type: 'SAL',
    destination_asset_type: 'SAL',
  };

  const prefixBytes = serializeTxPrefix(tx);
  const txHash = cnFastHash(prefixBytes);
  tx.rct_signatures = { type: RCT_TYPE.Null };
  tx._isCarrot = true;
  tx._ephemeralPubkey = ephPubHex;

  // Use a dummy tx secret key (CARROT uses ephemeral keys, not a single tx secret)
  const dummySecretKey = new Uint8Array(32);

  return { tx, txHash, txSecretKey: dummySecretKey };
}

/**
 * Create an empty protocol transaction (type 2)
 *
 * Every Salvium block contains a protocol TX alongside the miner TX.
 * For our testnet it has no outputs and zero burnt amount.
 *
 * @param {number} height - Block height
 * @returns {{ tx: Object, txHash: Uint8Array }}
 */
export function createEmptyProtocolTransaction(height) {
  const tx = {
    version: 2,
    unlockTime: 0n,
    txType: TX_TYPE.PROTOCOL,
    inputs: [{ type: 'gen', height }],
    outputs: [],
    extra: {},
    amount_burnt: 0n,
  };

  const prefixBytes = serializeTxPrefix(tx);
  const txHash = cnFastHash(prefixBytes);
  tx.rct_signatures = { type: RCT_TYPE.Null };

  return { tx, txHash };
}
