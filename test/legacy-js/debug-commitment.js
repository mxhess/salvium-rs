#!/usr/bin/env bun
/**
 * Debug script to investigate why stored mask + amount doesn't produce stored commitment
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
import {
  generateKeyDerivation,
  genCommitmentMask,
  computeSharedSecret,
  ecdhDecodeFull,
  commit
} from '../src/crypto/index.js';

function hexToBytes(hex) {
  if (typeof hex !== 'string') return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const walletAJson = JSON.parse(readFileSync('/home/mxhess/testnet-wallet/wallet-a.json', 'utf-8'));
const keysA = {
  viewSecretKey: walletAJson.viewSecretKey,
  spendSecretKey: walletAJson.spendSecretKey,
  viewPublicKey: walletAJson.viewPublicKey,
  spendPublicKey: walletAJson.spendPublicKey,
  address: walletAJson.address,
  generateImageKey: walletAJson.generateImageKey || null,
};

// Load cached sync state
const CACHE_FILE = '/home/mxhess/testnet-wallet/wallet-a-sync.json';
const storage = new MemoryStorage();
try {
  const cached = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
  storage.load(cached);
} catch {
  console.log('No cached wallet state - run test/integration-transfer.test.js first');
  process.exit(1);
}

// Get a few unspent outputs to analyze
const allOutputs = await storage.getOutputs({ isSpent: false });
console.log(`Total unspent outputs: ${allOutputs.length}`);

// Group by asset type
const byAsset = {};
for (const o of allOutputs) {
  const asset = o.assetType || 'SAL';
  byAsset[asset] = (byAsset[asset] || 0) + 1;
}
console.log('By asset:', byAsset);

// Get non-CARROT outputs
const nonCarrot = allOutputs.filter(o => !o.isCarrot);
console.log(`Non-CARROT outputs: ${nonCarrot.length}`);

// Analyze some outputs
console.log('\n=== Analyzing commitment computation ===\n');

// Fetch raw transaction for a non-CARROT output
for (let idx = 0; idx < Math.min(5, nonCarrot.length); idx++) {
  const output = nonCarrot[idx];
  console.log(`\n--- Output ${idx} ---`);
  console.log(`  txHash: ${output.txHash.slice(0, 16)}...`);
  console.log(`  outputIndex: ${output.outputIndex}`);
  console.log(`  amount: ${output.amount}`);
  console.log(`  isCarrot: ${output.isCarrot}`);
  console.log(`  stored mask: ${output.mask ? output.mask.slice(0, 32) + '...' : 'null'}`);
  console.log(`  stored commitment: ${output.commitment ? output.commitment.slice(0, 32) + '...' : 'null'}`);

  if (!output.mask || !output.commitment) {
    console.log('  Skipping - missing mask or commitment');
    continue;
  }

  // Compute commitment from mask + amount
  const maskBytes = hexToBytes(output.mask);
  const amountBig = BigInt(output.amount);
  const computedCommitment = commit(amountBig, maskBytes);
  const storedCommitment = hexToBytes(output.commitment);

  console.log(`  computed commitment: ${bytesToHex(computedCommitment).slice(0, 32)}...`);
  console.log(`  commitment match: ${bytesToHex(computedCommitment) === bytesToHex(storedCommitment)}`);

  // Fetch raw TX from daemon to verify
  try {
    const txResp = await daemon.getTransactions([output.txHash], true, false);
    const txData = txResp.result?.txs?.[0];
    if (txData?.as_json) {
      const txJson = JSON.parse(txData.as_json);
      const outPk = txJson.rct_signatures?.outPk;
      const ecdhInfo = txJson.rct_signatures?.ecdhInfo;

      console.log(`  rctType: ${txJson.rct_signatures?.type}`);
      console.log(`  txPubKey: ${txJson.extra ? 'present' : 'missing'}`);

      if (outPk && outPk[output.outputIndex]) {
        const blockchainCommitment = outPk[output.outputIndex];
        console.log(`  blockchain outPk[${output.outputIndex}]: ${blockchainCommitment.slice(0, 32)}...`);
        console.log(`  outPk matches stored: ${blockchainCommitment === output.commitment}`);
      }

      if (ecdhInfo && ecdhInfo[output.outputIndex]) {
        const ecdh = ecdhInfo[output.outputIndex];
        console.log(`  ecdhInfo[${output.outputIndex}].amount: ${ecdh.amount?.slice(0, 16)}...`);
      }

      // Try to re-derive the mask from the txPubKey
      if (txJson.extra) {
        // Parse tx extra to get txPubKey
        const extraHex = Array.isArray(txJson.extra)
          ? txJson.extra.map(b => b.toString(16).padStart(2, '0')).join('')
          : txJson.extra;
        const extraBytes = hexToBytes(extraHex);

        // Simple parsing - txPubKey is usually at offset 1 (after 0x01 tag)
        if (extraBytes[0] === 0x01 && extraBytes.length >= 33) {
          const txPubKey = extraBytes.slice(1, 33);
          console.log(`  txPubKey: ${bytesToHex(txPubKey).slice(0, 32)}...`);

          // Derive shared secret and mask
          const viewSecKey = hexToBytes(keysA.viewSecretKey);
          const derivation = generateKeyDerivation(txPubKey, viewSecKey);
          console.log(`  derivation: ${bytesToHex(derivation).slice(0, 32)}...`);

          const sharedSecret = computeSharedSecret(derivation, output.outputIndex);
          console.log(`  sharedSecret: ${bytesToHex(sharedSecret).slice(0, 32)}...`);

          const derivedMask = genCommitmentMask(sharedSecret);
          console.log(`  derived mask: ${bytesToHex(derivedMask).slice(0, 32)}...`);
          console.log(`  mask matches stored: ${bytesToHex(derivedMask) === output.mask}`);

          // Decrypt amount
          const encryptedAmount = hexToBytes(ecdhInfo[output.outputIndex].amount);
          const decoded = ecdhDecodeFull(encryptedAmount, sharedSecret);
          console.log(`  decrypted amount: ${decoded.amount}`);
          console.log(`  amount matches stored: ${decoded.amount === BigInt(output.amount)}`);

          // Compute commitment with derived values
          const computedFromDerived = commit(decoded.amount, decoded.mask);
          console.log(`  commitment from derived: ${bytesToHex(computedFromDerived).slice(0, 32)}...`);
          console.log(`  derived commitment matches blockchain: ${bytesToHex(computedFromDerived) === blockchainCommitment}`);
        }
      }
    }
  } catch (e) {
    console.log(`  Error fetching TX: ${e.message}`);
  }
}

// Also check a CARROT output
const carrotOutputs = allOutputs.filter(o => o.isCarrot);
if (carrotOutputs.length > 0) {
  console.log('\n=== CARROT Output Analysis ===\n');
  const output = carrotOutputs[0];
  console.log(`  txHash: ${output.txHash.slice(0, 16)}...`);
  console.log(`  outputIndex: ${output.outputIndex}`);
  console.log(`  amount: ${output.amount}`);
  console.log(`  stored mask: ${output.mask ? output.mask.slice(0, 32) + '...' : 'null'}`);
  console.log(`  stored commitment: ${output.commitment ? output.commitment.slice(0, 32) + '...' : 'null'}`);

  if (output.mask && output.commitment) {
    const maskBytes = hexToBytes(output.mask);
    const amountBig = BigInt(output.amount);
    const computedCommitment = commit(amountBig, maskBytes);
    console.log(`  computed commitment: ${bytesToHex(computedCommitment).slice(0, 32)}...`);
    console.log(`  commitment match: ${bytesToHex(computedCommitment) === output.commitment}`);
  }
}
