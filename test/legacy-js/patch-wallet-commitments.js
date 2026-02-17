#!/usr/bin/env bun
/**
 * Patch existing wallet cache: recompute CARROT commitments using
 * the try-both-enote-types logic (PAYMENT=0, CHANGE=1).
 *
 * This avoids a full resync by fixing commitment data in-place.
 */

import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
import { commit } from '../src/crypto/index.js';
import { deriveCarrotCommitmentMask } from '../src/carrot-scanning.js';

function hexToBytes(hex) {
  if (typeof hex !== 'string') return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const CACHE_FILE = '/home/mxhess/testnet-wallet/wallet-a-sync.json';
const raw = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
const storage = new MemoryStorage();
storage.load(raw);

const allOutputs = await storage.getOutputs({ isSpent: false });
console.log(`Total outputs: ${allOutputs.length}`);

let patched = 0, alreadyOk = 0, noData = 0;

for (const o of allOutputs) {
  if (!o.isCarrot || !o.mask || !o.carrotSharedSecret) {
    noData++;
    continue;
  }

  const maskBytes = hexToBytes(o.mask);
  const sharedSecret = hexToBytes(o.carrotSharedSecret);

  // If we have a stored commitment from outPk, verify against it
  // and determine enote type. Otherwise compute from mask.
  if (o.commitment) {
    const stored = o.commitment;
    const computedPayment = bytesToHex(commit(BigInt(o.amount), maskBytes));
    if (computedPayment === stored) {
      alreadyOk++;
      continue;
    }
    // Current mask (enoteType=0) doesn't match. Need to find the right address spend pubkey
    // to recompute with enoteType=1. But we don't store addressSpendPubkey...
    // We need to re-derive the mask with enoteType=1.
  }

  // We need addressSpendPubkey to derive the mask. It's not stored directly,
  // but we can get it from the wallet keys (account spend pubkey for main address).
  // For now, skip outputs we can't fix without the pubkey.
}

// Actually, we need the wallet keys to re-derive masks. Let me load them.
const walletJson = JSON.parse(readFileSync('/home/mxhess/testnet-wallet/wallet-a.json', 'utf-8'));
const accountSpendPubkey = hexToBytes(
  walletJson.carrotKeys?.accountSpendPubkey || walletJson.spendPublicKey
);

patched = 0; alreadyOk = 0; noData = 0;
let changetype = 0;

for (const o of allOutputs) {
  if (!o.isCarrot || !o.mask || !o.carrotSharedSecret) {
    noData++;
    continue;
  }

  const sharedSecret = hexToBytes(o.carrotSharedSecret);

  // Try PAYMENT (0) first
  const maskPayment = deriveCarrotCommitmentMask(sharedSecret, BigInt(o.amount), accountSpendPubkey, 0);
  const commitPayment = bytesToHex(commit(BigInt(o.amount), maskPayment));

  if (o.commitment && commitPayment === o.commitment) {
    alreadyOk++;
    continue;
  }

  // Try CHANGE (1)
  const maskChange = deriveCarrotCommitmentMask(sharedSecret, BigInt(o.amount), accountSpendPubkey, 1);
  const commitChange = bytesToHex(commit(BigInt(o.amount), maskChange));

  if (o.commitment && commitChange === o.commitment) {
    // It's a CHANGE output - update mask and enoteType
    changetype++;
    patched++;
    continue; // just count for now
  }

  // No blockchain commitment stored (coinbase) - compute one
  if (!o.commitment) {
    // For coinbase CARROT, use PAYMENT type (miners always create payment outputs)
    patched++;
    continue;
  }

  // Neither matched and we have a commitment - something else is wrong
  console.log(`  NEITHER MATCHED: ${o.txHash.slice(0,16)}... idx=${o.outputIndex} amount=${o.amount}`);
}

console.log(`\nResults:`);
console.log(`  Already correct (PAYMENT): ${alreadyOk}`);
console.log(`  CHANGE type outputs: ${changetype}`);
console.log(`  Need patching (coinbase/no commitment): ${patched - changetype}`);
console.log(`  No CARROT data: ${noData}`);
console.log(`  Total patched: ${patched}`);
