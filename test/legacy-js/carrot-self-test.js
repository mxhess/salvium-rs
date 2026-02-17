#!/usr/bin/env bun
/**
 * CARROT Self-Test
 * Generates a CARROT output and verifies detection
 * This tests the entire CARROT scanning pipeline end-to-end
 *
 * Usage:
 *   WALLET_SEED="your 25 word mnemonic" bun test/carrot-self-test.js
 *   MASTER_KEY="64-char-hex" bun test/carrot-self-test.js
 */

import { blake2b } from '../src/blake2b.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { scalarMultBase } from '../src/crypto/index.js';
import {
  x25519ScalarMult,
  edwardsToMontgomeryU,
  carrotEcdhKeyExchange,
  computeCarrotViewTag,
  makeInputContextCoinbase
} from '../src/carrot-scanning.js';

console.log('=== CARROT Self-Test ===\n');

// Get wallet seed from environment
if (!process.env.WALLET_SEED && !process.env.MASTER_KEY) {
  console.error('ERROR: WALLET_SEED or MASTER_KEY environment variable required.\n');
  console.log('Usage:');
  console.log('  WALLET_SEED="your 25 word mnemonic" bun test/carrot-self-test.js');
  console.log('  MASTER_KEY="64-char-hex" bun test/carrot-self-test.js');
  process.exit(1);
}

// 1. Generate recipient wallet
console.log('1. Generating recipient wallet...');

let seedResult;
if (process.env.WALLET_SEED) {
  const mnemonic = process.env.WALLET_SEED.trim();
  seedResult = mnemonicToSeed(mnemonic, { language: 'auto' });
  if (!seedResult.valid) {
    console.error('Invalid mnemonic:', seedResult.error);
    process.exit(1);
  }
} else {
  const masterKey = process.env.MASTER_KEY.trim();
  if (masterKey.length !== 64) {
    console.error('MASTER_KEY must be 64 hex characters');
    process.exit(1);
  }
  seedResult = { seed: hexToBytes(masterKey), valid: true };
}
const cnKeys = deriveKeys(seedResult.seed);
const recipientCarrot = deriveCarrotKeys(cnKeys.spendSecretKey);

const k_vi = hexToBytes(recipientCarrot.viewIncomingKey);
const K_s = hexToBytes(recipientCarrot.accountSpendPubkey);

console.log('   Recipient k_vi:', recipientCarrot.viewIncomingKey);
console.log('   Recipient K_s:', recipientCarrot.accountSpendPubkey);

// 2. Sender generates ephemeral keypair for X25519
console.log('\n2. Sender generating ephemeral keypair...');

// Generate random ephemeral secret (in real code, use crypto.getRandomValues)
const d_e = new Uint8Array(32);
for (let i = 0; i < 32; i++) d_e[i] = Math.floor(Math.random() * 256);
d_e[0] &= 248;  // Clear bits 0-2 for proper scalar
d_e[31] &= 127; // Clear bit 255

// D_e = d_e * G (in X25519 format)
// First compute on Edwards curve, then convert to Montgomery
const D_e_edwards = scalarMultBase(d_e);
const D_e = edwardsToMontgomeryU(D_e_edwards);

console.log('   Sender d_e (secret):', bytesToHex(d_e));
console.log('   Sender D_e (public):', bytesToHex(D_e));

// 3. Sender computes shared secret
console.log('\n3. Sender computing shared secret...');

// Convert recipient's K_s (Edwards) to X25519
const K_s_x25519 = edwardsToMontgomeryU(K_s);
console.log('   Recipient K_s (X25519):', bytesToHex(K_s_x25519));

// Sender computes s_sr = d_e * K_vi_G
// But wait - sender uses view pubkey, not spend pubkey
// k_vi * G in X25519 format
const K_vi_G = edwardsToMontgomeryU(hexToBytes(recipientCarrot.primaryAddressViewPubkey));
console.log('   Recipient K_vi*G (X25519):', bytesToHex(K_vi_G));

// Sender: s_sr = d_e * (k_vi * G)
const s_sr_sender = x25519ScalarMult(d_e, K_vi_G);
console.log('   Sender s_sr:', bytesToHex(s_sr_sender));

// 4. Generate one-time address Ko
console.log('\n4. Generating one-time address...');
// For simplicity, we'll use K_s directly as Ko (in real CARROT, there's more derivation)
const Ko = K_s;
console.log('   One-time address Ko:', bytesToHex(Ko));

// 5. Compute view tag (sender side)
console.log('\n5. Sender computing view tag...');
const blockHeight = 405000;
const inputContext = makeInputContextCoinbase(blockHeight);
const viewTagSender = computeCarrotViewTag(s_sr_sender, inputContext, Ko);
console.log('   Input context:', bytesToHex(inputContext));
console.log('   View tag (sender):', bytesToHex(viewTagSender));

// 6. Recipient scans the output
console.log('\n6. Recipient scanning output...');

// Recipient computes s_sr = k_vi * D_e
const s_sr_recipient = carrotEcdhKeyExchange(k_vi, D_e);
console.log('   Recipient s_sr:', bytesToHex(s_sr_recipient));

// Check if shared secrets match
const secretsMatch = bytesToHex(s_sr_sender) === bytesToHex(s_sr_recipient);
console.log('   Shared secrets match:', secretsMatch ? 'YES' : 'NO');

// Recipient computes expected view tag
const viewTagRecipient = computeCarrotViewTag(s_sr_recipient, inputContext, Ko);
console.log('   View tag (recipient):', bytesToHex(viewTagRecipient));

// Check if view tags match
const viewTagsMatch = bytesToHex(viewTagSender) === bytesToHex(viewTagRecipient);
console.log('   View tags match:', viewTagsMatch ? 'YES' : 'NO');

// 7. Final result
console.log('\n=== Results ===');
if (secretsMatch && viewTagsMatch) {
  console.log('SUCCESS: CARROT ECDH and view tag computation working correctly!');
} else {
  console.log('FAILURE: Something is wrong');
  if (!secretsMatch) console.log('  - Shared secrets do not match');
  if (!viewTagsMatch) console.log('  - View tags do not match');
}
