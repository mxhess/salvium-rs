#!/usr/bin/env bun
/**
 * Independently verify that accountSpendPubkey = k_gi*G + k_ps*T
 * and that all wallet keys are consistent.
 */
import { setCryptoBackend, scalarMultBase, scalarMultPoint, pointAddCompressed } from '../src/crypto/index.js';
import { getGeneratorT } from '../src/crypto/provider.js';
import { readFileSync } from 'fs';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const w = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a.json`, 'utf-8'));

const k_gi = hexToBytes(w.carrotKeys.generateImageKey);
const k_ps = hexToBytes(w.carrotKeys.proveSpendKey);
const k_vi = hexToBytes(w.carrotKeys.viewIncomingKey);
const T = getGeneratorT();

console.log('=== Secret keys ===');
console.log(`k_gi (generateImageKey): ${w.carrotKeys.generateImageKey}`);
console.log(`k_ps (proveSpendKey):    ${w.carrotKeys.proveSpendKey}`);
console.log(`k_vi (viewIncomingKey):  ${w.carrotKeys.viewIncomingKey}`);
console.log(`T generator: ${bytesToHex(T)}`);

// Compute K_s = k_gi*G + k_ps*T
const giG = scalarMultBase(k_gi);
const psT = scalarMultPoint(k_ps, T);
const computedKs = pointAddCompressed(giG, psT);

console.log('\n=== Account Spend Pubkey (K_s) ===');
console.log(`Computed: ${bytesToHex(computedKs)}`);
console.log(`Stored:   ${w.carrotKeys.accountSpendPubkey}`);
console.log(`Match:    ${bytesToHex(computedKs) === w.carrotKeys.accountSpendPubkey}`);

// Also check: K^0_v = scalarMultBase(k_vi) [X25519 not Ed25519!]
// But wait - primaryAddressViewPubkey in CARROT is computed differently
// K^0_v = ConvertPointX(k_vi * G) where ConvertPointX converts Ed25519 to X25519
// Actually, for CARROT, the view pubkey might use X25519 convention
const computedView = scalarMultBase(k_vi);
console.log('\n=== View pubkeys ===');
console.log(`k_vi*G (Ed25519):       ${bytesToHex(computedView)}`);
console.log(`primaryAddressViewPub:  ${w.carrotKeys.primaryAddressViewPubkey}`);

// Check CryptoNote keys
if (w.spendSecretKey) {
  const cnSpendPub = scalarMultBase(hexToBytes(w.spendSecretKey));
  console.log('\n=== CryptoNote keys ===');
  console.log(`CN spend pub computed: ${bytesToHex(cnSpendPub)}`);
  console.log(`CN spend pub stored:   ${w.spendPublicKey}`);
  console.log(`Match: ${bytesToHex(cnSpendPub) === w.spendPublicKey}`);
}
if (w.viewSecretKey) {
  const cnViewPub = scalarMultBase(hexToBytes(w.viewSecretKey));
  console.log(`CN view pub computed: ${bytesToHex(cnViewPub)}`);
  console.log(`CN view pub stored:   ${w.viewPublicKey}`);
  console.log(`Match: ${bytesToHex(cnViewPub) === w.viewPublicKey}`);
}

// Now check the C++ T point
// The Seraphis T point should be: hash_to_point("seraphis_T")
// or similar domain-specific generation
import { hashToPoint, keccak256 } from '../src/crypto/index.js';
console.log('\n=== T point verification ===');
console.log(`Our T: ${bytesToHex(T)}`);

// Try various domain separators for T
const domains = [
  'seraphis_T',
  'seraphis T',
  'Seraphis T',
  'sp_T',
  'salvium_T',
];
for (const d of domains) {
  const dBytes = new TextEncoder().encode(d);
  try {
    const tCandidate = hashToPoint(keccak256(dBytes));
    console.log(`hashToPoint(keccak256("${d}")): ${bytesToHex(tCandidate)}`);
  } catch (e) {
    console.log(`hashToPoint(keccak256("${d}")): error - ${e.message}`);
  }
}

// Check our CARROT address encoding
console.log('\n=== CARROT address ===');
console.log(`Address: ${w.carrotAddress}`);
