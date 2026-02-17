#!/usr/bin/env bun
/**
 * Decode our CARROT address and verify the encoded keys match the wallet.
 */
import { readFileSync } from 'fs';
import { parseAddress } from '../src/address.js';
import { setCryptoBackend } from '../src/crypto/index.js';

await setCryptoBackend('wasm');

const w = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a.json`, 'utf-8'));

console.log('CARROT address:', w.carrotAddress);

try {
  const decoded = parseAddress(w.carrotAddress);
  console.log('\nDecoded address:');
  console.log(JSON.stringify(decoded, null, 2));

  // Check if keys match
  if (decoded.spendPublicKey) {
    console.log(`\nspendPublicKey from address: ${decoded.spendPublicKey}`);
    console.log(`accountSpendPubkey wallet:   ${w.carrotKeys.accountSpendPubkey}`);
    console.log(`Match: ${decoded.spendPublicKey === w.carrotKeys.accountSpendPubkey}`);
  }
  if (decoded.viewPublicKey) {
    console.log(`\nviewPublicKey from address:    ${decoded.viewPublicKey}`);
    console.log(`primaryAddressViewPub wallet: ${w.carrotKeys.primaryAddressViewPubkey}`);
    console.log(`Match: ${decoded.viewPublicKey === w.carrotKeys.primaryAddressViewPubkey}`);
  }
} catch (e) {
  console.log('Error decoding:', e.message);
}

// Also check the CN address
console.log('\n\nCN address:', w.address);
try {
  const decoded = parseAddress(w.address);
  console.log('Decoded CN address:');
  console.log(`spendPublicKey: ${decoded.spendPublicKey}`);
  console.log(`viewPublicKey: ${decoded.viewPublicKey}`);
  console.log(`spendKey match: ${decoded.spendPublicKey === w.spendPublicKey}`);
  console.log(`viewKey match: ${decoded.viewPublicKey === w.viewPublicKey}`);
} catch (e) {
  console.log('Error decoding:', e.message);
}
