#!/usr/bin/env bun
/**
 * Balance Diagnostic Script
 *
 * Runs a full sync then checks all "unspent" output key images against
 * the blockchain via is_key_image_spent to find:
 *   1. False positives (outputs we detected that aren't really ours)
 *   2. Missed spends (our outputs that are spent on-chain but not marked)
 *
 * Usage:
 *   WALLET_SEED="..." bun test/diagnose-balance.js
 *   WALLET_SEED="..." STORAGE_BACKEND=ffi CRYPTO_BACKEND=ffi bun test/diagnose-balance.js
 */

import { createDaemonRPC } from '../src/rpc/index.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { generateCNSubaddressMap, generateCarrotSubaddressMap, SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR } from '../src/subaddress.js';
import { initCrypto, setCryptoBackend, getCurrentBackendType } from '../src/crypto/index.js';

let FfiStorage = null;
if (process.env.STORAGE_BACKEND === 'ffi') {
  FfiStorage = (await import('../src/wallet-store-ffi.js')).FfiStorage;
}

const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';

async function run() {
  // Init crypto
  const requestedBackend = process.env.CRYPTO_BACKEND || 'wasm';
  if (requestedBackend === 'ffi') {
    await setCryptoBackend('ffi');
  } else {
    await initCrypto();
  }
  console.log(`Crypto backend: ${getCurrentBackendType()}`);

  // Get keys
  if (!process.env.WALLET_SEED) {
    console.error('Set WALLET_SEED env var');
    process.exit(1);
  }
  const { seed, valid, error } = mnemonicToSeed(process.env.WALLET_SEED.trim(), { language: 'auto' });
  if (!valid) { console.error('Bad mnemonic:', error); process.exit(1); }
  const keys = deriveKeys(seed);
  const carrotKeys = deriveCarrotKeys(keys.spendSecretKey);

  // Setup daemon
  const daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 30000 });
  const info = await daemon.getInfo();
  if (!info.success) { console.error('Daemon unreachable'); process.exit(1); }
  console.log(`Daemon height: ${info.result.height}`);

  // Setup storage
  const storageBackend = process.env.STORAGE_BACKEND || 'memory';
  let storage;
  if (storageBackend === 'ffi' && FfiStorage) {
    const dbPath = process.env.STORAGE_PATH || '/tmp/salvium-diag.db';
    const keyBytes = new Uint8Array(32);
    storage = new FfiStorage({ path: dbPath, key: keyBytes });
    console.log(`Storage: ffi → ${dbPath}`);
  } else {
    storage = new MemoryStorage();
    console.log('Storage: memory');
  }
  await storage.open();
  await storage.clear();
  await storage.setSyncHeight(0);

  // Subaddress maps
  console.log('Generating subaddress maps...');
  const cnSubaddresses = generateCNSubaddressMap(
    keys.spendPublicKey, keys.viewSecretKey,
    SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR
  );
  const carrotSubaddresses = generateCarrotSubaddressMap(
    hexToBytes(carrotKeys.accountSpendPubkey),
    hexToBytes(carrotKeys.accountViewPubkey),
    hexToBytes(carrotKeys.generateAddressSecret),
    SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR
  );
  console.log(`  CN: ${cnSubaddresses.size}, CARROT: ${carrotSubaddresses.size}`);

  // Setup sync
  const sync = new WalletSync({
    storage, daemon,
    keys: {
      viewSecretKey: keys.viewSecretKey,
      spendPublicKey: keys.spendPublicKey,
      spendSecretKey: keys.spendSecretKey
    },
    carrotKeys: {
      viewIncomingKey: hexToBytes(carrotKeys.viewIncomingKey),
      accountSpendPubkey: hexToBytes(carrotKeys.accountSpendPubkey),
      generateImageKey: hexToBytes(carrotKeys.generateImageKey),
      generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
      viewBalanceSecret: hexToBytes(carrotKeys.viewBalanceSecret)
    },
    subaddresses: cnSubaddresses,
    carrotSubaddresses,
    batchSize: 100
  });

  // Progress
  let lastH = 0;
  sync.on('syncProgress', (d) => {
    if (d.currentHeight - lastH >= 5000) {
      console.log(`  Height ${d.currentHeight} (${d.percentComplete.toFixed(1)}%)`);
      lastH = d.currentHeight;
    }
  });

  // Run sync
  console.log('\nSyncing...');
  const t0 = Date.now();
  await sync.start(0);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`Sync complete in ${elapsed}s`);

  // Get all outputs
  const outputs = await storage.getOutputs();
  const syncHeight = await storage.getSyncHeight();

  // Separate by spent status
  const unspent = outputs.filter(o => !o.isSpent);
  const spent = outputs.filter(o => o.isSpent);

  console.log(`\n${'='.repeat(60)}`);
  console.log('OUTPUT SUMMARY');
  console.log(`${'='.repeat(60)}`);
  console.log(`Total outputs:   ${outputs.length}`);
  console.log(`Spent:           ${spent.length}`);
  console.log(`Unspent:         ${unspent.length}`);

  // Group by asset type
  const byAsset = {};
  for (const o of unspent) {
    const at = o.assetType || 'SAL';
    if (!byAsset[at]) byAsset[at] = { count: 0, total: 0n };
    byAsset[at].count++;
    byAsset[at].total += BigInt(o.amount);
  }
  console.log('\nUnspent by asset type:');
  for (const [at, data] of Object.entries(byAsset)) {
    console.log(`  ${at}: ${data.count} outputs, ${(Number(data.total) / 1e8).toFixed(8)} total`);
  }

  // Group by txType
  const byTxType = {};
  for (const o of unspent) {
    const tt = o.txType || 'unknown';
    if (!byTxType[tt]) byTxType[tt] = { count: 0, total: 0n };
    byTxType[tt].count++;
    byTxType[tt].total += BigInt(o.amount);
  }
  console.log('\nUnspent by tx type:');
  for (const [tt, data] of Object.entries(byTxType)) {
    console.log(`  ${tt}: ${data.count} outputs, ${(Number(data.total) / 1e8).toFixed(8)} total`);
  }

  // Group by isCarrot
  const cnUnspent = unspent.filter(o => !o.isCarrot);
  const carrotUnspent = unspent.filter(o => o.isCarrot);
  const cnTotal = cnUnspent.reduce((s, o) => s + BigInt(o.amount), 0n);
  const carrotTotal = carrotUnspent.reduce((s, o) => s + BigInt(o.amount), 0n);
  console.log(`\nCN unspent:     ${cnUnspent.length} outputs, ${(Number(cnTotal) / 1e8).toFixed(8)}`);
  console.log(`CARROT unspent: ${carrotUnspent.length} outputs, ${(Number(carrotTotal) / 1e8).toFixed(8)}`);

  // Check key images with null/empty
  const nullKi = unspent.filter(o => !o.keyImage);
  const nullKiTotal = nullKi.reduce((s, o) => s + BigInt(o.amount), 0n);
  console.log(`\nNull key image unspent: ${nullKi.length} outputs, ${(Number(nullKiTotal) / 1e8).toFixed(8)}`);
  if (nullKi.length > 0) {
    console.log('  Sample null-ki outputs:');
    for (const o of nullKi.slice(0, 10)) {
      console.log(`    h=${o.blockHeight} amt=${(Number(o.amount)/1e8).toFixed(4)} carrot=${o.isCarrot} type=${o.txType} sub=${o.subaddressIndex?.major},${o.subaddressIndex?.minor}`);
    }
  }

  // ============================================
  // KEY IMAGE SPENT CHECK
  // ============================================
  console.log(`\n${'='.repeat(60)}`);
  console.log('KEY IMAGE VERIFICATION');
  console.log(`${'='.repeat(60)}`);

  // Filter unspent outputs with valid key images
  const checkable = unspent.filter(o => o.keyImage && o.keyImage.length === 64);
  console.log(`\nCheckable unspent outputs (valid key images): ${checkable.length}`);

  // Check in batches of 100
  let onchainSpent = 0;
  let onchainUnspent = 0;
  let onchainPool = 0;
  let onchainError = 0;
  const falseUnspent = []; // Outputs we think are unspent but blockchain says are spent

  const BATCH = 100;
  for (let i = 0; i < checkable.length; i += BATCH) {
    const batch = checkable.slice(i, i + BATCH);
    const keyImages = batch.map(o => o.keyImage);
    try {
      const resp = await daemon.isKeyImageSpent(keyImages);
      if (resp.success && resp.result?.spent_status) {
        for (let j = 0; j < resp.result.spent_status.length; j++) {
          const status = resp.result.spent_status[j];
          if (status === 0) {
            onchainUnspent++;
          } else if (status === 1) {
            onchainSpent++;
            falseUnspent.push(batch[j]);
          } else if (status === 2) {
            onchainPool++;
          }
        }
      } else {
        onchainError += batch.length;
        console.error(`  is_key_image_spent batch ${i} failed:`, resp.error?.message);
      }
    } catch (e) {
      onchainError += batch.length;
      console.error(`  is_key_image_spent batch ${i} error:`, e.message);
    }
    if (i > 0 && i % 500 === 0) console.log(`  Checked ${i}/${checkable.length}...`);
  }

  console.log(`\nKey image verification results:`);
  console.log(`  On-chain unspent:          ${onchainUnspent}`);
  console.log(`  On-chain spent (MISSED):   ${onchainSpent}`);
  console.log(`  In mempool:                ${onchainPool}`);
  console.log(`  Errors:                    ${onchainError}`);

  if (falseUnspent.length > 0) {
    const missedTotal = falseUnspent.reduce((s, o) => s + BigInt(o.amount), 0n);
    console.log(`\n  MISSED SPENDS: ${falseUnspent.length} outputs worth ${(Number(missedTotal) / 1e8).toFixed(8)}`);
    console.log(`  Sample missed spends:`);
    for (const o of falseUnspent.slice(0, 20)) {
      console.log(`    h=${o.blockHeight} amt=${(Number(o.amount)/1e8).toFixed(4)} ki=${o.keyImage.slice(0,16)}... carrot=${o.isCarrot} type=${o.txType}`);
    }
  }

  // Compute corrected balance
  const missedTotal = falseUnspent.reduce((s, o) => s + BigInt(o.amount), 0n);
  const nullKiBalance = nullKi.reduce((s, o) => s + BigInt(o.amount), 0n);
  const totalUnspentBalance = unspent.reduce((s, o) => s + BigInt(o.amount), 0n);
  const correctedBalance = totalUnspentBalance - missedTotal;

  console.log(`\n${'='.repeat(60)}`);
  console.log('BALANCE ANALYSIS');
  console.log(`${'='.repeat(60)}`);
  console.log(`Raw unspent balance:    ${(Number(totalUnspentBalance) / 1e8).toFixed(8)}`);
  console.log(`Missed spends:         -${(Number(missedTotal) / 1e8).toFixed(8)}`);
  console.log(`Corrected balance:      ${(Number(correctedBalance) / 1e8).toFixed(8)}`);
  console.log(`Expected (C++ wallet):  3367.84799534`);
  console.log(`Null-ki balance:        ${(Number(nullKiBalance) / 1e8).toFixed(8)} (would be false positives if ki is wrong)`);

  // Check if corrected balance matches
  const expectedAtomic = 336784799534n;
  const diff = correctedBalance - expectedAtomic;
  console.log(`\nDifference from expected: ${(Number(diff) / 1e8).toFixed(8)}`);

  if (Math.abs(Number(diff)) < 1e8) {
    console.log('✓ Corrected balance matches C++ wallet (within 1 SAL)');
    console.log('\nROOT CAUSE: Key images are generated correctly but spent detection is missing these outputs.');
    console.log('This means the _checkSpentOutputs method is not seeing the spending transactions.');
  } else if (correctedBalance > expectedAtomic) {
    console.log('✗ Corrected balance STILL higher than expected.');
    console.log('This suggests FALSE POSITIVE outputs (we detected outputs that are not ours).');
    console.log('These false-positive outputs would have WRONG key images that the blockchain');
    console.log('does not recognize, so is_key_image_spent returns "unspent" for them.');
  } else {
    console.log('✗ Corrected balance LOWER than expected. Possible missing outputs.');
  }

  // Additional: check the unspent outputs that daemon also says are unspent
  // Are their amounts reasonable?
  const trueUnspent = checkable.filter(o => !falseUnspent.includes(o));
  const trueUnspentTotal = trueUnspent.reduce((s, o) => s + BigInt(o.amount), 0n);
  console.log(`\nTrue unspent outputs: ${trueUnspent.length}, total: ${(Number(trueUnspentTotal) / 1e8).toFixed(8)}`);

  // Close storage
  await storage.close();
}

run().catch(e => { console.error(e); process.exit(1); });
