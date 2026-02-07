#!/usr/bin/env bun
/**
 * Check if SalviumOne commitments have extra components beyond mask*G + amount*H.
 * If outPk != mask*G + amount*H, there might be an asset tag component.
 */
import { setCryptoBackend, commit, scalarMultBase } from '../src/crypto/index.js';
import { getCryptoBackend } from '../src/crypto/provider.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { parseTransaction } from '../src/transaction/parsing.js';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const daemon = new DaemonRPC({ url: 'http://web.whiskymine.io:29081' });
const backend = getCryptoBackend();

// Test with one of our problematic TXs (rctType 9, SalviumOne)
const txHash = 'd2ad187cc0dde491ae6134c8ad2df9188646859ecf2974271375f5257a51ada2';
const txResp = await daemon.getTransactions([txHash], true, false);
const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
const parsed = parseTransaction(hexToBytes(txData.as_hex));

console.log(`TX: ${txHash.slice(0,16)}... rctType=${parsed.rct?.type}`);
console.log(`Outputs: ${parsed.prefix?.vout?.length}`);

// Also check a KNOWN GOOD rctType=6 (BulletproofPlus) TX for comparison
// Find one from our wallet...
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8')));
const allOutputs = await storage.getOutputs({ isSpent: false });

// Find a non-CARROT output with commitment and mask
const cnOutput = allOutputs.find(o => !o.isCarrot && o.commitment && o.mask);
if (cnOutput) {
  console.log(`\n=== CryptoNote output (non-CARROT) for comparison ===`);
  console.log(`TX: ${cnOutput.txHash?.slice(0,16)}... block=${cnOutput.blockHeight}`);
  console.log(`Amount: ${cnOutput.amount}`);
  console.log(`AssetType: ${cnOutput.assetType}`);
  const maskBytes = hexToBytes(cnOutput.mask);
  const c = commit(BigInt(cnOutput.amount), maskBytes);
  console.log(`commit(amount, mask): ${bytesToHex(c)}`);
  console.log(`stored commitment:    ${cnOutput.commitment}`);
  console.log(`MATCH: ${bytesToHex(c) === cnOutput.commitment}`);
}

// Now look at the salvium_data for our rctType 9 TX
console.log(`\n=== SalviumOne TX salvium_data ===`);
console.log(`salvium_data present: ${!!parsed.rct?.salvium_data}`);
if (parsed.rct?.salvium_data) {
  const sd = parsed.rct.salvium_data;
  console.log(`  Keys: ${Object.keys(sd).join(', ')}`);
  // Look for any asset-related data
  for (const [key, val] of Object.entries(sd)) {
    if (val instanceof Uint8Array) {
      console.log(`  ${key}: ${bytesToHex(val).slice(0,64)}... (${val.length} bytes)`);
    } else if (Array.isArray(val)) {
      console.log(`  ${key}: [${val.length} items]`);
      for (const item of val.slice(0, 3)) {
        if (item instanceof Uint8Array) {
          console.log(`    ${bytesToHex(item).slice(0,64)}... (${item.length} bytes)`);
        } else if (typeof item === 'object') {
          console.log(`    ${JSON.stringify(item).slice(0,80)}`);
        } else {
          console.log(`    ${item}`);
        }
      }
    } else {
      console.log(`  ${key}: ${JSON.stringify(val).slice(0,80)}`);
    }
  }
}

// Also fetch the TX as JSON from daemon to see all fields
const blockResp = await daemon.getBlock({ height: 34554 });
const blockJson = JSON.parse(blockResp.result.json);
console.log(`\n=== Block 34554 regular TXs ===`);
const txHashes = blockJson.tx_hashes || [];
console.log(`TX hashes: ${txHashes.length}`);

// Get JSON representation of our TX
const txJsonResp = await daemon.getTransactions([txHash], { decode_as_json: true, prune: false });
const txJsonData = txJsonResp.result?.txs?.[0] || txJsonResp.txs?.[0];
if (txJsonData?.as_json) {
  const j = typeof txJsonData.as_json === 'string' ? JSON.parse(txJsonData.as_json) : txJsonData.as_json;
  console.log(`\n=== TX JSON rct_signatures ===`);
  console.log(`  type: ${j.rct_signatures?.type}`);
  console.log(`  txnFee: ${j.rct_signatures?.txnFee}`);
  const outPk = j.rct_signatures?.outPk;
  if (outPk) {
    console.log(`  outPk: ${JSON.stringify(outPk).slice(0,120)}`);
  }
  const ecdhInfo = j.rct_signatures?.ecdhInfo;
  if (ecdhInfo) {
    console.log(`  ecdhInfo: ${JSON.stringify(ecdhInfo).slice(0,120)}`);
  }
  // Check for any extra fields in rct_signatures
  const knownFields = ['type', 'txnFee', 'outPk', 'ecdhInfo', 'pseudoOuts', 'p_r'];
  const extra = Object.keys(j.rct_signatures || {}).filter(k => !knownFields.includes(k));
  if (extra.length) {
    console.log(`  Extra rct fields: ${extra.join(', ')}`);
    for (const k of extra) {
      console.log(`    ${k}: ${JSON.stringify(j.rct_signatures[k]).slice(0,100)}`);
    }
  }

  // Check salvium_data in JSON
  if (j.rct_signatures?.salvium_data) {
    console.log(`\n=== salvium_data from JSON ===`);
    console.log(JSON.stringify(j.rct_signatures.salvium_data, null, 2).slice(0, 500));
  }
}
