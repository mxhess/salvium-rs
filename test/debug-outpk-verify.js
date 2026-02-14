#!/usr/bin/env bun
/**
 * Cross-verify outPk from our binary parser vs daemon JSON.
 * Also check if maybe the commitment stored in the enote is different from outPk.
 */
import { setCryptoBackend } from '../src/crypto/index.js';
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

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const txHash = 'd2ad187cc0dde491ae6134c8ad2df9188646859ecf2974271375f5257a51ada2';

// Get TX both as hex and as JSON
const txResp = await daemon.getTransactions([txHash], { decode_as_json: true, prune: false });
const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];

// Parse from binary
const parsed = parseTransaction(hexToBytes(txData.as_hex));
console.log('=== Binary parser outPk ===');
for (let i = 0; i < parsed.rct?.outPk?.length; i++) {
  console.log(`outPk[${i}]: ${bytesToHex(parsed.rct.outPk[i])}`);
}

// Parse from JSON
if (txData.as_json) {
  const j = typeof txData.as_json === 'string' ? JSON.parse(txData.as_json) : txData.as_json;
  console.log('\n=== Daemon JSON outPk ===');
  const outPk = j.rct_signatures?.outPk;
  if (outPk) {
    for (let i = 0; i < outPk.length; i++) {
      console.log(`outPk[${i}]: ${outPk[i]}`);
    }
  }

  // Show the ecdhInfo
  const ecdhInfo = j.rct_signatures?.ecdhInfo;
  if (ecdhInfo) {
    console.log('\n=== ecdhInfo ===');
    for (let i = 0; i < ecdhInfo.length; i++) {
      console.log(`ecdhInfo[${i}]: ${JSON.stringify(ecdhInfo[i])}`);
    }
  }

  // Check if the outPk matches
  if (outPk) {
    for (let i = 0; i < outPk.length; i++) {
      const binaryHex = bytesToHex(parsed.rct.outPk[i]);
      const jsonHex = outPk[i];
      console.log(`\noutPk[${i}] match: ${binaryHex === jsonHex}`);
      if (binaryHex !== jsonHex) {
        console.log(`  Binary: ${binaryHex}`);
        console.log(`  JSON:   ${jsonHex}`);
      }
    }
  }

  // Show full rct_signatures fields
  console.log('\n=== rct_signatures fields ===');
  for (const [k, v] of Object.entries(j.rct_signatures || {})) {
    if (typeof v === 'string' || typeof v === 'number') {
      console.log(`${k}: ${v}`);
    } else if (Array.isArray(v)) {
      console.log(`${k}: [${v.length} items]`);
    } else if (typeof v === 'object') {
      console.log(`${k}: ${JSON.stringify(v).slice(0, 100)}`);
    }
  }
}

// Also show parsed prefix output details
console.log('\n=== Parsed prefix outputs ===');
for (let i = 0; i < parsed.prefix?.vout?.length; i++) {
  const out = parsed.prefix.vout[i];
  console.log(`output[${i}]:`);
  console.log(`  key: ${bytesToHex(out.key)}`);
  console.log(`  viewTag: ${bytesToHex(out.viewTag)}`);
  console.log(`  amount: ${out.amount}`);
  console.log(`  type: ${out.type}`);
}
