#!/usr/bin/env bun
/**
 * Debug: check the rctType and ecdhInfo for CARROT outputs
 */
import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { parseTransaction } from '../src/transaction/parsing.js';
import { readFileSync } from 'fs';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  if (typeof hex !== 'string') return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const daemon = new DaemonRPC({ url: 'http://web.whiskymine.io:29081' });
const storage = new MemoryStorage();
const cached = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8'));
storage.load(cached);

const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot && o.commitment);

console.log(`CARROT outputs with commitment: ${carrotOutputs.length}\n`);

for (const o of carrotOutputs.slice(0, 5)) {
  console.log(`=== TX ${o.txHash.slice(0,16)}... idx=${o.outputIndex} block=${o.blockHeight} ===`);
  console.log(`  assetType: ${o.assetType}, amount: ${o.amount}`);

  // Fetch the actual TX from daemon
  try {
    const blockResp = await daemon.getBlock({ height: o.blockHeight });
    if (!blockResp.success) { console.log('  Failed to get block'); continue; }
    const blockJson = JSON.parse(blockResp.result.json);

    // Check if this TX is miner_tx, protocol_tx, or regular
    const minerHash = blockResp.result.miner_tx_hash;
    const protocolHash = blockResp.result.protocol_tx_hash;
    const isMiner = o.txHash === minerHash;
    const isProtocol = o.txHash === protocolHash;
    const isRegular = !isMiner && !isProtocol;
    console.log(`  TX type: ${isMiner ? 'MINER' : isProtocol ? 'PROTOCOL' : 'REGULAR'}`);

    if (isMiner) {
      console.log(`  miner_tx rct_type: ${blockJson.miner_tx?.rct_signatures?.type ?? 'null'}`);
      console.log(`  miner_tx vout[${o.outputIndex}] amount: ${blockJson.miner_tx?.vout?.[o.outputIndex]?.amount}`);
      const outPk = blockJson.miner_tx?.rct_signatures?.outPk;
      console.log(`  miner_tx outPk: ${outPk ? JSON.stringify(outPk).slice(0,80) : 'null'}`);
      console.log(`  miner_tx ecdhInfo: ${JSON.stringify(blockJson.miner_tx?.rct_signatures?.ecdhInfo)?.slice(0,80) || 'null'}`);
    } else if (isProtocol) {
      console.log(`  protocol_tx rct_type: ${blockJson.protocol_tx?.rct_signatures?.type ?? 'null'}`);
      console.log(`  protocol_tx vout[${o.outputIndex}] amount: ${blockJson.protocol_tx?.vout?.[o.outputIndex]?.amount}`);
      const outPk = blockJson.protocol_tx?.rct_signatures?.outPk;
      console.log(`  protocol_tx outPk: ${outPk ? JSON.stringify(outPk).slice(0,80) : 'null'}`);
    } else {
      // Regular TX - fetch from daemon
      const txResp = await daemon.getTransactions([o.txHash], true, false);
      const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
      if (txData?.as_hex) {
        const parsed = parseTransaction(hexToBytes(txData.as_hex));
        console.log(`  rctType: ${parsed.rct?.type}`);
        console.log(`  ecdhInfo count: ${parsed.rct?.ecdhInfo?.length || 0}`);
        console.log(`  outPk count: ${parsed.rct?.outPk?.length || 0}`);
        if (parsed.rct?.ecdhInfo?.[o.outputIndex]) {
          console.log(`  ecdhInfo[${o.outputIndex}].amount: ${bytesToHex(parsed.rct.ecdhInfo[o.outputIndex].amount || new Uint8Array(8)).slice(0,16)}...`);
        }
      } else if (txData?.as_json) {
        const txJson = typeof txData.as_json === 'string' ? JSON.parse(txData.as_json) : txData.as_json;
        console.log(`  rctType: ${txJson.rct_signatures?.type}`);
        console.log(`  ecdhInfo: ${JSON.stringify(txJson.rct_signatures?.ecdhInfo)?.slice(0,80) || 'null'}`);
      }
    }
  } catch (e) {
    console.log(`  Error: ${e.message}`);
  }
  console.log();
}
