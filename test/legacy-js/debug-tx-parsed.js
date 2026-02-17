#!/usr/bin/env bun
// Debug parsed transaction structure

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  const txHash = 'a5e85d03e9200229a72fc3cfe94e5b139c8c2ad982dc3fd174898be63269e670';

  const resp = await daemon.getTransactions([txHash], { decode_as_json: true });
  const txData = resp.result?.txs?.[0];

  console.log('TX size:', txData.as_hex.length / 2, 'bytes');

  const tx = parseTransaction(hexToBytes(txData.as_hex));

  console.log('\n=== Prefix ===');
  console.log('Version:', tx.prefix.version);
  console.log('Unlock time:', tx.prefix.unlockTime);
  console.log('Inputs:', tx.prefix.vin.length);

  for (let i = 0; i < Math.min(3, tx.prefix.vin.length); i++) {
    const inp = tx.prefix.vin[i];
    console.log(`  Input ${i}: type=${inp.type}, amount=${inp.amount}, asset=${inp.assetType}, offsets=${inp.keyOffsets?.length}`);
  }
  if (tx.prefix.vin.length > 3) console.log(`  ... and ${tx.prefix.vin.length - 3} more`);

  console.log('Outputs:', tx.prefix.vout.length);
  for (let i = 0; i < tx.prefix.vout.length; i++) {
    const out = tx.prefix.vout[i];
    console.log(`  Output ${i}: amount=${out.amount}, type=${out.type}, asset=${out.assetType}, viewTag=${out.viewTag}`);
  }

  console.log('Extra fields:', tx.prefix.extra?.length);
  console.log('txType:', tx.prefix.txType);
  console.log('source_asset_type:', tx.prefix.source_asset_type);
  console.log('destination_asset_type:', tx.prefix.destination_asset_type);

  console.log('\n=== RCT ===');
  console.log('Type:', tx.rct?.type);
  console.log('Fee:', tx.rct?.txnFee);
  console.log('ecdhInfo count:', tx.rct?.ecdhInfo?.length);
  console.log('outPk count:', tx.rct?.outPk?.length);
  console.log('p_r:', tx.rct?.p_r ? bytesToHex(tx.rct.p_r).slice(0, 16) + '...' : 'null');
  console.log('salvium_data:', !!tx.rct?.salvium_data);
  console.log('bulletproofPlus:', tx.rct?.bulletproofPlus?.length || 'none');
  console.log('CLSAGs:', tx.rct?.CLSAGs?.length || 'none');
}

test().catch(console.error);
