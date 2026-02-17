#!/usr/bin/env bun
/**
 * TX Diagnostic — builds a minimal transfer, serializes, parses back, submits
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { parseTransaction, serializeTransaction } from '../src/transaction.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { loadWalletFromFile, getHeight } from './test-helpers.js';

await setCryptoBackend('wasm');

const DAEMON_URL = 'http://node12.whiskymine.io:29081';
const NETWORK = 'testnet';
const WALLET_A_FILE = `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const SYNC_CACHE_A = WALLET_A_FILE.replace(/\.json$/, '-sync.json');

const daemon = new DaemonRPC({ url: DAEMON_URL });

async function main() {
  const h = await getHeight(daemon);
  console.log(`Chain height: ${h}`);
  console.log();

  // Load wallet
  const walletA = await loadWalletFromFile(WALLET_A_FILE, NETWORK);
  walletA.setDaemon(daemon);

  // Load sync cache
  const { existsSync } = await import('node:fs');
  if (existsSync(SYNC_CACHE_A)) {
    const cached = JSON.parse(await Bun.file(SYNC_CACHE_A).text());
    walletA.loadSyncCache(cached);
  }

  // Sync
  console.log('Syncing wallet...');
  await walletA.syncWithDaemon();
  await Bun.write(SYNC_CACHE_A, walletA.dumpSyncCacheJSON());

  const { balance, unlockedBalance } = await walletA.getStorageBalance();
  console.log(`Balance: ${balance}, Unlocked: ${unlockedBalance}`);

  if (unlockedBalance === 0n) {
    console.log('No spendable balance. Need more blocks to mature.');
    return;
  }

  // Build a self-transfer (A -> A) for diagnosis
  const addr = walletA.getLegacyAddress();
  console.log(`\nBuilding self-transfer: 0.1 SAL to ${addr.slice(0,20)}...`);

  try {
    const result = await walletA.transfer(
      [{ address: addr, amount: 10_000_000n }],
      { priority: 'default', dryRun: true }
    );

    console.log('\n=== TX BUILT SUCCESSFULLY (dry run) ===');
    console.log(`TX hash:    ${result.txHash}`);
    console.log(`Fee:        ${result.fee}`);
    console.log(`Inputs:     ${result.inputCount}`);
    console.log(`Outputs:    ${result.outputCount}`);

    const tx = result.tx;
    const prefix = tx.prefix;
    console.log(`\n--- TX PREFIX ---`);
    console.log(`Version:    ${prefix.version}`);
    console.log(`Unlock:     ${prefix.unlockTime}`);
    console.log(`TX type:    ${prefix.txType}`);
    console.log(`Src asset:  ${prefix.source_asset_type}`);
    console.log(`Dst asset:  ${prefix.destination_asset_type}`);
    console.log(`Amount burnt: ${prefix.amount_burnt}`);
    console.log(`Inputs:     ${prefix.vin.length}`);
    console.log(`Outputs:    ${prefix.vout.length}`);

    for (let i = 0; i < prefix.vin.length; i++) {
      const inp = prefix.vin[i];
      console.log(`  vin[${i}]: type=${inp.type}, amount=${inp.amount}, asset=${inp.assetType}, offsets=[${inp.keyOffsets.slice(0,3)}...], ki=${bytesToHex(inp.keyImage).slice(0,16)}...`);
    }

    for (let i = 0; i < prefix.vout.length; i++) {
      const out = prefix.vout[i];
      const target = typeof out.target === 'string' ? out.target.slice(0,16) : bytesToHex(out.target).slice(0,16);
      console.log(`  vout[${i}]: type=0x${out.type.toString(16)}, amount=${out.amount}, asset=${out.assetType}, viewTag=${out.viewTag}, target=${target}...`);
    }

    // Extra
    const extra = prefix.extra;
    if (extra?.txPubKey) {
      const pk = typeof extra.txPubKey === 'string' ? extra.txPubKey : bytesToHex(extra.txPubKey);
      console.log(`  extra.txPubKey: ${pk.slice(0,16)}...`);
    }

    // Return address fields
    if (prefix.return_address_list) {
      console.log(`  return_address_list: ${prefix.return_address_list.length} F-points`);
      for (let i = 0; i < prefix.return_address_list.length; i++) {
        const fp = prefix.return_address_list[i];
        const fpHex = typeof fp === 'string' ? fp : bytesToHex(fp);
        console.log(`    F[${i}]: ${fpHex.slice(0,16)}...`);
      }
    }
    if (prefix.return_address_change_mask) {
      console.log(`  return_address_change_mask: [${Array.from(prefix.return_address_change_mask).join(', ')}]`);
    }
    if (prefix.return_address) {
      const ra = typeof prefix.return_address === 'string' ? prefix.return_address : bytesToHex(prefix.return_address);
      console.log(`  return_address: ${ra.slice(0,16)}...`);
    }
    if (prefix.return_pubkey) {
      const rp = typeof prefix.return_pubkey === 'string' ? prefix.return_pubkey : bytesToHex(prefix.return_pubkey);
      console.log(`  return_pubkey: ${rp.slice(0,16)}...`);
    }

    console.log(`\n--- RCT ---`);
    const rct = tx.rct;
    console.log(`Type:       ${rct.type}`);
    console.log(`Fee:        ${rct.fee}`);
    console.log(`ecdhInfo:   ${rct.ecdhInfo.length} entries`);
    console.log(`outPk:      ${rct.outPk.length} entries`);
    console.log(`pseudoOuts: ${rct.pseudoOuts.length} entries`);
    console.log(`p_r:        ${typeof rct.p_r === 'string' ? rct.p_r.slice(0,16) : bytesToHex(rct.p_r).slice(0,16)}...`);
    console.log(`CLSAGs:     ${rct.CLSAGs?.length || 0}`);
    console.log(`TCLSAGs:    ${rct.TCLSAGs?.length || 0}`);
    console.log(`BP+:        ${rct.bulletproofPlus ? 'yes' : 'no'}`);

    if (rct.salvium_data) {
      console.log(`salvium_data: type=${rct.salvium_data.salvium_data_type}`);
    }

    // Serialize
    console.log(`\n--- SERIALIZATION ---`);
    const serialized = serializeTransaction(tx);
    console.log(`Serialized length: ${serialized.length} bytes`);
    console.log(`Serialized hex (first 200 chars): ${bytesToHex(serialized).slice(0, 200)}...`);

    // Parse back
    console.log(`\n--- ROUND-TRIP PARSE ---`);
    try {
      const parsed = parseTransaction(serialized);
      console.log(`Parse OK! Keys: ${Object.keys(parsed).join(', ')}`);
      console.log(`  version: ${parsed.version}`);
      console.log(`  type:    ${parsed.type}`);
      console.log(`  inputs:  ${parsed.vin?.length}`);
      console.log(`  outputs: ${parsed.vout?.length}`);
      console.log(`  rctType: ${parsed.rct_signatures?.type}`);
      console.log(`  fee:     ${parsed.rct_signatures?.txnFee}`);
      if (parsed._bytesRead !== serialized.length) {
        console.log(`  WARNING: parsed ${parsed._bytesRead} bytes but serialized is ${serialized.length} bytes!`);
        console.log(`  DIFF: ${serialized.length - parsed._bytesRead} extra bytes`);
        // Show the extra byte(s)
        const extraStart = parsed._bytesRead;
        const extraBytes = serialized.slice(extraStart);
        console.log(`  Extra bytes at offset ${extraStart}: [${Array.from(extraBytes).map(b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}]`);
      } else {
        console.log(`  Byte count matches: ${parsed._bytesRead} == ${serialized.length}`);
      }
    } catch (e) {
      console.log(`Parse FAILED: ${e.message}`);
      console.log(e.stack);
    }

    // Check _prefixEndOffset from parser
    const parsed2 = parseTransaction(serialized);
    console.log(`\n  Parser _prefixEndOffset: ${parsed2._prefixEndOffset}`);

    // Also serialize just the prefix to check its length
    const { serializeTxPrefix } = await import('../src/transaction/serialization.js');
    const prefixBytes = serializeTxPrefix({
      ...tx.prefix,
      inputs: tx.prefix.vin,
      outputs: tx.prefix.vout
    });
    console.log(`\n--- SECTION SIZES ---`);
    console.log(`Prefix:     ${prefixBytes.length} bytes`);
    console.log(`Parser saw prefix end at: ${parsed2._prefixEndOffset}`);
    if (parsed2._prefixEndOffset !== prefixBytes.length) {
      console.log(`  PREFIX MISMATCH: serializer=${prefixBytes.length}, parser=${parsed2._prefixEndOffset}`);
    }

    const { serializeRctBase } = await import('../src/transaction/serialization.js');
    const rctBaseBytes = serializeRctBase(tx.rct);
    console.log(`RCT base:   ${rctBaseBytes.length} bytes`);
    console.log(`Prunable:   ${serialized.length - prefixBytes.length - rctBaseBytes.length} bytes`);

    // Check what's in prunable
    const prunableStart = prefixBytes.length + rctBaseBytes.length;
    const prunableBytes = serialized.slice(prunableStart);
    console.log(`  Prunable hex (first 40): ${bytesToHex(prunableBytes).slice(0, 40)}...`);
    console.log(`  BP+ count varint: 0x${prunableBytes[0].toString(16)} (${prunableBytes[0]})`);

    // BP+ proof size
    const bpSerialized = tx.rct.bulletproofPlus?.serialized;
    console.log(`  BP+ serialized: ${bpSerialized?.length || 0} bytes`);

    // CLSAG size
    const { serializeCLSAG } = await import('../src/transaction/serialization.js');
    if (tx.rct.CLSAGs?.[0]) {
      const clsagBytes = serializeCLSAG(tx.rct.CLSAGs[0]);
      console.log(`  CLSAG[0]:  ${clsagBytes.length} bytes`);
    }

    // pseudoOuts
    console.log(`  pseudoOuts: ${tx.rct.pseudoOuts.length} × 32 = ${tx.rct.pseudoOuts.length * 32} bytes`);

    // Expected prunable size
    const expectedPrunable = 1 /* varint(1) for BP+ count */ +
      (bpSerialized?.length || 0) +
      (tx.rct.CLSAGs?.reduce((sum, sig) => sum + serializeCLSAG(sig).length, 0) || 0) +
      tx.rct.pseudoOuts.length * 32;
    console.log(`  Expected prunable: ${expectedPrunable} bytes`);
    console.log(`  Actual prunable:   ${prunableBytes.length} bytes`);
    console.log(`  Prunable diff:     ${prunableBytes.length - expectedPrunable} bytes`);

    // Fetch a real coinbase TX from chain and verify our parser/serializer roundtrips
    console.log(`\n--- COINBASE ROUNDTRIP TEST ---`);
    try {
      // Get a block to find a coinbase TX
      const blockResp = await daemon.getBlockByHeight(100);
      const blockData = blockResp.result || blockResp.data;
      const minerTxHex = blockData?.miner_tx_hash || blockData?.block_header?.miner_tx_hash;

      // Get block details to get the miner TX hash
      const blockJson = blockData?.json ? JSON.parse(blockData.json) : null;
      const txHashes = blockJson?.tx_hashes || [];
      console.log(`  Block 100: ${txHashes.length} non-coinbase TXs`);

      // Try to get the miner TX blob from the block blob
      const blockBlob = blockData?.blob;
      if (blockBlob) {
        const blockBytes = hexToBytes(blockBlob);
        console.log(`  Block blob: ${blockBytes.length} bytes`);
      }
    } catch (e) {
      console.log(`  Coinbase test failed: ${e.message}`);
    }

    // Now let's do a manual hex comparison — show our prefix hex vs expected
    console.log(`\n--- HEX DECOMPOSITION ---`);
    const txHexFull = bytesToHex(serialized);
    const prefixHex = bytesToHex(prefixBytes);
    const rctBaseHex = bytesToHex(rctBaseBytes);
    console.log(`Prefix (${prefixBytes.length}b): ${prefixHex.slice(0,100)}...`);
    console.log(`RctBase (${rctBaseBytes.length}b): ${rctBaseHex}`);
    console.log(`Prunable starts at byte ${prefixBytes.length + rctBaseBytes.length}`);

    // Manual decode of first few prefix bytes
    let pos = 0;
    const decodeVarIntAt = (hex, p) => {
      const bytes = hexToBytes(hex);
      let val = 0n, shift = 0n;
      while (p < bytes.length) {
        const b = BigInt(bytes[p]);
        val |= (b & 0x7fn) << shift;
        shift += 7n;
        p++;
        if ((b & 0x80n) === 0n) break;
      }
      return { value: val, nextPos: p };
    };

    console.log(`\nPrefix decode:`);
    let r = decodeVarIntAt(prefixHex, 0);
    console.log(`  version = ${r.value} (pos ${r.nextPos})`);
    r = decodeVarIntAt(prefixHex, r.nextPos);
    console.log(`  unlockTime = ${r.value} (pos ${r.nextPos})`);
    r = decodeVarIntAt(prefixHex, r.nextPos);
    console.log(`  vin_count = ${r.value} (pos ${r.nextPos})`);

    // Try submitting
    console.log(`\n--- SUBMITTING TO DAEMON ---`);
    const txHex = bytesToHex(serialized);

    // Try without sanity checks first
    console.log('Submitting WITHOUT sanity checks...');
    const resp1 = await daemon.sendRawTransaction(txHex, {
      source_asset_type: prefix.source_asset_type,
      do_sanity_checks: false
    });
    console.log(`Response: ${JSON.stringify(resp1.result || resp1.data || resp1, null, 2)}`);

    // Try with sanity checks
    console.log('\nSubmitting WITH sanity checks...');
    const resp2 = await daemon.sendRawTransaction(txHex, {
      source_asset_type: prefix.source_asset_type,
      do_sanity_checks: true
    });
    console.log(`Response: ${JSON.stringify(resp2.result || resp2.data || resp2, null, 2)}`);

  } catch (e) {
    console.log(`\nERROR: ${e.message}`);
    console.log(e.stack);
  }
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
