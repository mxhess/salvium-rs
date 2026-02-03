#!/usr/bin/env bun
/**
 * Debug: Build a TX in dry-run mode and dump the serialized hex for analysis.
 * Compares our serialization with what the daemon expects.
 */
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer } from '../src/wallet/transfer.js';
import { hexToBytes } from '../src/address.js';

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const WALLET_FILE = process.env.WALLET_FILE || `${process.env.HOME}/testnet-wallet/wallet.json`;
const NETWORK = 'testnet';

const daemon = new DaemonRPC({ url: DAEMON_URL });

// Load wallet
const walletJson = JSON.parse(await Bun.file(WALLET_FILE).text());
const keys = {
  viewSecretKey: walletJson.viewSecretKey,
  spendSecretKey: walletJson.spendSecretKey,
  viewPublicKey: walletJson.viewPublicKey,
  spendPublicKey: walletJson.spendPublicKey,
};

// Sync
const storage = new MemoryStorage();
const sync = createWalletSync({ daemon, keys, storage, network: NETWORK });
await sync.start();

// Create ephemeral wallet B
const walletB = Wallet.create({ network: NETWORK });
const addressB = walletB.getAddress();

// Build TX (dry run)
const result = await transfer({
  wallet: { keys, storage },
  daemon,
  destinations: [{ address: addressB, amount: 10_000_000_000n }],
  options: { priority: 'default', dryRun: true, network: NETWORK }
});

const hex = result.serializedHex;
const bytes = hexToBytes(hex);

console.log(`TX hex length: ${hex.length} chars (${bytes.length} bytes)\n`);

// Parse the prefix manually
let pos = 0;
function readVarint() {
  let result = 0n;
  let shift = 0n;
  while (pos < bytes.length) {
    const b = bytes[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return result;
}
function readBytes(n) {
  const slice = bytes.slice(pos, pos + n);
  pos += n;
  return slice;
}
function readString() {
  const len = Number(readVarint());
  const s = new TextDecoder().decode(readBytes(len));
  return s;
}
function toHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('=== TX PREFIX ===');
const version = readVarint();
console.log(`version: ${version}`);
const unlockTime = readVarint();
console.log(`unlock_time: ${unlockTime}`);

// Inputs
const numInputs = Number(readVarint());
console.log(`\nvin count: ${numInputs}`);
for (let i = 0; i < numInputs; i++) {
  const tag = bytes[pos++];
  console.log(`  vin[${i}] tag: 0x${tag.toString(16)}`);
  if (tag === 0x02) { // txin_to_key
    const amount = readVarint();
    const assetType = readString();
    const numOffsets = Number(readVarint());
    const offsets = [];
    for (let j = 0; j < numOffsets; j++) offsets.push(Number(readVarint()));
    const keyImage = toHex(readBytes(32));
    console.log(`    amount: ${amount}, asset: "${assetType}", offsets(${numOffsets}): [${offsets.slice(0, 3).join(',')}${numOffsets > 3 ? ',...' : ''}], ki: ${keyImage.slice(0, 16)}...`);
  }
}

// Outputs
const numOutputs = Number(readVarint());
console.log(`\nvout count: ${numOutputs}`);
for (let i = 0; i < numOutputs; i++) {
  const amount = readVarint();
  const tag = bytes[pos++];
  console.log(`  vout[${i}] amount: ${amount}, tag: 0x${tag.toString(16)}`);
  if (tag === 0x03) { // txout_to_tagged_key
    const key = toHex(readBytes(32));
    const assetType = readString();
    const unlockTime = readVarint();
    const viewTag = bytes[pos++];
    console.log(`    key: ${key.slice(0,16)}..., asset: "${assetType}", unlock: ${unlockTime}, view_tag: 0x${viewTag.toString(16).padStart(2,'0')}`);
  } else if (tag === 0x02) { // txout_to_key
    const key = toHex(readBytes(32));
    const assetType = readString();
    const unlockTime = readVarint();
    console.log(`    key: ${key.slice(0,16)}..., asset: "${assetType}", unlock: ${unlockTime}`);
  }
}

// Extra
const extraLen = Number(readVarint());
const extraBytes = readBytes(extraLen);
console.log(`\nextra: ${extraLen} bytes`);

// Salvium prefix fields
const txType = readVarint();
const txTypeNames = {0:'UNSET',1:'MINER',2:'PROTOCOL',3:'TRANSFER',4:'BURN',5:'CONVERT',6:'YIELD',7:'STAKE',8:'RETURN',9:'AUDIT'};
console.log(`\ntype: ${txType} (${txTypeNames[Number(txType)] || '?'})`);

if (txType !== 0n && txType !== 2n) {
  const amountBurnt = readVarint();
  console.log(`amount_burnt: ${amountBurnt}`);

  if (txType !== 1n) {
    // return address handling depends on version
    if (txType === 3n && version >= 3n) {
      // return_address_list
      const listLen = Number(readVarint());
      console.log(`return_address_list count: ${listLen}`);
      for (let i = 0; i < listLen; i++) {
        const addr = toHex(readBytes(32));
        console.log(`  [${i}]: ${addr.slice(0,16)}...`);
      }
      const maskLen = Number(readVarint());
      const mask = readBytes(maskLen);
      console.log(`return_address_change_mask: ${maskLen} bytes: ${toHex(mask)}`);
    } else if (txType === 7n && version >= 4n) {
      console.log('protocol_tx_data (STAKE+CARROT) — skipping');
    } else {
      const returnAddr = toHex(readBytes(32));
      const returnPubkey = toHex(readBytes(32));
      console.log(`return_address: ${returnAddr.slice(0,16)}...`);
      console.log(`return_pubkey: ${returnPubkey.slice(0,16)}...`);
    }

    const srcAsset = readString();
    const dstAsset = readString();
    const slippage = readVarint();
    console.log(`source_asset_type: "${srcAsset}"`);
    console.log(`destination_asset_type: "${dstAsset}"`);
    console.log(`amount_slippage_limit: ${slippage}`);
  }
}

console.log(`\nPrefix parsed up to byte ${pos}/${bytes.length}`);
console.log(`\n=== RCT SIGNATURES ===`);
const rctType = bytes[pos++];
console.log(`rct_type: ${rctType}`);
if (rctType > 0) {
  const fee = readVarint();
  console.log(`fee: ${fee}`);
  console.log(`\nRemaining bytes: ${bytes.length - pos}`);
}

// Write hex to file for reference
await Bun.write('/tmp/debug-tx.hex', hex);
console.log('\nTX hex written to /tmp/debug-tx.hex');
