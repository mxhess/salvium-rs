import { setCryptoBackend } from './src/crypto/index.js';
import { DaemonRPC } from './src/rpc/daemon.js';
import { scanCarrotOutput, makeInputContext, makeInputContextCoinbase } from './src/carrot-scanning.js';
import { Wallet } from './src/wallet.js';
import { hexToBytes, bytesToHex } from './src/address.js';
import { readFileSync } from 'fs';
import { commit as pedersonCommit } from './src/crypto/index.js';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const wj = JSON.parse(readFileSync(process.env.HOME + '/testnet-wallet/wallet.json'));
const wallet = Wallet.fromJSON({ ...wj, network: 'testnet' });

// Helper to convert to bytes
function toBytes(val) {
  if (val instanceof Uint8Array) return val;
  if (typeof val === 'string') return hexToBytes(val);
  if (val && typeof val === 'object') return new Uint8Array(Object.values(val));
  throw new Error('Cannot convert to bytes: ' + typeof val);
}

console.log('=== CARROT Keys ===');
const viewIncomingKey = toBytes(wallet.carrotKeys.viewIncomingKey);
const accountSpendPubkey = toBytes(wallet.carrotKeys.accountSpendPubkey);
console.log('viewIncomingKey:', bytesToHex(viewIncomingKey));
console.log('accountSpendPubkey:', bytesToHex(accountSpendPubkey));

// Fetch block 1110 (CARROT block)
const resp = await daemon.getBlock({ height: 1780 });
console.log('\n=== Raw Response ===');
console.log('resp.result.json exists:', !!resp.result?.json);

if (!resp.result?.json) {
  console.log('No JSON in response');
  console.log('resp:', JSON.stringify(resp, null, 2).slice(0, 500));
  process.exit(1);
}

const blockJson = JSON.parse(resp.result.json);
const minerTx = blockJson.miner_tx;

console.log('\n=== Block 1110 Miner TX ===');
console.log('version:', minerTx.version);
console.log('type:', minerTx.type);
console.log('outputs:', minerTx.vout?.length);

// Check output structure
console.log('\n=== Output Structure ===');
const output = minerTx.vout[0];
console.log('output.target keys:', Object.keys(output.target || {}));

const carrotTarget = output.target?.carrot_v1;
if (!carrotTarget) {
  console.log('No carrot_v1 target found!');
  console.log('Output:', JSON.stringify(output, null, 2));
  process.exit(1);
}

console.log('\n=== CARROT Output ===');
console.log('key:', carrotTarget.key);
console.log('asset_type:', carrotTarget.asset_type);
console.log('view_tag:', carrotTarget.view_tag);

// Parse extra bytes
const extraBytes = new Uint8Array(minerTx.extra);
console.log('\n=== Extra Bytes ===');
console.log('raw:', bytesToHex(extraBytes));

// Extract tx pubkey (D_e for CARROT coinbase)
let offset = 0;
if (extraBytes[offset] === 0x01) {
  offset++;
  const txPubKey = extraBytes.slice(offset, offset + 32);
  offset += 32;
  console.log('txPubKey (D_e):', bytesToHex(txPubKey));

  // Build input context for coinbase
  const inputContext = makeInputContextCoinbase(1110);
  console.log('\n=== Input Context ===');
  console.log('context:', bytesToHex(inputContext));

  // Get view tag as 3-byte array
  const viewTagHex = carrotTarget.view_tag;
  const viewTag = new Uint8Array(3);
  viewTag[0] = parseInt(viewTagHex.slice(0, 2), 16);
  viewTag[1] = parseInt(viewTagHex.slice(2, 4), 16);
  viewTag[2] = parseInt(viewTagHex.slice(4, 6), 16);
  console.log('viewTag:', bytesToHex(viewTag));

  // Compute zeroCommit for coinbase (scalar 1)
  const clearAmount = BigInt(output.amount);
  const scalarOne = new Uint8Array(32);
  scalarOne[0] = 1;
  const amountCommitment = pedersonCommit(clearAmount, scalarOne);
  console.log('amountCommitment:', bytesToHex(amountCommitment));

  // Build output object for scanning
  const outputForScan = {
    key: hexToBytes(carrotTarget.key),
    viewTag: viewTag,
    enoteEphemeralPubkey: txPubKey,
    encryptedAmount: null  // Clear amount for coinbase
  };

  console.log('\n=== Scanning ===');
  console.log('outputForScan.key:', bytesToHex(outputForScan.key));
  console.log('outputForScan.viewTag:', bytesToHex(outputForScan.viewTag));
  console.log('outputForScan.enoteEphemeralPubkey:', bytesToHex(outputForScan.enoteEphemeralPubkey));
  console.log('\nviewIncomingKey:', bytesToHex(viewIncomingKey));
  console.log('accountSpendPubkey:', bytesToHex(accountSpendPubkey));

  // Try scanning
  try {
    const result = scanCarrotOutput(
      outputForScan,
      viewIncomingKey,
      accountSpendPubkey,
      inputContext,
      new Map(),  // No subaddresses
      amountCommitment
    );

    if (result) {
      console.log('\n=== SCAN RESULT ===');
      console.log('owned:', result.owned);
      console.log('amount:', result.amount);
      console.log('isMainAddress:', result.isMainAddress);
      console.log('subaddressIndex:', result.subaddressIndex);
    } else {
      console.log('\nScan result: null (not ours)');
    }
  } catch (e) {
    console.log('\nScan error:', e.message);
    console.log(e.stack);
  }
}
