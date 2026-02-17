#!/usr/bin/env bun
// Debug transaction with EXACT Salvium format parsing

import { createDaemonRPC } from '../src/rpc/index.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

function decodeVarint(data, offset) {
  let value = 0n;
  let shift = 0n;
  let bytesRead = 0;

  while (offset + bytesRead < data.length) {
    const byte = data[offset + bytesRead];
    bytesRead++;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
    if (shift >= 70n) throw new Error('Varint overflow');
  }
  return { value: Number(value), bytesRead };
}

async function test() {
  const txHash = 'a5e85d03e9200229a72fc3cfe94e5b139c8c2ad982dc3fd174898be63269e670';

  const resp = await daemon.getTransactions([txHash], { decode_as_json: true });
  const txData = resp.result?.txs?.[0];
  const data = hexToBytes(txData.as_hex);
  const jsonTx = JSON.parse(txData.as_json);

  console.log('TX size:', data.length, 'bytes');
  console.log('Daemon JSON: inputs=%d, outputs=%d, rct_type=%d\n',
    jsonTx.vin?.length, jsonTx.vout?.length, jsonTx.rct_signatures?.type);

  let offset = 0;

  // Helper to read varint
  const readVarint = () => {
    const { value, bytesRead } = decodeVarint(data, offset);
    offset += bytesRead;
    return value;
  };

  // Helper to read bytes
  const readBytes = (count) => {
    const result = data.slice(offset, offset + count);
    offset += count;
    return result;
  };

  // Helper to read string (length-prefixed)
  const readString = () => {
    const len = readVarint();
    if (len === 0) return '';
    const str = new TextDecoder().decode(data.slice(offset, offset + len));
    offset += len;
    return str;
  };

  // Version
  const version = readVarint();
  console.log(`Version: ${version} (offset 0->${offset})`);

  // Unlock time
  const unlockTime = readVarint();
  console.log(`Unlock time: ${unlockTime} (offset->${offset})`);

  // Number of inputs
  const numInputs = readVarint();
  console.log(`\nInputs: ${numInputs} (expected ${jsonTx.vin?.length})`);

  // Parse inputs (Salvium txin_to_key: amount, asset_type, key_offsets, k_image)
  for (let i = 0; i < numInputs; i++) {
    const startOffset = offset;
    const inputType = data[offset++];

    if (inputType === 0xff) {
      // Coinbase
      const height = readVarint();
      console.log(`  Input ${i}: GEN height=${height}`);
    } else if (inputType === 0x02) {
      // txin_to_key
      const amount = readVarint();
      const assetType = readString();
      const numOffsets = readVarint();
      const offsets = [];
      for (let j = 0; j < numOffsets; j++) {
        offsets.push(readVarint());
      }
      const keyImage = readBytes(32);
      console.log(`  Input ${i}: amount=${amount}, asset="${assetType}", offsets=${numOffsets}, ki=${bytesToHex(keyImage).slice(0, 8)}... (${startOffset}->${offset})`);
    } else {
      console.log(`  Input ${i}: UNKNOWN type 0x${inputType.toString(16)} at offset ${offset-1}`);
      break;
    }
  }

  console.log(`After inputs: offset ${offset}`);

  // Number of outputs
  const numOutputs = readVarint();
  console.log(`\nOutputs: ${numOutputs} (expected ${jsonTx.vout?.length})`);

  // Parse outputs (Salvium txout_to_key/tagged_key)
  for (let i = 0; i < numOutputs; i++) {
    const startOffset = offset;
    const amount = readVarint();
    const outputType = data[offset++];

    if (outputType === 0x02) {
      // txout_to_key: key + asset_type + unlock_time
      const key = readBytes(32);
      const assetType = readString();
      const outUnlock = readVarint();
      console.log(`  Output ${i}: amount=${amount}, type=key, asset="${assetType}", unlock=${outUnlock} (${startOffset}->${offset})`);
    } else if (outputType === 0x03) {
      // txout_to_tagged_key: key + asset_type + unlock_time + view_tag
      const key = readBytes(32);
      const assetType = readString();
      const outUnlock = readVarint();
      const viewTag = data[offset++];
      console.log(`  Output ${i}: amount=${amount}, type=tagged, asset="${assetType}", unlock=${outUnlock}, vtag=${viewTag} (${startOffset}->${offset})`);
    } else {
      console.log(`  Output ${i}: UNKNOWN type 0x${outputType.toString(16)} at offset ${offset-1}`);
      break;
    }
  }

  console.log(`After outputs: offset ${offset}`);

  // Extra
  const extraLen = readVarint();
  console.log(`\nExtra length: ${extraLen}`);
  const extra = readBytes(extraLen);
  console.log(`After extra: offset ${offset}`);

  // Salvium tx prefix fields (txType, etc.)
  console.log('\n=== Salvium TX prefix fields ===');
  const txType = readVarint();
  console.log(`txType: ${txType}`);

  // TX_TYPE: UNSET=0, PROTOCOL=1, MINER=2, TRANSFER=3, BURN=4, CONVERT=5, STAKE=6
  if (txType !== 0 && txType !== 1) {
    const amountBurnt = readVarint();
    console.log(`amount_burnt: ${amountBurnt}`);

    if (txType !== 2) {
      // Not MINER
      if (txType === 3 && version >= 5) {
        // TRANSFER with N outputs
        const listCount = readVarint();
        console.log(`return_address_list count: ${listCount}`);
        for (let i = 0; i < listCount; i++) {
          readBytes(32);
        }
        const maskCount = readVarint();
        readBytes(maskCount);
      } else if (txType === 6 && version >= 6) {
        // STAKE with CARROT
        console.log('protocol_tx_data:');
        console.log('  return_address:', bytesToHex(readBytes(32)).slice(0, 16) + '...');
        console.log('  return_pubkey:', bytesToHex(readBytes(32)).slice(0, 16) + '...');
        console.log('  return_view_tag:', bytesToHex(readBytes(3)));
        console.log('  return_anchor_enc:', bytesToHex(readBytes(16)));
      } else {
        const returnAddr = readBytes(32);
        const returnPubkey = readBytes(32);
        console.log(`return_address: ${bytesToHex(returnAddr).slice(0, 16)}...`);
        console.log(`return_pubkey: ${bytesToHex(returnPubkey).slice(0, 16)}...`);
      }

      const srcType = readString();
      const dstType = readString();
      const slippage = readVarint();
      console.log(`source_asset_type: "${srcType}"`);
      console.log(`destination_asset_type: "${dstType}"`);
      console.log(`amount_slippage_limit: ${slippage}`);
    }
  }

  console.log(`\n=== RCT section starts at offset ${offset} ===`);
  console.log(`Remaining bytes: ${data.length - offset}`);

  // Check RCT structure
  console.log(`\nFirst 100 RCT bytes: ${bytesToHex(data.slice(offset, offset + 100))}`);

  // Check if asset type marker exists after offset
  for (let i = offset; i < Math.min(offset + 100, data.length - 4); i++) {
    if (data[i] === 0x03 && data[i+1] === 0x53 && data[i+2] === 0x41 && data[i+3] === 0x4c) {
      console.log(`\nFound SAL marker at offset ${i} (${i - offset} bytes into RCT)`);
      break;
    }
  }
}

test().catch(console.error);
