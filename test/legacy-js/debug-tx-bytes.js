#!/usr/bin/env bun
// Debug transaction byte structure

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

  console.log('TX size:', data.length, 'bytes');
  console.log('Daemon says: type=6, inputs=9, outputs=2\n');

  // Find SAL marker
  let salOffset = -1;
  for (let i = 0; i < Math.min(200, data.length - 4); i++) {
    if (data[i] === 0x03 && data[i+1] === 0x53 && data[i+2] === 0x41 && data[i+3] === 0x4c) {
      salOffset = i;
      console.log(`Found SAL marker at offset ${i}`);
      break;
    }
  }

  if (salOffset === -1) {
    console.log('No SAL marker found in first 200 bytes');
    return;
  }

  let offset = salOffset;

  // Read asset types (2 outputs)
  console.log('\nAsset types:');
  for (let i = 0; i < 2; i++) {
    const len = data[offset++];
    const str = new TextDecoder().decode(data.slice(offset, offset + len));
    offset += len;
    console.log(`  Output ${i}: "${str}" (len=${len})`);
  }

  // Separator
  if (data[offset] === 0x00) {
    console.log(`Separator byte at ${offset}: 0x00`);
    offset++;
  }

  // RCT type
  const type = data[offset++];
  console.log(`RCT type at ${offset-1}: ${type}`);

  // Fee
  const fee = decodeVarint(data, offset);
  console.log(`Fee: ${fee.value} (${fee.bytesRead} bytes)`);
  offset += fee.bytesRead;

  // ecdhInfo (2 outputs, 8 bytes each for type 6)
  console.log('\necdhInfo:');
  for (let i = 0; i < 2; i++) {
    const amount = data.slice(offset, offset + 8);
    console.log(`  Output ${i}: ${bytesToHex(amount)}`);
    offset += 8;
  }

  // outPk (2 outputs, 32 bytes each)
  console.log('\noutPk:');
  for (let i = 0; i < 2; i++) {
    const pk = data.slice(offset, offset + 32);
    console.log(`  Output ${i}: ${bytesToHex(pk).slice(0, 16)}...`);
    offset += 32;
  }

  // p_r (32 bytes)
  const p_r = data.slice(offset, offset + 32);
  console.log(`\np_r: ${bytesToHex(p_r).slice(0, 16)}...`);
  offset += 32;

  console.log(`\nOffset after base RCT: ${offset}`);
  console.log(`Remaining bytes: ${data.length - offset}`);

  // What's next?
  console.log(`\nNext 20 bytes: ${bytesToHex(data.slice(offset, offset + 20))}`);

  // Try to read nbp (number of bulletproofs)
  try {
    const nbp = decodeVarint(data, offset);
    console.log(`\nTrying to read nbp varint: ${nbp.value} (${nbp.bytesRead} bytes)`);
  } catch (e) {
    console.log(`\nFailed to read nbp: ${e.message}`);
  }
}

test().catch(console.error);
