#!/usr/bin/env bun
// Debug transaction byte structure - find correct RCT offset

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

  let offset = 0;

  // Version
  const version = decodeVarint(data, offset);
  console.log(`Version: ${version.value} at offset 0`);
  offset += version.bytesRead;

  // Unlock time
  const unlockTime = decodeVarint(data, offset);
  console.log(`Unlock time: ${unlockTime.value}`);
  offset += unlockTime.bytesRead;

  // Number of inputs
  const numInputs = decodeVarint(data, offset);
  console.log(`\nInputs: ${numInputs.value}`);
  offset += numInputs.bytesRead;

  // Skip inputs (simplified - just find pattern)
  for (let i = 0; i < numInputs.value; i++) {
    const inputType = data[offset++];
    if (inputType === 0x02) { // txin_to_key
      const amount = decodeVarint(data, offset);
      offset += amount.bytesRead;
      const numOffsets = decodeVarint(data, offset);
      offset += numOffsets.bytesRead;
      for (let j = 0; j < numOffsets.value; j++) {
        const ko = decodeVarint(data, offset);
        offset += ko.bytesRead;
      }
      offset += 32; // key image
    }
  }

  console.log(`After inputs: offset ${offset}`);

  // Number of outputs
  const numOutputs = decodeVarint(data, offset);
  console.log(`\nOutputs: ${numOutputs.value}`);
  offset += numOutputs.bytesRead;

  // Skip outputs
  for (let i = 0; i < numOutputs.value; i++) {
    const amount = decodeVarint(data, offset);
    offset += amount.bytesRead;
    const outputType = data[offset++];
    if (outputType === 0x02) { // txout_to_key
      offset += 32; // public key
    } else if (outputType === 0x03) { // txout_to_tagged_key
      offset += 32; // public key
      offset += 1;  // view tag
    }
  }

  console.log(`After outputs: offset ${offset}`);

  // Extra
  const extraLen = decodeVarint(data, offset);
  console.log(`\nExtra length: ${extraLen.value}`);
  offset += extraLen.bytesRead;
  offset += extraLen.value; // Skip extra bytes

  console.log(`\n=== RCT section starts at offset ${offset} ===`);
  console.log(`Remaining bytes: ${data.length - offset}`);

  // Show first 50 bytes of RCT
  console.log(`\nFirst 50 RCT bytes: ${bytesToHex(data.slice(offset, offset + 50))}`);

  // Search for SAL marker from RCT start
  let salOffset = -1;
  for (let i = offset; i < Math.min(offset + 200, data.length - 4); i++) {
    if (data[i] === 0x03 && data[i+1] === 0x53 && data[i+2] === 0x41 && data[i+3] === 0x4c) {
      salOffset = i;
      console.log(`\nFound SAL marker at offset ${i} (${i - offset} bytes into RCT)`);
      break;
    }
  }

  if (salOffset === -1) {
    console.log('\nNo SAL marker found - checking raw RCT type byte');
    const rawType = data[offset];
    console.log(`Raw type byte at RCT start: 0x${rawType.toString(16)} (${rawType})`);
  }
}

test().catch(console.error);
