#!/usr/bin/env bun
/**
 * Debug script to analyze a transaction that fails to parse
 */

import { createDaemonRPC } from '../src/rpc/index.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { decodeVarint, RCT_TYPE } from '../src/transaction.js';

const DAEMON_URL = process.env.DAEMON_URL || 'http://core2.whiskymine.io:19081';
const TX_HASH = process.argv[2] || 'e2f1b68ca90f6d2c374d86f983ec8a512530f90d05cc63314b55dfa85ee9a0ef';

async function main() {
  console.log(`Fetching transaction: ${TX_HASH}`);
  console.log(`From daemon: ${DAEMON_URL}\n`);

  const daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 30000 });

  const response = await daemon.getTransactions([TX_HASH], { decode_as_json: true });
  if (!response.success || !response.result.txs?.[0]) {
    console.error('Failed to fetch transaction:', response.error?.message);
    process.exit(1);
  }

  const txData = response.result.txs[0];
  const txBlob = hexToBytes(txData.as_hex);

  console.log(`Transaction blob length: ${txBlob.length} bytes`);
  console.log(`Transaction JSON available: ${!!txData.as_json}\n`);

  // FIRST: Show daemon's interpretation (the ground truth)
  if (txData.as_json) {
    const json = JSON.parse(txData.as_json);
    console.log(`=== DAEMON'S INTERPRETATION (ground truth) ===`);
    console.log(`version: ${json.version}`);
    console.log(`unlock_time: ${json.unlock_time}`);
    console.log(`vin count: ${json.vin?.length}`);
    console.log(`vout count: ${json.vout?.length}`);
    console.log(`extra length: ${json.extra?.length}`);
    if (json.type !== undefined) console.log(`type (Salvium tx_type): ${json.type}`);
    if (json.amount_burnt !== undefined) console.log(`amount_burnt: ${json.amount_burnt}`);
    if (json.rct_signatures) {
      console.log(`rct_signatures.type: ${json.rct_signatures.type}`);
      console.log(`rct_signatures.txnFee: ${json.rct_signatures.txnFee}`);
      console.log(`rct_signatures.ecdhInfo count: ${json.rct_signatures.ecdhInfo?.length}`);
      console.log(`rct_signatures.outPk count: ${json.rct_signatures.outPk?.length}`);
    }
    console.log();

    // Show first input
    if (json.vin?.[0]) {
      console.log(`First input:`, JSON.stringify(json.vin[0], null, 2).slice(0, 500));
    }
    // Show first output
    if (json.vout?.[0]) {
      console.log(`First output:`, JSON.stringify(json.vout[0], null, 2));
    }
    console.log();
  }

  console.log(`=== FIRST 100 BYTES HEX ===`);
  console.log(bytesToHex(txBlob.slice(0, 100)));
  console.log();

  // Parse prefix manually to get to RCT section
  let offset = 0;

  // Version
  const version = decodeVarint(txBlob, offset);
  offset += version.bytesRead;
  console.log(`Version: ${version.value}`);

  // Unlock time
  const unlockTime = decodeVarint(txBlob, offset);
  offset += unlockTime.bytesRead;
  console.log(`Unlock time: ${unlockTime.value}`);

  // Input count
  const inputCount = decodeVarint(txBlob, offset);
  offset += inputCount.bytesRead;
  console.log(`Input count: ${inputCount.value}`);

  // Skip inputs
  for (let i = 0; i < Number(inputCount.value); i++) {
    const inputType = txBlob[offset++];
    if (inputType === 0x02) { // ToKey
      const amount = decodeVarint(txBlob, offset);
      offset += amount.bytesRead;
      const keyOffsetCount = decodeVarint(txBlob, offset);
      offset += keyOffsetCount.bytesRead;
      for (let j = 0; j < Number(keyOffsetCount.value); j++) {
        const keyOffset = decodeVarint(txBlob, offset);
        offset += keyOffset.bytesRead;
      }
      offset += 32; // key_image
    }
    if (i === 0) console.log(`First input type: ${inputType.toString(16)}`);
  }
  console.log(`Offset after inputs: ${offset}`);

  // Output count
  const outputCount = decodeVarint(txBlob, offset);
  offset += outputCount.bytesRead;
  console.log(`Output count: ${outputCount.value}`);

  // Skip outputs
  for (let i = 0; i < Number(outputCount.value); i++) {
    const amount = decodeVarint(txBlob, offset);
    offset += amount.bytesRead;
    const outType = txBlob[offset++];

    if (i === 0) console.log(`First output type: ${outType.toString(16)}`);

    if (outType === 0x02) { // ToKey
      offset += 32; // pubkey
    } else if (outType === 0x03) { // ToTaggedKey
      offset += 32; // pubkey
      // asset_type string
      const assetLen = decodeVarint(txBlob, offset);
      offset += assetLen.bytesRead;
      offset += Number(assetLen.value); // asset_type bytes
      const outUnlock = decodeVarint(txBlob, offset);
      offset += outUnlock.bytesRead;
      offset += 1; // view_tag
    } else if (outType === 0x04) { // CARROT
      offset += 32; // pubkey
      const assetLen = decodeVarint(txBlob, offset);
      offset += assetLen.bytesRead;
      offset += Number(assetLen.value);
      offset += 3;  // view_tag (3 bytes)
      offset += 16; // encrypted_janus_anchor
    }
  }
  console.log(`Offset after outputs: ${offset}`);

  // Extra
  const extraLen = decodeVarint(txBlob, offset);
  offset += extraLen.bytesRead;
  offset += Number(extraLen.value);
  console.log(`Extra length: ${extraLen.value}`);
  console.log(`Offset after extra: ${offset}`);

  // Now we're at RCT section
  console.log(`\n=== RCT Section ===`);
  const rctStartOffset = offset;
  const rctType = txBlob[offset++];
  console.log(`RCT type: ${rctType} (${Object.entries(RCT_TYPE).find(([k,v]) => v === rctType)?.[0] || 'unknown'})`);

  if (rctType === 0) {
    console.log('Null RCT type - coinbase transaction');
    return;
  }

  // Fee
  const fee = decodeVarint(txBlob, offset);
  offset += fee.bytesRead;
  console.log(`Fee: ${fee.value}`);

  // ECDH info (8 bytes per output)
  const ecdhStart = offset;
  offset += 8 * Number(outputCount.value);
  console.log(`ECDH info: ${Number(outputCount.value)} entries (${offset - ecdhStart} bytes)`);

  // outPk (32 bytes per output)
  const outPkStart = offset;
  offset += 32 * Number(outputCount.value);
  console.log(`outPk: ${Number(outputCount.value)} entries (${offset - outPkStart} bytes)`);

  // p_r (32 bytes) - Salvium specific
  const p_r = bytesToHex(txBlob.slice(offset, offset + 32));
  offset += 32;
  console.log(`p_r: ${p_r.slice(0, 32)}...`);

  console.log(`\nOffset before salvium_data: ${offset}`);
  console.log(`Remaining bytes: ${txBlob.length - offset}`);

  // Now parse salvium_data_t
  if (rctType === RCT_TYPE.SalviumZero || rctType === RCT_TYPE.SalviumOne) {
    console.log(`\n=== salvium_data_t ===`);

    // salvium_data_type (varint)
    const dataType = decodeVarint(txBlob, offset);
    offset += dataType.bytesRead;
    console.log(`salvium_data_type: ${dataType.value}`);

    // pr_proof (96 bytes)
    console.log(`pr_proof: ${bytesToHex(txBlob.slice(offset, offset + 32)).slice(0, 32)}... (96 bytes)`);
    offset += 96;

    // sa_proof (96 bytes)
    console.log(`sa_proof: ${bytesToHex(txBlob.slice(offset, offset + 32)).slice(0, 32)}... (96 bytes)`);
    offset += 96;

    console.log(`Offset after proofs: ${offset}`);
    console.log(`Remaining bytes: ${txBlob.length - offset}`);

    // If type 1 (SalviumZeroAudit), there's more data
    if (Number(dataType.value) === 1) {
      console.log(`\n=== SalviumZeroAudit additional fields ===`);

      // cz_proof (96 bytes)
      console.log(`cz_proof: ${bytesToHex(txBlob.slice(offset, offset + 32)).slice(0, 32)}... (96 bytes)`);
      offset += 96;

      // input_verification_data count
      const ivdCount = decodeVarint(txBlob, offset);
      offset += ivdCount.bytesRead;
      console.log(`input_verification_data count: ${ivdCount.value}`);

      // Parse first input_verification_data entry to debug
      if (Number(ivdCount.value) > 0) {
        console.log(`\nFirst input_verification_data entry:`);

        // aR (32 bytes)
        console.log(`  aR: ${bytesToHex(txBlob.slice(offset, offset + 32)).slice(0, 32)}...`);
        offset += 32;

        // amount (varint)
        const amount = decodeVarint(txBlob, offset);
        offset += amount.bytesRead;
        console.log(`  amount: ${amount.value}`);

        // i (varint)
        const idx = decodeVarint(txBlob, offset);
        offset += idx.bytesRead;
        console.log(`  i: ${idx.value}`);

        // origin_tx_type (varint)
        const originType = decodeVarint(txBlob, offset);
        offset += originType.bytesRead;
        console.log(`  origin_tx_type: ${originType.value}`);

        console.log(`  Offset after first entry: ${offset}`);
        console.log(`  Next bytes: ${bytesToHex(txBlob.slice(offset, offset + 16))}`);

        if (Number(originType.value) !== 0) {
          console.log(`\n  origin_tx_type != 0, reading stake fields:`);
          // aR_stake (32 bytes)
          console.log(`  aR_stake: ${bytesToHex(txBlob.slice(offset, offset + 32)).slice(0, 32)}...`);
          offset += 32;

          // i_stake (varint) - THIS IS WHERE THE ERROR OCCURS
          console.log(`  Bytes at i_stake position: ${bytesToHex(txBlob.slice(offset, offset + 10))}`);
          try {
            const iStake = decodeVarint(txBlob, offset);
            offset += iStake.bytesRead;
            console.log(`  i_stake: ${iStake.value}`);
          } catch (e) {
            console.log(`  i_stake parse error: ${e.message}`);
            console.log(`  This confirms the format mismatch!`);
          }
        }
      }
    }
  }

  console.log(`\n=== Summary ===`);
  console.log(`Total bytes: ${txBlob.length}`);
  console.log(`Parsed up to: ${offset}`);
  console.log(`Remaining: ${txBlob.length - offset}`);
}

main().catch(console.error);
