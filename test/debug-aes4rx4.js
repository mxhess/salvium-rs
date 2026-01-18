/**
 * Debug: Verify fillAes4Rx4 output matches C++ reference
 *
 * This tests the Program struct generation, which has:
 *   entropyBuffer[16] = 128 bytes
 *   programBuffer[256] = 2048 bytes
 *   Total = 2176 bytes filled by fillAes4Rx4
 */

import { fillAes4Rx4 } from '../src/randomx/aes.js';
import { blake2b } from '../src/blake2b.js';

function bytesToHex(bytes, limit = bytes.length) {
  return Array.from(bytes.slice(0, limit)).map(b => b.toString(16).padStart(2, '0')).join('');
}

console.log('=== fillAes4Rx4 Debug ===\n');

// Seed is tempHash from blake2b("This is a test", 64)
const input = new TextEncoder().encode('This is a test');
const tempHash = blake2b(input, 64);

console.log('Input: "This is a test"');
console.log(`TempHash (64 bytes): ${bytesToHex(tempHash)}`);
console.log();

// Generate program struct (2176 bytes)
const ENTROPY_SIZE = 128;
const PROGRAM_BYTES = 256 * 8;  // 2048
const progData = fillAes4Rx4(tempHash, new Uint8Array(ENTROPY_SIZE + PROGRAM_BYTES));

console.log(`Program struct size: ${progData.length} bytes`);
console.log();

console.log('First 64 bytes of entropy (should be first AES output):');
console.log(`  ${bytesToHex(progData, 64)}`);
console.log();

console.log('Bytes 64-128 of entropy:');
console.log(`  ${bytesToHex(progData.slice(64, 128))}`);
console.log();

console.log('First 64 bytes of program (bytes 128-192):');
console.log(`  ${bytesToHex(progData.slice(128, 192))}`);
console.log();

// Parse first 8 instructions
console.log('First 8 parsed instructions:');
for (let i = 0; i < 8; i++) {
  const offset = ENTROPY_SIZE + i * 8;
  const opcode = progData[offset];
  const dst = progData[offset + 1] & 7;
  const src = (progData[offset + 1] >> 4) & 7;
  const mod = progData[offset + 2];
  const imm32 = progData[offset + 4] |
               (progData[offset + 5] << 8) |
               (progData[offset + 6] << 16) |
               (progData[offset + 7] << 24);
  console.log(`  [${i}] opcode=${opcode.toString(16).padStart(2,'0')} dst=${dst} src=${src} mod=${mod.toString(16).padStart(2,'0')} imm32=${(imm32 >>> 0).toString(16).padStart(8,'0')}`);
}
