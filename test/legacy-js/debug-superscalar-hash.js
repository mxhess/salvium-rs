/**
 * Debug: Compare superscalar program hash with C++ reference
 *
 * C++ Instruction struct layout (8 bytes):
 *   uint8_t opcode;   // offset 0
 *   uint8_t dst;      // offset 1
 *   uint8_t src;      // offset 2
 *   uint8_t mod;      // offset 3
 *   uint32_t imm32;   // offset 4-7 (little-endian)
 *
 * Expected hash for program 0: d3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61
 */

import { blake2b } from '../src/blake2b.js';
import { Blake2Generator, generateSuperscalar, SuperscalarInstructionType } from '../src/randomx/superscalar.js';

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Serialize program to bytes matching C++ layout
function serializeProgram(prog) {
  const bytes = new Uint8Array(prog.instructions.length * 8);

  for (let i = 0; i < prog.instructions.length; i++) {
    const instr = prog.instructions[i];
    const offset = i * 8;

    bytes[offset + 0] = instr.opcode & 0xff;
    bytes[offset + 1] = instr.dst & 0xff;
    bytes[offset + 2] = instr.src & 0xff;
    bytes[offset + 3] = instr.mod & 0xff;

    // imm32 as little-endian
    const imm = instr.imm32 >>> 0;
    bytes[offset + 4] = imm & 0xff;
    bytes[offset + 5] = (imm >> 8) & 0xff;
    bytes[offset + 6] = (imm >> 16) & 0xff;
    bytes[offset + 7] = (imm >> 24) & 0xff;
  }

  return bytes;
}

console.log('=== Superscalar Program Hash Debug ===\n');

const key = new TextEncoder().encode('test key 000');
const gen = new Blake2Generator(key);

// Expected hashes from C++ tests.cpp
const expectedHashes = [
  'd3a4a6623738756f77e6104469102f082eff2a3e60be7ad696285ef7dfc72a61',
  'f5e7e0bbc7e93c609003d6359208688070afb4a77165a552ff7be63b38dfbc86',
  '85ed8b11734de5b3e9836641413a8f36e99e89694f419c8cd25c3f3f16c40c5a',
  '5dd956292cf5d5704ad99e362d70098b2777b2a1730520be52f772ca48cd3bc0',
  '6f14018ca7d519e9b48d91af094c0f2d7e12e93af0228782671a8640092af9e5',
  '134be097c92e2c45a92f23208cacd89e4ce51f1009a0b900dbe83b38de11d791',
  '268f9392c20c6e31371a5131f82bd7713d3910075f2f0468baafaa1abd2f3187',
  'c668a05fd909714ed4a91e8d96d67b17e44329e88bc71e0672b529a3fc16be47',
  '99739351315840963011e4c5d8e90ad0bfed3facdcb713fe8f7138fbf01c4c94',
  '14ab53d61880471f66e80183968d97effd5492b406876060e595fcf9682f9295'
];

// Generate and hash all 10 programs
let allMatch = true;
for (let progIdx = 0; progIdx < 10; progIdx++) {
  const prog = generateSuperscalar(gen);
  const progBytes = serializeProgram(prog);
  const hash = blake2b(progBytes, 32);
  const hashHex = bytesToHex(hash);
  const match = hashHex === expectedHashes[progIdx];

  console.log(`Program ${progIdx}: size=${prog.instructions.length.toString().padStart(3)} addrReg=${prog.addressRegister} hash=${hashHex.slice(0, 16)}... ${match ? '✓' : '✗'}`);

  if (!match) {
    allMatch = false;
    console.log(`  Expected: ${expectedHashes[progIdx]}`);
    console.log(`  Got:      ${hashHex}`);
  }
}

console.log();
console.log(allMatch ? 'All 10 program hashes match!' : 'Some program hashes do not match.');
