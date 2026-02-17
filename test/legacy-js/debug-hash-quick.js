/**
 * Debug: Quick hash test with WASM cache
 */

import { RandomXContext, preloadWasm } from '../src/randomx/index.js';

console.log('=== Quick Hash Test ===\n');

// Pre-load WASM
console.log('Pre-loading WASM...');
await preloadWasm();
console.log('WASM loaded.\n');

const testKey = new TextEncoder().encode('test key 000');
const testInput = new TextEncoder().encode('This is a test');

const ctx = new RandomXContext({ wasm: true, fullMode: false });

console.log('Initializing cache (WASM)...');
const startInit = Date.now();
await ctx.init(testKey);
console.log(`Cache init: ${((Date.now() - startInit) / 1000).toFixed(1)}s\n`);

console.log('Computing hash...');
const startHash = Date.now();
const hash = ctx.hash(testInput);
const hashTime = (Date.now() - startHash) / 1000;

console.log(`Hash: ${Buffer.from(hash).toString('hex')}`);
console.log(`Expected: 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f`);
console.log(`Time: ${hashTime.toFixed(2)}s`);

const expected = '639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f';
const actual = Buffer.from(hash).toString('hex');
console.log(`\nMatch: ${actual === expected ? 'YES!' : 'NO'}`);
