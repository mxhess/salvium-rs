/**
 * Test the AssemblyScript-compiled VM
 */

import { createFullVM } from '../src/randomx/vm-full.js';

async function main() {
  console.log('=== Full Mode VM Test ===\n');

  // Create a small test dataset (just for testing)
  const testDataset = new BigInt64Array(1000 * 8);
  for (let i = 0; i < testDataset.length; i++) {
    testDataset[i] = BigInt(i * 12345);
  }

  console.log('Creating VM...');
  const vm = await createFullVM(testDataset);
  console.log('VM created\n');

  // Test hashing
  const testInput = Buffer.from('test input for randomx hashing');

  console.log('Computing hashes...');
  const start = performance.now();
  const numHashes = 5;

  for (let i = 0; i < numHashes; i++) {
    const input = Buffer.concat([testInput, Buffer.from([i])]);
    const hash = vm.calculateHash(input);
    console.log(`Hash ${i + 1}: ${Buffer.from(hash).toString('hex').substring(0, 32)}...`);
  }

  const elapsed = performance.now() - start;
  console.log(`\n${numHashes} hashes in ${elapsed.toFixed(2)}ms`);
  console.log(`Per hash: ${(elapsed / numHashes).toFixed(2)}ms`);
  console.log(`Hashrate: ${(numHashes / (elapsed / 1000)).toFixed(2)} H/s`);
}

main().catch(console.error);
