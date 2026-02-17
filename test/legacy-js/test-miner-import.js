/**
 * Test miner imports and configuration
 */

import { StratumMiner, getAvailableCores } from '../src/stratum/miner.js';
import { RandomXFullMode, RANDOMX_DATASET_SIZE } from '../src/randomx/full-mode.js';

console.log('=== Miner Import Test ===\n');

console.log('Available cores:', getAvailableCores());
console.log('Dataset size:', (RANDOMX_DATASET_SIZE / 1024 / 1024 / 1024).toFixed(2), 'GB');

// Test light mode miner creation
console.log('\nCreating light mode miner...');
const lightMiner = new StratumMiner({
  pool: 'stratum+tcp://localhost:3333',
  wallet: 'SAL1test...',
  threads: 2,
  mode: 'light'
});
console.log('Light mode miner created:', {
  mode: lightMiner.options.mode,
  threads: lightMiner.options.threads
});

// Test full mode miner creation
console.log('\nCreating full mode miner...');
const fullMiner = new StratumMiner({
  pool: 'stratum+tcp://localhost:3333',
  wallet: 'SAL1test...',
  threads: 4,
  mode: 'full'
});
console.log('Full mode miner created:', {
  mode: fullMiner.options.mode,
  threads: fullMiner.options.threads
});

console.log('\n=== All imports successful ===');
