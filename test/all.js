#!/usr/bin/env node
/**
 * Master Test Runner
 *
 * Runs all salvium-js tests in sequence.
 *
 * Usage:
 *   bun test/all.js                    # Run all tests
 *   bun test/all.js --integration      # Include RPC integration tests
 *   bun test/all.js --integration URL  # Integration tests against specific daemon
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const args = process.argv.slice(2);
const runIntegration = args.includes('--integration');
const daemonUrl = args.find(a => a.startsWith('http'));

const tests = [
  { name: 'Core Tests', file: 'run.js' },
  { name: 'Blake2b Tests', file: 'blake2b.test.js' },
  { name: 'RPC Module Tests', file: 'rpc.test.js' },
  { name: 'Subaddress Tests', file: 'subaddress.test.js' },
  { name: 'Mnemonic Tests', file: 'mnemonic.test.js' },
  { name: 'Key Derivation Tests', file: 'keys.test.js' },
  { name: 'Address Generation Tests', file: 'address.test.js' },
  { name: 'Wallet Tests', file: 'wallet.test.js' },
  { name: 'Transaction Scanning Tests', file: 'scanning.test.js' },
  { name: 'Key Image Tests', file: 'keyimage.test.js' },
  { name: 'Transaction Construction Tests', file: 'transaction.test.js' },
  { name: 'Bulletproofs+ Tests', file: 'bulletproofs_plus.test.js' },
  { name: 'Mining Tests', file: 'mining.test.js' },
  { name: 'RandomX Tests', file: 'randomx.test.js' },
  { name: 'UTXO Selection Tests', file: 'utxo-selection.test.js' },
  { name: 'Transaction Builder Tests', file: 'transaction-builder.test.js' },
  { name: 'Wallet Class Tests', file: 'wallet-class.test.js' },
  { name: 'Transaction Parser Tests', file: 'transaction-parser.test.js' },
  { name: 'Wallet Storage Tests', file: 'wallet-store.test.js' },
  { name: 'Wallet Sync Tests', file: 'wallet-sync.test.js' },
  { name: 'Query System Tests', file: 'query.test.js' },
  { name: 'Connection Manager Tests', file: 'connection-manager.test.js' },
  { name: 'Offline Signing Tests', file: 'offline.test.js' },
  { name: 'Multisig Tests', file: 'multisig.test.js' },
  { name: 'Persistent Wallet Tests', file: 'persistent-wallet.test.js' },
];

if (runIntegration) {
  tests.push({
    name: 'RPC Integration Tests',
    file: 'rpc.integration.js',
    args: daemonUrl ? [daemonUrl] : []
  });
}

let totalPassed = 0;
let totalFailed = 0;

async function runTest(testConfig) {
  return new Promise((resolve) => {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Running: ${testConfig.name}`);
    console.log('='.repeat(60));

    const testPath = join(__dirname, testConfig.file);
    const testArgs = testConfig.args || [];

    let proc;
    if (testConfig.vitest) {
      // Run with vitest for tests that use describe/it/expect
      proc = spawn('bunx', ['vitest', 'run', testPath, '--reporter=verbose'], {
        stdio: 'inherit',
        cwd: join(__dirname, '..')
      });
    } else {
      proc = spawn('bun', [testPath, ...testArgs], {
        stdio: 'inherit',
        cwd: join(__dirname, '..')
      });
    }

    proc.on('close', (code) => {
      resolve(code === 0);
    });

    proc.on('error', (err) => {
      console.error(`Failed to run ${testConfig.name}: ${err.message}`);
      resolve(false);
    });
  });
}

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║               salvium-js Test Suite                        ║');
console.log('╚════════════════════════════════════════════════════════════╝');

let allPassed = true;

for (const test of tests) {
  const passed = await runTest(test);
  if (!passed) {
    allPassed = false;
    totalFailed++;
  } else {
    totalPassed++;
  }
}

console.log(`\n${'='.repeat(60)}`);
console.log('FINAL SUMMARY');
console.log('='.repeat(60));
console.log(`Test suites passed: ${totalPassed}/${tests.length}`);
console.log(`Test suites failed: ${totalFailed}/${tests.length}`);

if (allPassed) {
  console.log('\n✓ All test suites passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some test suites failed!');
  process.exit(1);
}
