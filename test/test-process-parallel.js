/**
 * Test Child Process Parallelism
 *
 * Uses child_process.fork() instead of worker_threads to get
 * true process isolation and parallel WASM execution.
 */

import { fork } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const workerScript = join(__dirname, 'process-worker.js');

async function testProcesses(numProcesses, hashesPerProcess) {
  console.log(`\n--- ${numProcesses} process(es), ${hashesPerProcess} hashes each ---`);

  const processes = [];
  const results = [];
  const initStart = Date.now();

  // Create processes
  for (let i = 0; i < numProcesses; i++) {
    const child = fork(workerScript, [String(i), String(hashesPerProcess)], {
      stdio: ['pipe', 'pipe', 'pipe', 'ipc']
    });

    const resultPromise = new Promise((resolve) => {
      child.on('message', (msg) => {
        if (msg.type === 'ready') {
          console.log(`  Process ${i} ready`);
        } else if (msg.type === 'done') {
          resolve(msg);
        }
      });
    });

    processes.push({ child, resultPromise });
  }

  // Wait for all to be ready
  await Promise.all(processes.map(p => new Promise(r => {
    p.child.once('message', (msg) => {
      if (msg.type === 'ready') r();
    });
  })));

  const initTime = Date.now() - initStart;
  console.log(`Init time: ${initTime}ms`);

  // Start all processes
  console.log('Starting hashing...');
  const hashStart = Date.now();
  for (const { child } of processes) {
    child.send({ type: 'start' });
  }

  // Wait for results
  const allResults = await Promise.all(processes.map(p => p.resultPromise));
  const totalTime = Date.now() - hashStart;

  let totalHashes = 0;
  for (const { workerId, hashCount, elapsed } of allResults) {
    console.log(`  Process ${workerId}: ${hashCount} hashes in ${elapsed}ms`);
    totalHashes += hashCount;
  }

  const hps = totalHashes / (totalTime / 1000);
  console.log(`Total: ${totalHashes} hashes in ${totalTime}ms (${hps.toFixed(2)} H/s)`);

  // Kill processes
  for (const { child } of processes) {
    child.kill();
  }

  return hps;
}

async function main() {
  console.log('Child Process Hash Test');
  console.log('=======================');
  console.log('(Using fork() for true process isolation)');

  const hashesPerProcess = 10;

  const hps1 = await testProcesses(1, hashesPerProcess);
  const hps2 = await testProcesses(2, hashesPerProcess);
  const hps4 = await testProcesses(4, hashesPerProcess);

  console.log('\n=== Summary ===');
  console.log(`1 process:  ${hps1.toFixed(2)} H/s`);
  console.log(`2 processes: ${hps2.toFixed(2)} H/s (${(hps2/hps1).toFixed(2)}x)`);
  console.log(`4 processes: ${hps4.toFixed(2)} H/s (${(hps4/hps1).toFixed(2)}x)`);

  if (hps4 >= hps1 * 3) {
    console.log('\n✓ Child processes scale well!');
  } else {
    console.log('\n✗ Scaling is limited (possibly memory bandwidth)');
  }
}

main().catch(console.error);
