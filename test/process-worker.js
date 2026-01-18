/**
 * Child Process Worker for RandomX Hashing
 */

const workerId = parseInt(process.argv[2]);
const hashCount = parseInt(process.argv[3]);

// Dynamic import
const { randomx_init_cache, randomx_create_vm } = await import('../src/randomx/vendor/index.js');

// Initialize
const seedHash = new TextEncoder().encode('test seed');
const cache = randomx_init_cache(seedHash);
const vm = randomx_create_vm(cache);

const template = new Uint8Array(76);
const view = new DataView(template.buffer);

// Signal ready
process.send({ type: 'ready', workerId });

// Wait for start
process.on('message', (msg) => {
  if (msg.type === 'start') {
    const start = Date.now();

    for (let i = 0; i < hashCount; i++) {
      view.setUint32(39, i, true);
      vm.calculate_hash(template);
    }

    const elapsed = Date.now() - start;
    process.send({ type: 'done', workerId, hashCount, elapsed });
  }
});
