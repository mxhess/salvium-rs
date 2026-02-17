import { randomx_init_cache, randomx_create_vm, randomx_superscalarhash } from '../src/randomx/vendor/index.js';

// Initialize cache
const key = new TextEncoder().encode('test key');
console.log('Initializing cache...');
const cache = randomx_init_cache(key);

console.log('\n=== Cache object properties ===');
console.log('cache type:', typeof cache);
console.log('cache constructor:', cache.constructor?.name);

// Check for expected properties from RxCache
console.log('\nExpected RxCache properties:');
console.log('cache.memory:', cache.memory ? 'exists' : 'missing');
console.log('cache.thunk:', cache.thunk ? 'exists' : 'missing');
console.log('cache.vm:', cache.vm ? 'exists' : 'missing');

if (cache.memory) {
  console.log('  - memory type:', cache.memory.constructor?.name);
  console.log('  - memory buffer size:', cache.memory.buffer?.byteLength);
}

if (cache.thunk) {
  console.log('  - thunk type:', cache.thunk.constructor?.name);
}

if (cache.vm) {
  console.log('  - vm type:', cache.vm.constructor?.name);
}

// Check for superscalarhash
console.log('\n=== Superscalar hash test ===');
const ssHash = randomx_superscalarhash(cache);
console.log('ssHash type:', typeof ssHash);

// Test computing a dataset item
const item0 = ssHash(0n);
console.log('item[0] result:', item0);
console.log('item[0] length:', item0?.length);
