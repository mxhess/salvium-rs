import { randomx_init_cache, randomx_create_vm, randomx_superscalarhash } from '../src/randomx/vendor/index.js';

const cache = randomx_init_cache('test');
console.log('Cache properties:');
console.log('  cache.memory type:', cache.memory.constructor.name);
console.log('  cache.memory buffer size:', cache.memory.buffer.byteLength);
console.log('  cache.thunk type:', cache.thunk.constructor.name);
console.log('  cache.vm type:', cache.vm.constructor.name);

// Create superscalar hash
const ssHash = randomx_superscalarhash(cache);
console.log('\nSuperscalar hash function created');
console.log('  ssHash type:', typeof ssHash);

// Test one item
const item0 = ssHash(0n);
console.log('  item[0]:', item0);

// Check WebAssembly module imports
console.log('\nWebAssembly module analysis:');

// Get imports for cache.vm
const vmImports = WebAssembly.Module.imports(cache.vm);
console.log('VM module imports:');
for (const imp of vmImports) {
  console.log('  -', imp.module, '/', imp.name, ':', imp.kind);
}

// Get exports for cache.vm
const vmExports = WebAssembly.Module.exports(cache.vm);
console.log('\nVM module exports:');
for (const exp of vmExports) {
  console.log('  -', exp.name, ':', exp.kind);
}
