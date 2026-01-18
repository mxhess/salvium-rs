import { randomx_init_cache, randomx_create_vm } from '../src/randomx/vendor/index.js';

const cache = randomx_init_cache('test');

console.log('Cache memory:');
console.log('  buffer size:', cache.memory.buffer.byteLength);
console.log('  pages:', cache.memory.buffer.byteLength / 65536);

// The vendored library creates VM successfully - let's examine it
const vm = randomx_create_vm(cache);
console.log('\nVM created successfully');
console.log('VM methods:', Object.keys(vm));

// Check if we can hash
const hash = vm.calculate_hex_hash('test');
console.log('\nTest hash:', hash);
