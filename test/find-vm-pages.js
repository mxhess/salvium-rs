import { randomx_init_cache, randomx_superscalarhash } from '../src/randomx/vendor/index.js';

const cache = randomx_init_cache('test');

// Try to find the correct VM memory size by trial and error
// Start with a reasonable minimum and increase until it works

const testPages = [33, 34, 35, 36, 50, 64, 100, 128];

for (const pages of testPages) {
  try {
    const memory = new WebAssembly.Memory({ initial: pages, maximum: pages });
    const vmImports = { env: { memory } };
    const vmInstance = new WebAssembly.Instance(cache.vm, vmImports);
    console.log('SUCCESS: VM instantiated with', pages, 'pages');
    
    // Check exports
    const exports = vmInstance.exports;
    console.log('  Exports:', Object.keys(exports));
    
    // Try to initialize
    const scratchPtr = exports.i(3);
    console.log('  Scratch ptr:', scratchPtr);
    break;
  } catch (e) {
    console.log('FAILED with', pages, 'pages:', e.message);
  }
}
