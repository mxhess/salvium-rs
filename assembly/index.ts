/**
 * RandomX WASM Module
 *
 * AssemblyScript implementation of RandomX components.
 * Native u64 operations for maximum performance.
 */

// Re-export Blake2b
export {
  blake2b,
  blake2b_init,
  blake2b_update,
  blake2b_final
} from './blake2b';

// Re-export Argon2d
export {
  argon2d_init,
  argon2d_fill_segment,
  argon2d_write_block,
  argon2d_read_block,
  argon2d_xor_block,
  argon2d_test_index_alpha,
  argon2d_debug_blockR_ptr
} from './argon2d';

// Re-export Superscalar
export {
  superscalar_init,
  init_registers,
  exec_instruction,
  exec_imul_rcp,
  get_cache_block,
  xor_cache_block,
  mix_cache_block,
  get_address_reg,
  write_registers,
  read_registers,
  get_reg,
  set_reg,
  reciprocal,
  // Optimized batch functions
  setup_programs,
  set_program_meta,
  init_dataset_item,
  init_dataset_batch,
  init_dataset_batch_simd
} from './superscalar';

// Re-export VM (Full mode support)
export {
  vm_init,
  vm_reset,
  vm_set_config,
  vm_set_a_registers,
  vm_set_dataset_size,
  vm_execute,
  vm_get_register_file,
  vm_set_r,
  vm_get_r
} from './vm';

// Re-export AES (for scratchpad fill)
export {
  fillScratchpad,
  mixScratchpad
} from './aes';

// Memory management helpers
export function allocate(size: u32): usize {
  return heap.alloc(size);
}

export function deallocate(ptr: usize): void {
  heap.free(ptr);
}

// Simple test function to verify WASM is working
export function add(a: u64, b: u64): u64 {
  return a + b;
}

export function rotr64(x: u64, n: u32): u64 {
  return (x >> n) | (x << (64 - n));
}

// Test BlaMka function (core of Argon2d)
export function fBlaMka(x: u64, y: u64): u64 {
  const mask32: u64 = 0xFFFFFFFF;
  const xy = (x & mask32) * (y & mask32);
  return x + y + (xy << 1);
}
