//! FFI bindings to the vendored GhostRider C library.

use std::ffi::c_void;

#[allow(dead_code)]
extern "C" {
    /// Allocate a per-thread GhostRider context (holds 2MB scratchpad).
    /// Returns opaque pointer, or null on allocation failure.
    pub fn ghostrider_alloc_ctx() -> *mut c_void;

    /// Free a GhostRider context previously allocated with ghostrider_alloc_ctx().
    pub fn ghostrider_free_ctx(ctx: *mut c_void);

    /// Compute the full GhostRider PoW hash.
    ///
    /// Returns 0 on success, non-zero on error.
    pub fn ghostrider_hash(
        input: *const u8,
        input_len: usize,
        output: *mut u8,
        ctx: *mut c_void,
    ) -> i32;

    /// Compute an individual SPH-512 hash for testing.
    ///
    /// algo_index: 0=blake, 1=bmw, 2=groestl, 3=jh, 4=keccak, 5=skein,
    ///             6=luffa, 7=cubehash, 8=shavite, 9=simd, 10=echo,
    ///             11=hamsi, 12=fugue, 13=shabal, 14=whirlpool
    /// output: 64-byte buffer
    pub fn ghostrider_sph_hash(
        algo_index: i32,
        input: *const u8,
        input_len: usize,
        output: *mut u8,
    ) -> i32;
}
