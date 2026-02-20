//! FFI bindings to the vendored RandomX v2 C library.
//!
//! Same API surface as RandomX v1 plus `randomx_calculate_commitment`.

#[allow(dead_code)]
extern "C" {
    pub fn randomx_get_flags() -> u32;

    pub fn randomx_alloc_cache(flags: u32) -> *mut std::ffi::c_void;
    pub fn randomx_init_cache(
        cache: *mut std::ffi::c_void,
        key: *const u8,
        key_size: usize,
    );
    pub fn randomx_release_cache(cache: *mut std::ffi::c_void);

    pub fn randomx_alloc_dataset(flags: u32) -> *mut std::ffi::c_void;
    pub fn randomx_dataset_item_count() -> u64;
    pub fn randomx_init_dataset(
        dataset: *mut std::ffi::c_void,
        cache: *mut std::ffi::c_void,
        start_item: u64,
        item_count: u64,
    );
    pub fn randomx_release_dataset(dataset: *mut std::ffi::c_void);

    pub fn randomx_create_vm(
        flags: u32,
        cache: *mut std::ffi::c_void,
        dataset: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    pub fn randomx_destroy_vm(vm: *mut std::ffi::c_void);

    pub fn randomx_calculate_hash(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
    );
    pub fn randomx_calculate_hash_first(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: usize,
    );
    pub fn randomx_calculate_hash_next(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
    );
    pub fn randomx_calculate_hash_last(
        vm: *mut std::ffi::c_void,
        output: *mut u8,
    );

    /// v2-specific: calculate commitment = Blake2b(input || hash)
    pub fn randomx_calculate_commitment(
        input: *const u8,
        input_size: usize,
        hash_in: *const u8,
        com_out: *mut u8,
    );
}
