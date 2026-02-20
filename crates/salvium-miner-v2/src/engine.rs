//! RandomX v2 mining engine implementing the HashAlgorithm trait.
//!
//! Wraps the vendored RandomX v2 C library. Supports both full mode
//! (2GB shared dataset) and light mode (256MB cache per VM).

use crate::ffi;
use salvium_miner::mining::HashAlgorithm;
use std::sync::Arc;

/// Wrapper to send raw pointers across threads.
/// Safety: RandomX dataset is read-only after init; VMs are per-thread.
struct RawPtr(*mut std::ffi::c_void);
unsafe impl Send for RawPtr {}
unsafe impl Sync for RawPtr {}

/// Shared dataset state, initialized once and shared by all workers (full mode).
pub struct SharedDataset {
    dataset_ptr: *mut std::ffi::c_void,
    flags: u32,
}

unsafe impl Send for SharedDataset {}
unsafe impl Sync for SharedDataset {}

impl SharedDataset {
    /// Initialize RandomX v2 cache and dataset from a seed hash (full mode, ~2GB).
    pub fn new(seed_hash: &[u8], num_init_threads: usize, use_large_pages: bool) -> Result<Arc<Self>, String> {
        let base_flags = unsafe { ffi::randomx_get_flags() } | 0x4 | 0x8; // FULL_MEM | JIT
        let (flags, using_large_pages) = if use_large_pages {
            let with_lp = base_flags | 0x1;
            let test_cache = unsafe { ffi::randomx_alloc_cache(with_lp) };
            if !test_cache.is_null() {
                unsafe { ffi::randomx_release_cache(test_cache); }
                (with_lp, true)
            } else {
                (base_flags, false)
            }
        } else {
            (base_flags, false)
        };
        eprintln!("RandomX v2 large pages: {}", if using_large_pages { "YES" } else { "NO (falling back)" });
        eprintln!("RandomX v2 flags: 0x{:x}", flags);

        // Allocate and init cache
        let cache_ptr = unsafe { ffi::randomx_alloc_cache(flags) };
        if cache_ptr.is_null() {
            return Err("Failed to allocate RandomX v2 cache".to_string());
        }
        unsafe {
            ffi::randomx_init_cache(cache_ptr, seed_hash.as_ptr(), seed_hash.len());
        }
        eprintln!("RandomX v2 cache initialized (256MB)");

        // Allocate and init dataset
        let dataset_ptr = unsafe { ffi::randomx_alloc_dataset(flags) };
        if dataset_ptr.is_null() {
            unsafe { ffi::randomx_release_cache(cache_ptr); }
            return Err("Failed to allocate RandomX v2 dataset (need ~2GB free RAM)".to_string());
        }

        let item_count = unsafe { ffi::randomx_dataset_item_count() };
        eprintln!("Generating RandomX v2 dataset ({} items, ~2GB)...", item_count);
        let start = std::time::Instant::now();

        // Multi-threaded dataset init
        let items_per_thread = item_count / num_init_threads as u64;
        let ds_shared = Arc::new(RawPtr(dataset_ptr));
        let ca_shared = Arc::new(RawPtr(cache_ptr));
        let mut init_handles = Vec::new();
        for i in 0..num_init_threads {
            let ds = Arc::clone(&ds_shared);
            let ca = Arc::clone(&ca_shared);
            let start_item = i as u64 * items_per_thread;
            let count = if i == num_init_threads - 1 {
                item_count - start_item
            } else {
                items_per_thread
            };
            init_handles.push(std::thread::spawn(move || unsafe {
                ffi::randomx_init_dataset(ds.0, ca.0, start_item, count);
            }));
        }
        for h in init_handles {
            let _ = h.join();
        }
        eprintln!("RandomX v2 dataset ready in {:.1}s", start.elapsed().as_secs_f64());

        // Release cache (dataset is self-contained after init)
        unsafe { ffi::randomx_release_cache(cache_ptr); }

        Ok(Arc::new(Self { dataset_ptr, flags }))
    }

    /// Create a VM for this dataset (one per worker thread).
    pub fn create_vm(&self) -> Result<*mut std::ffi::c_void, String> {
        let vm_ptr = unsafe {
            ffi::randomx_create_vm(self.flags, std::ptr::null_mut(), self.dataset_ptr)
        };
        if vm_ptr.is_null() {
            Err("Failed to create RandomX v2 VM".to_string())
        } else {
            Ok(vm_ptr)
        }
    }
}

/// Light-mode RandomX v2 state (256MB cache, no dataset).
pub struct LightCache {
    cache_ptr: *mut std::ffi::c_void,
    flags: u32,
}

unsafe impl Send for LightCache {}
unsafe impl Sync for LightCache {}

impl LightCache {
    /// Initialize a light-mode cache (256MB) for RandomX v2.
    pub fn new(seed_hash: &[u8], use_large_pages: bool) -> Result<Arc<Self>, String> {
        let base_flags = unsafe { ffi::randomx_get_flags() } | 0x8; // JIT only, no FULL_MEM
        let (flags, _using_large_pages) = if use_large_pages {
            let with_lp = base_flags | 0x1;
            let test_cache = unsafe { ffi::randomx_alloc_cache(with_lp) };
            if !test_cache.is_null() {
                unsafe { ffi::randomx_release_cache(test_cache); }
                (with_lp, true)
            } else {
                (base_flags, false)
            }
        } else {
            (base_flags, false)
        };

        let cache_ptr = unsafe { ffi::randomx_alloc_cache(flags) };
        if cache_ptr.is_null() {
            return Err("Failed to allocate RandomX v2 light cache".to_string());
        }
        unsafe {
            ffi::randomx_init_cache(cache_ptr, seed_hash.as_ptr(), seed_hash.len());
        }

        Ok(Arc::new(Self { cache_ptr, flags }))
    }

    /// Create a light-mode VM for this cache.
    pub fn create_vm(&self) -> Result<*mut std::ffi::c_void, String> {
        let vm_ptr = unsafe {
            ffi::randomx_create_vm(self.flags, self.cache_ptr, std::ptr::null_mut())
        };
        if vm_ptr.is_null() {
            Err("Failed to create RandomX v2 light VM".to_string())
        } else {
            Ok(vm_ptr)
        }
    }
}

impl Drop for LightCache {
    fn drop(&mut self) {
        unsafe { ffi::randomx_release_cache(self.cache_ptr); }
    }
}

/// Per-thread RandomX v2 hasher implementing HashAlgorithm.
pub struct RandomXV2Engine {
    vm_ptr: *mut std::ffi::c_void,
    // Hold a reference to keep the dataset/cache alive
    _dataset: Option<Arc<SharedDataset>>,
    _cache: Option<Arc<LightCache>>,
}

// Safety: each VM is used by exactly one thread
unsafe impl Send for RandomXV2Engine {}

impl RandomXV2Engine {
    /// Create a full-mode engine (shared 2GB dataset).
    pub fn new(dataset: Arc<SharedDataset>) -> Result<Self, String> {
        let vm_ptr = dataset.create_vm()?;
        Ok(Self {
            vm_ptr,
            _dataset: Some(dataset),
            _cache: None,
        })
    }

    /// Create a light-mode engine (256MB cache, slower but less memory).
    pub fn new_light(cache: Arc<LightCache>) -> Result<Self, String> {
        let vm_ptr = cache.create_vm()?;
        Ok(Self {
            vm_ptr,
            _dataset: None,
            _cache: Some(cache),
        })
    }
}

impl HashAlgorithm for RandomXV2Engine {
    fn name(&self) -> &str {
        "RandomX v2"
    }

    fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe {
            ffi::randomx_calculate_hash(
                self.vm_ptr,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
            );
        }
        output
    }
}

impl Drop for RandomXV2Engine {
    fn drop(&mut self) {
        unsafe {
            ffi::randomx_destroy_vm(self.vm_ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_light_engine_with_key(key: &[u8]) -> RandomXV2Engine {
        let cache = LightCache::new(key, false).expect("cache init failed");
        RandomXV2Engine::new_light(cache).expect("engine init failed")
    }

    fn make_light_engine() -> RandomXV2Engine {
        make_light_engine_with_key(&[0u8; 32])
    }

    #[test]
    fn test_randomx_v2_hash_produces_nonzero_output() {
        let mut engine = make_light_engine();
        let input = b"test input for RandomX v2 hash verification";
        let hash = engine.hash(input);
        assert!(!hash.iter().all(|&b| b == 0), "hash should not be all zeros");
    }

    #[test]
    fn test_randomx_v2_hash_is_deterministic() {
        let mut engine = make_light_engine();
        let input = b"deterministic test input for v2";
        let hash1 = engine.hash(input);
        let hash2 = engine.hash(input);
        assert_eq!(hash1, hash2, "same input must produce same hash");
    }

    #[test]
    fn test_randomx_v2_hash_different_inputs() {
        let mut engine = make_light_engine();
        let hash1 = engine.hash(b"input A for randomx v2 testing");
        let hash2 = engine.hash(b"input B for randomx v2 testing");
        assert_ne!(hash1, hash2, "different inputs should produce different hashes");
    }

    #[test]
    fn test_randomx_v2_hash_trait_name() {
        let engine = make_light_engine();
        assert_eq!(engine.name(), "RandomX v2");
        assert!(engine.needs_reinit_on_seed_change());
    }

    // ── Official test vectors from RandomX tests.cpp ──────────────────

    /// Test vector A: key="test key 000", input="This is a test"
    /// Expected hash: 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f
    #[test]
    fn test_randomx_v2_official_vector_a() {
        let mut engine = make_light_engine_with_key(b"test key 000");
        let hash = engine.hash(b"This is a test");
        let expected = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f";
        let actual = hex::encode(hash);
        assert_eq!(actual, expected,
            "RandomX v2 vector A mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    /// Test vector B: key="test key 000", input="Lorem ipsum dolor sit amet"
    /// Expected hash: 300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969
    #[test]
    fn test_randomx_v2_official_vector_b() {
        let mut engine = make_light_engine_with_key(b"test key 000");
        let hash = engine.hash(b"Lorem ipsum dolor sit amet");
        let expected = "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969";
        let actual = hex::encode(hash);
        assert_eq!(actual, expected,
            "RandomX v2 vector B mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    /// Test vector C: key="test key 000", input="sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    /// Expected hash: c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8
    #[test]
    fn test_randomx_v2_official_vector_c() {
        let mut engine = make_light_engine_with_key(b"test key 000");
        let hash = engine.hash(b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua");
        let expected = "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8";
        let actual = hex::encode(hash);
        assert_eq!(actual, expected,
            "RandomX v2 vector C mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    /// Test vector D: key="test key 001" (different key!), same input as C
    /// Expected hash: e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc
    #[test]
    fn test_randomx_v2_official_vector_d() {
        let mut engine = make_light_engine_with_key(b"test key 001");
        let hash = engine.hash(b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua");
        let expected = "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc";
        let actual = hex::encode(hash);
        assert_eq!(actual, expected,
            "RandomX v2 vector D mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    /// Test vector E: key="test key 001", hex-encoded block blob input
    /// Expected hash: c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1
    #[test]
    fn test_randomx_v2_official_vector_e() {
        let mut engine = make_light_engine_with_key(b"test key 001");
        let input = hex::decode(
            "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416"
        ).expect("invalid hex");
        let hash = engine.hash(&input);
        let expected = "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1";
        let actual = hex::encode(hash);
        assert_eq!(actual, expected,
            "RandomX v2 vector E (block blob) mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    /// Test vector: commitment = hash then Blake2b(input || hash)
    /// key="test key 000", input="This is a test"
    /// Expected commitment: d53ccf348b75291b7be76f0a7ac8208bbced734b912f6fca60539ab6f86be919
    #[test]
    fn test_randomx_v2_commitment() {
        let mut engine = make_light_engine_with_key(b"test key 000");
        let input = b"This is a test";
        let hash = engine.hash(input);

        // Now compute commitment: Blake2b(input || hash)
        let mut commitment = [0u8; 32];
        unsafe {
            ffi::randomx_calculate_commitment(
                input.as_ptr(),
                input.len(),
                hash.as_ptr(),
                commitment.as_mut_ptr(),
            );
        }
        let expected = "d53ccf348b75291b7be76f0a7ac8208bbced734b912f6fca60539ab6f86be919";
        let actual = hex::encode(commitment);
        assert_eq!(actual, expected,
            "RandomX v2 commitment mismatch!\n  got:    {}\n  expect: {}", actual, expected);
    }

    // ── Mining loop integration test ──────────────────────────────────

    #[test]
    fn test_randomx_v2_mining_loop_smoke() {
        use salvium_miner::mining::MiningLoop;
        use salvium_miner::miner::MiningJob;
        use std::sync::atomic::Ordering;

        let seed = [42u8; 32];
        let cache = LightCache::new(&seed, false).expect("cache init failed");

        let mining_loop = MiningLoop::new(1, move |_| {
            let engine = RandomXV2Engine::new_light(cache.clone())?;
            Ok(Box::new(engine))
        }).expect("failed to create mining loop");

        // Create a fake job with trivial difficulty
        let mut hashing_blob = vec![0u8; 76];
        hashing_blob[0] = 10;
        hashing_blob[1] = 10;
        hashing_blob[2] = 1;

        mining_loop.send_job(MiningJob {
            job_id: 1,
            hashing_blob,
            template_blob: vec![0u8; 200],
            difficulty: 1,
            height: 100,
        });

        // RandomX light mode is slow (~4-10 H/s in debug), give it time
        std::thread::sleep(std::time::Duration::from_secs(3));

        let hashes = mining_loop.hash_count.load(Ordering::Relaxed);
        eprintln!("RandomX v2 light-mode hashes in 3s: {}", hashes);
        assert!(hashes > 0, "should have computed at least one hash");

        // With difficulty=1, every hash should be a valid block
        let block = mining_loop.try_recv_block();
        assert!(block.is_some(), "should have found a block with difficulty=1");

        let block = block.unwrap();
        assert!(!block.hash.iter().all(|&b| b == 0), "found block hash should be non-zero");

        mining_loop.stop();
    }
}
