//! Multi-threaded RandomX mining engine
//!
//! Full mode: uses direct C FFI to share a single 2GB dataset across worker VMs.
//! Light mode: uses randomx-rs Rust API with per-thread 256MB caches.

use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

// Direct C FFI for dataset sharing (the Rust wrapper doesn't support this)
extern "C" {
    fn randomx_alloc_dataset(flags: u32) -> *mut std::ffi::c_void;
    fn randomx_init_dataset(
        dataset: *mut std::ffi::c_void,
        cache: *mut std::ffi::c_void,
        start_item: u64,
        item_count: u64,
    );
    fn randomx_dataset_item_count() -> u64;
    fn randomx_create_vm(
        flags: u32,
        cache: *mut std::ffi::c_void,
        dataset: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn randomx_destroy_vm(vm: *mut std::ffi::c_void);
    fn randomx_calculate_hash(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: u64,
        output: *mut u8,
    );
    fn randomx_alloc_cache(flags: u32) -> *mut std::ffi::c_void;
    fn randomx_init_cache(
        cache: *mut std::ffi::c_void,
        key: *const u8,
        key_size: u64,
    );
    fn randomx_release_cache(cache: *mut std::ffi::c_void);
    fn randomx_release_dataset(dataset: *mut std::ffi::c_void);
    fn randomx_get_flags() -> u32;
    fn randomx_calculate_hash_first(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: u64,
    );
    fn randomx_calculate_hash_next(
        vm: *mut std::ffi::c_void,
        input: *const u8,
        input_size: u64,
        output: *mut u8,
    );
    fn randomx_calculate_hash_last(
        vm: *mut std::ffi::c_void,
        output: *mut u8,
    );
}

/// A found block ready for submission
pub struct FoundBlock {
    pub nonce: u32,
    pub hash: Vec<u8>,
    pub blob_hex: String,
    pub job_id: u64,
}

/// Job data sent to worker threads
#[derive(Clone)]
pub struct MiningJob {
    pub job_id: u64,
    pub hashing_blob: Vec<u8>,
    pub template_blob: Vec<u8>,
    pub difficulty: u128,
    pub height: u64,
}

/// Wrapper to send raw pointers across threads.
/// Safety: RandomX dataset is read-only after init; VMs are per-thread.
struct RawPtr(*mut std::ffi::c_void);
unsafe impl Send for RawPtr {}
unsafe impl Sync for RawPtr {}

/// Mining engine managing worker threads
pub struct MiningEngine {
    pub hash_count: Arc<AtomicU64>,
    pub running: Arc<AtomicBool>,
    result_rx: mpsc::Receiver<FoundBlock>,
    job_senders: Vec<mpsc::Sender<MiningJob>>,
    _handles: Vec<thread::JoinHandle<()>>,
}

impl MiningEngine {
    /// Initialize the mining engine with full mode (shared 2GB dataset, direct C FFI)
    pub fn new_full(
        num_threads: usize,
        seed_hash: &[u8],
        use_large_pages: bool,
    ) -> Result<Self, String> {
        let base_flags = unsafe { randomx_get_flags() } | 0x4 | 0x8;
        let (flags, using_large_pages) = if use_large_pages {
            let with_lp = base_flags | 0x1; // FLAG_LARGE_PAGES
            let test_cache = unsafe { randomx_alloc_cache(with_lp) };
            if !test_cache.is_null() {
                unsafe { randomx_release_cache(test_cache); }
                (with_lp, true)
            } else {
                (base_flags, false)
            }
        } else {
            (base_flags, false)
        };
        eprintln!("Large pages: {}", if using_large_pages { "YES" } else { "NO (falling back)" });
        eprintln!("RandomX flags: 0x{:x}", flags);

        // Allocate and init cache via C FFI
        let cache_ptr = unsafe { randomx_alloc_cache(flags) };
        if cache_ptr.is_null() {
            return Err("Failed to allocate RandomX cache".to_string());
        }
        unsafe {
            randomx_init_cache(cache_ptr, seed_hash.as_ptr(), seed_hash.len() as u64);
        }
        eprintln!("Cache initialized (256MB)");

        // Allocate and init dataset
        let dataset_ptr = unsafe { randomx_alloc_dataset(flags) };
        if dataset_ptr.is_null() {
            unsafe { randomx_release_cache(cache_ptr); }
            return Err("Failed to allocate RandomX dataset (need ~2GB free RAM)".to_string());
        }

        let item_count = unsafe { randomx_dataset_item_count() };
        eprintln!("Generating dataset ({} items, ~2GB)...", item_count);
        let start = std::time::Instant::now();

        // Initialize dataset using multiple threads for speed
        let items_per_thread = item_count / num_threads as u64;
        let ds_shared = Arc::new(RawPtr(dataset_ptr));
        let ca_shared = Arc::new(RawPtr(cache_ptr));
        let mut init_handles = Vec::new();
        for i in 0..num_threads {
            let ds = Arc::clone(&ds_shared);
            let ca = Arc::clone(&ca_shared);
            let start_item = i as u64 * items_per_thread;
            let count = if i == num_threads - 1 {
                item_count - start_item
            } else {
                items_per_thread
            };
            init_handles.push(thread::spawn(move || unsafe {
                randomx_init_dataset(ds.0, ca.0, start_item, count);
            }));
        }
        for h in init_handles {
            let _ = h.join();
        }

        eprintln!("Dataset ready in {:.1}s", start.elapsed().as_secs_f64());

        // Now create per-thread VMs sharing the dataset
        let hash_count = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let (result_tx, result_rx) = mpsc::channel();
        let mut job_senders = Vec::new();
        let mut handles = Vec::new();

        for worker_id in 0..num_threads {
            let (job_tx, job_rx) = mpsc::channel::<MiningJob>();
            job_senders.push(job_tx);

            let hash_count = Arc::clone(&hash_count);
            let running = Arc::clone(&running);
            let result_tx = result_tx.clone();
            let ds = Arc::clone(&ds_shared);
            let nonce_start = (worker_id as u64 * (u32::MAX as u64 / num_threads as u64)) as u32;

            let handle = thread::spawn(move || {
                let vm_ptr = unsafe {
                    randomx_create_vm(flags, std::ptr::null_mut(), ds.0)
                };
                if vm_ptr.is_null() {
                    eprintln!("Worker {} failed to create VM", worker_id);
                    return;
                }

                eprintln!("Worker {} ready", worker_id);

                worker_loop(
                    vm_ptr, &job_rx, &running, &hash_count, &result_tx, nonce_start,
                );

                unsafe { randomx_destroy_vm(vm_ptr); }
            });

            handles.push(handle);
        }

        // Release cache (dataset is self-contained after init)
        unsafe { randomx_release_cache(cache_ptr); }

        // NOTE: dataset_ptr is intentionally leaked — it must outlive all worker VMs.
        // In a long-running miner this is fine; the OS reclaims on exit.

        Ok(Self {
            hash_count,
            running,
            result_rx,
            job_senders,
            _handles: handles,
        })
    }

    /// Initialize light mode (each thread has own 256MB cache via Rust API)
    pub fn new_light(
        num_threads: usize,
        seed_hash: &[u8],
        use_large_pages: bool,
    ) -> Result<Self, String> {
        let mut flags = RandomXFlag::get_recommended_flags();
        if use_large_pages {
            let raw_flags = flags.bits() | 0x1; // FLAG_LARGE_PAGES
            let test_cache = unsafe { randomx_alloc_cache(raw_flags) };
            if !test_cache.is_null() {
                unsafe { randomx_release_cache(test_cache); }
                flags |= RandomXFlag::FLAG_LARGE_PAGES;
                eprintln!("Large pages: YES");
            } else {
                eprintln!("Large pages: NO (falling back)");
            }
        } else {
            eprintln!("Large pages: disabled");
        }

        let hash_count = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let (result_tx, result_rx) = mpsc::channel();
        let mut job_senders = Vec::new();
        let mut handles = Vec::new();

        let seed = seed_hash.to_vec();

        for worker_id in 0..num_threads {
            let (job_tx, job_rx) = mpsc::channel::<MiningJob>();
            job_senders.push(job_tx);

            let hash_count = Arc::clone(&hash_count);
            let running = Arc::clone(&running);
            let result_tx = result_tx.clone();
            let seed = seed.clone();
            let nonce_start = (worker_id as u64 * (u32::MAX as u64 / num_threads as u64)) as u32;

            let handle = thread::spawn(move || {
                let cache = match RandomXCache::new(flags, &seed) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Worker {} cache init failed: {:?}", worker_id, e);
                        return;
                    }
                };
                let mut vm = match RandomXVM::new(flags, Some(cache), None) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Worker {} VM init failed: {:?}", worker_id, e);
                        return;
                    }
                };

                eprintln!("Worker {} ready (light mode)", worker_id);

                while running.load(Ordering::Relaxed) {
                    let job = match job_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                        Ok(j) => j,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };

                    let nonce_offset = find_nonce_offset(&job.hashing_blob);
                    let mut current_job = job;
                    loop {
                        match mine_job_rust(
                            &mut vm, &current_job, &running, &hash_count,
                            &result_tx, nonce_start, nonce_offset, &job_rx,
                        ) {
                            Some(new_job) => current_job = new_job,
                            None => break,
                        }
                    }
                }
            });

            handles.push(handle);
        }

        Ok(Self {
            hash_count,
            running,
            result_rx,
            job_senders,
            _handles: handles,
        })
    }

    pub fn send_job(&self, job: MiningJob) {
        for tx in &self.job_senders {
            let _ = tx.send(job.clone());
        }
    }

    pub fn try_recv_block(&self) -> Option<FoundBlock> {
        self.result_rx.try_recv().ok()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Worker loop using raw C FFI VM pointer (full mode) with pipelined hashing.
///
/// Uses randomx_calculate_hash_first/next/last to overlap memory fetch with
/// computation (same technique as XMRig). Double-buffered blobs avoid
/// touching memory the VM may still be reading.
fn worker_loop(
    vm_ptr: *mut std::ffi::c_void,
    job_rx: &mpsc::Receiver<MiningJob>,
    running: &AtomicBool,
    hash_count: &AtomicU64,
    result_tx: &mpsc::Sender<FoundBlock>,
    nonce_start: u32,
) {
    let mut hash_out = [0u8; 32];

    while running.load(Ordering::Relaxed) {
        // Wait for a job
        let mut job = match job_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(j) => j,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };

        let mut nonce_offset = find_nonce_offset(&job.hashing_blob);
        let mut nonce = nonce_start;

        // Double-buffered blobs for pipelined hashing
        let mut blob_a = job.hashing_blob.clone();
        let mut blob_b = job.hashing_blob.clone();
        let mut blob_len = blob_a.len();

        // Prime the pipeline: start first hash
        set_nonce(&mut blob_a, nonce_offset, nonce);
        unsafe {
            randomx_calculate_hash_first(vm_ptr, blob_a.as_ptr(), blob_len as u64);
        }
        let mut prev_nonce = nonce;
        nonce = nonce.wrapping_add(1);

        loop {
            // Stop or nonce space exhausted: drain last hash from pipeline
            if !running.load(Ordering::Relaxed) || nonce == nonce_start {
                unsafe {
                    randomx_calculate_hash_last(vm_ptr, hash_out.as_mut_ptr());
                }
                hash_count.fetch_add(1, Ordering::Relaxed);
                if check_hash(&hash_out, job.difficulty) {
                    submit_block(&job, prev_nonce, &hash_out, result_tx);
                }
                break;
            }

            // Check for new job (non-blocking)
            if let Ok(new_job) = job_rx.try_recv() {
                // Drain last hash from pipeline
                unsafe {
                    randomx_calculate_hash_last(vm_ptr, hash_out.as_mut_ptr());
                }
                hash_count.fetch_add(1, Ordering::Relaxed);
                if check_hash(&hash_out, job.difficulty) {
                    submit_block(&job, prev_nonce, &hash_out, result_tx);
                }

                // Switch to new job and re-prime pipeline
                job = new_job;
                nonce_offset = find_nonce_offset(&job.hashing_blob);
                nonce = nonce_start;
                blob_a = job.hashing_blob.clone();
                blob_b = job.hashing_blob.clone();
                blob_len = blob_a.len();

                set_nonce(&mut blob_a, nonce_offset, nonce);
                unsafe {
                    randomx_calculate_hash_first(vm_ptr, blob_a.as_ptr(), blob_len as u64);
                }
                prev_nonce = nonce;
                nonce = nonce.wrapping_add(1);
                continue;
            }

            // Pipeline: output hash for prev_nonce, start hashing nonce
            set_nonce(&mut blob_b, nonce_offset, nonce);
            unsafe {
                randomx_calculate_hash_next(
                    vm_ptr,
                    blob_b.as_ptr(),
                    blob_len as u64,
                    hash_out.as_mut_ptr(),
                );
            }
            hash_count.fetch_add(1, Ordering::Relaxed);

            if check_hash(&hash_out, job.difficulty) {
                submit_block(&job, prev_nonce, &hash_out, result_tx);
            }

            prev_nonce = nonce;
            nonce = nonce.wrapping_add(1);
            std::mem::swap(&mut blob_a, &mut blob_b);
        }
    }
}

/// Mine a single job using the Rust RandomXVM wrapper (light mode).
/// Checks for new jobs periodically so workers can switch to updated templates.
/// Returns Some(new_job) if a new job arrived, None if mining was stopped.
fn mine_job_rust(
    vm: &mut RandomXVM,
    job: &MiningJob,
    running: &AtomicBool,
    hash_count: &AtomicU64,
    result_tx: &mpsc::Sender<FoundBlock>,
    nonce_start: u32,
    nonce_offset: usize,
    job_rx: &mpsc::Receiver<MiningJob>,
) -> Option<MiningJob> {
    let mut nonce = nonce_start;
    let mut blob = job.hashing_blob.clone(); // clone once, reuse across iterations

    loop {
        if !running.load(Ordering::Relaxed) {
            return None;
        }

        // Check for new job every iteration (try_recv is non-blocking)
        if let Ok(new_job) = job_rx.try_recv() {
            return Some(new_job);
        }

        set_nonce(&mut blob, nonce_offset, nonce);

        let hash = match vm.calculate_hash(&blob) {
            Ok(h) => h,
            Err(_) => {
                nonce = nonce.wrapping_add(1);
                continue;
            }
        };

        hash_count.fetch_add(1, Ordering::Relaxed);

        if check_hash(&hash, job.difficulty) {
            let mut template = job.template_blob.clone();
            let tmpl_offset = find_nonce_offset(&template);
            set_nonce(&mut template, tmpl_offset, nonce);

            let _ = result_tx.send(FoundBlock {
                nonce,
                hash: hash.clone(),
                blob_hex: hex::encode(&template),
                job_id: job.job_id,
            });
        }

        nonce = nonce.wrapping_add(1);
        if nonce == nonce_start {
            return None;
        }
    }
}

fn submit_block(
    job: &MiningJob,
    nonce: u32,
    hash: &[u8; 32],
    result_tx: &mpsc::Sender<FoundBlock>,
) {
    let mut template = job.template_blob.clone();
    let tmpl_offset = find_nonce_offset(&template);
    set_nonce(&mut template, tmpl_offset, nonce);
    let _ = result_tx.send(FoundBlock {
        nonce,
        hash: hash.to_vec(),
        blob_hex: hex::encode(&template),
        job_id: job.job_id,
    });
}

fn set_nonce(blob: &mut [u8], offset: usize, nonce: u32) {
    blob[offset] = (nonce & 0xff) as u8;
    blob[offset + 1] = ((nonce >> 8) & 0xff) as u8;
    blob[offset + 2] = ((nonce >> 16) & 0xff) as u8;
    blob[offset + 3] = ((nonce >> 24) & 0xff) as u8;
}

/// Find nonce offset in block hashing blob.
/// Layout: major_version(varint) + minor_version(varint) + timestamp(varint) + prev_id(32 bytes) + nonce(4 bytes)
pub fn find_nonce_offset(blob: &[u8]) -> usize {
    let mut offset = 0;
    // Skip 3 varints (major_version, minor_version, timestamp)
    for _ in 0..3 {
        while blob[offset] & 0x80 != 0 {
            offset += 1;
        }
        offset += 1;
    }
    // Skip prev_id (32 bytes)
    offset += 32;
    offset
}

/// Check if hash meets difficulty target.
/// CryptoNote convention: interpret hash as little-endian 256-bit integer,
/// block is valid if hash * difficulty < 2^256.
fn check_hash(hash: &[u8], difficulty: u128) -> bool {
    if difficulty == 0 {
        return false;
    }
    // Read hash as little-endian u128 pair [low, high]
    let mut lo = 0u128;
    let mut hi = 0u128;
    for i in 0..16 {
        lo |= (hash[i] as u128) << (i * 8);
    }
    for i in 0..16 {
        hi |= (hash[16 + i] as u128) << (i * 8);
    }

    // Check: hash * difficulty < 2^256
    // Multiply as 256-bit: result = [lo*diff, hi*diff + carry]
    let (_, lo_overflow) = lo.overflowing_mul(difficulty);
    let hi_prod = match hi.checked_mul(difficulty) {
        Some(h) => h,
        None => return false,
    };
    let carry = if lo_overflow { difficulty } else { 0 };
    hi_prod.checked_add(carry).is_some()
}

/// Parse difficulty from wide_difficulty hex string or u64
pub fn parse_difficulty(difficulty: u64, wide_difficulty: Option<&str>) -> u128 {
    if let Some(wide) = wide_difficulty {
        let hex_str = wide.strip_prefix("0x").unwrap_or(wide);
        u128::from_str_radix(hex_str, 16).unwrap_or(difficulty as u128)
    } else {
        difficulty as u128
    }
}
