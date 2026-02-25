//! Multi-threaded RandomX mining engine
//!
//! Full mode: 2GB dataset shared across workers via Arc (randomx-rs).
//! Light mode: 256MB cache shared across workers via Arc (randomx-rs).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

/// Thread-safe wrapper for RandomXCache.
/// Safety: RandomX caches are read-only after initialization.
struct SharedCache(RandomXCache);
unsafe impl Send for SharedCache {}
unsafe impl Sync for SharedCache {}

/// Thread-safe wrapper for RandomXDataset.
/// Safety: RandomX datasets are read-only after initialization.
struct SharedDataset(RandomXDataset);
unsafe impl Send for SharedDataset {}
unsafe impl Sync for SharedDataset {}

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
    /// When Some, use this fixed nonce offset instead of varint-parsing the blob.
    /// Used by stratum where the nonce is always at byte 76 in the 80-byte header.
    pub nonce_offset: Option<usize>,
    /// When Some, use big-endian target comparison instead of CryptoNote difficulty check.
    /// Used by stratum pools (Bitcoin-style target).
    pub target: Option<[u8; 32]>,
}

/// Mining engine managing worker threads
pub struct MiningEngine {
    pub hash_count: Arc<AtomicU64>,
    pub running: Arc<AtomicBool>,
    result_rx: mpsc::Receiver<FoundBlock>,
    job_senders: Vec<mpsc::Sender<MiningJob>>,
    _handles: Vec<thread::JoinHandle<()>>,
}

impl MiningEngine {
    /// Initialize the mining engine with full mode (shared 2GB dataset)
    pub fn new_full(
        num_threads: usize,
        seed_hash: &[u8],
        use_large_pages: bool,
    ) -> Result<Self, String> {
        let base_flags = RandomXFlag::get_recommended_flags()
            | RandomXFlag::FLAG_FULL_MEM
            | RandomXFlag::FLAG_JIT;

        let (cache, flags, using_large_pages) =
            alloc_cache(base_flags, seed_hash, use_large_pages)?;
        eprintln!(
            "Large pages: {}",
            if using_large_pages {
                "YES"
            } else {
                "NO (falling back)"
            }
        );
        eprintln!("RandomX flags: {:?}", flags);
        eprintln!("Cache initialized (256MB)");

        // Create dataset (randomx-rs handles allocation + init)
        eprintln!("Generating dataset (~2GB)...");
        let start = std::time::Instant::now();
        let dataset = RandomXDataset::new(flags, cache, 0)
            .map_err(|e| format!("Failed to create dataset: {e}"))?;
        eprintln!("Dataset ready in {:.1}s", start.elapsed().as_secs_f64());

        // Wrap dataset for cross-thread sharing
        let shared_ds = Arc::new(SharedDataset(dataset));

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
            let ds = Arc::clone(&shared_ds);
            let nonce_start = (worker_id as u64 * (u32::MAX as u64 / num_threads as u64)) as u32;

            let handle = thread::spawn(move || {
                let vm = match RandomXVM::new(flags, None, Some(ds.0.clone())) {
                    Ok(vm) => vm,
                    Err(e) => {
                        eprintln!("Worker {worker_id} failed to create VM: {e}");
                        return;
                    }
                };
                eprintln!("Worker {worker_id} ready");
                worker_loop(&vm, &job_rx, &running, &hash_count, &result_tx, nonce_start);
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

    /// Initialize light mode (single shared 256MB cache)
    pub fn new_light(
        num_threads: usize,
        seed_hash: &[u8],
        use_large_pages: bool,
    ) -> Result<Self, String> {
        let base_flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_JIT;

        let (cache, flags, using_large_pages) =
            alloc_cache(base_flags, seed_hash, use_large_pages)?;
        eprintln!(
            "Large pages: {}",
            if using_large_pages {
                "YES"
            } else {
                "NO (falling back)"
            }
        );
        eprintln!("RandomX flags: {:?} (light mode)", flags);
        eprintln!("Cache initialized (256MB shared)");

        // Wrap cache for cross-thread sharing
        let shared_ca = Arc::new(SharedCache(cache));

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
            let ca = Arc::clone(&shared_ca);
            let nonce_start = (worker_id as u64 * (u32::MAX as u64 / num_threads as u64)) as u32;

            let handle = thread::spawn(move || {
                let vm = match RandomXVM::new(flags, Some(ca.0.clone()), None) {
                    Ok(vm) => vm,
                    Err(e) => {
                        eprintln!("Worker {worker_id} failed to create VM: {e}");
                        return;
                    }
                };
                eprintln!("Worker {worker_id} ready (light mode)");
                worker_loop(&vm, &job_rx, &running, &hash_count, &result_tx, nonce_start);
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

/// Try to allocate a cache with large pages; fall back to regular pages on failure.
fn alloc_cache(
    base_flags: RandomXFlag,
    seed_hash: &[u8],
    use_large_pages: bool,
) -> Result<(RandomXCache, RandomXFlag, bool), String> {
    if use_large_pages {
        let lp_flags = base_flags | RandomXFlag::FLAG_LARGE_PAGES;
        if let Ok(cache) = RandomXCache::new(lp_flags, seed_hash) {
            return Ok((cache, lp_flags, true));
        }
    }
    let cache = RandomXCache::new(base_flags, seed_hash)
        .map_err(|e| format!("Failed to allocate RandomX cache: {e}"))?;
    Ok((cache, base_flags, false))
}

/// Worker loop: fetch jobs, hash nonces, check targets.
fn worker_loop(
    vm: &RandomXVM,
    job_rx: &mpsc::Receiver<MiningJob>,
    running: &AtomicBool,
    hash_count: &AtomicU64,
    result_tx: &mpsc::Sender<FoundBlock>,
    nonce_start: u32,
) {
    let mut blob = Vec::new();

    while running.load(Ordering::Relaxed) {
        // Wait for a job
        let mut job = match job_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(j) => j,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };

        let mut nonce_offset = job
            .nonce_offset
            .unwrap_or_else(|| find_nonce_offset(&job.hashing_blob));
        let mut nonce = nonce_start;
        blob.clone_from(&job.hashing_blob);

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check for new job (non-blocking)
            if let Ok(new_job) = job_rx.try_recv() {
                job = new_job;
                nonce_offset = job
                    .nonce_offset
                    .unwrap_or_else(|| find_nonce_offset(&job.hashing_blob));
                nonce = nonce_start;
                blob.clone_from(&job.hashing_blob);
            }

            set_nonce(&mut blob, nonce_offset, nonce);
            let hash_vec = vm.calculate_hash(&blob).expect("RandomX hash failed");
            hash_count.fetch_add(1, Ordering::Relaxed);

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_vec);

            let meets = match job.target {
                Some(ref t) => check_hash_target(&hash, t),
                None => check_hash(&hash, job.difficulty),
            };
            if meets {
                submit_block(&job, nonce, &hash, result_tx);
            }

            nonce = nonce.wrapping_add(1);
            if nonce == nonce_start {
                break; // exhausted nonce space
            }
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
    let tmpl_offset = job
        .nonce_offset
        .unwrap_or_else(|| find_nonce_offset(&template));
    set_nonce(&mut template, tmpl_offset, nonce);
    let _ = result_tx.send(FoundBlock {
        nonce,
        hash: hash.to_vec(),
        blob_hex: hex::encode(&template),
        job_id: job.job_id,
    });
}

pub fn set_nonce(blob: &mut [u8], offset: usize, nonce: u32) {
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
pub fn check_hash(hash: &[u8], difficulty: u128) -> bool {
    if difficulty == 0 {
        return false;
    }
    // Read hash as little-endian u128 pair [low, high]
    let mut lo = 0u128;
    let mut hi = 0u128;
    for (i, &byte) in hash[..16].iter().enumerate() {
        lo |= (byte as u128) << (i * 8);
    }
    for (i, &byte) in hash[16..32].iter().enumerate() {
        hi |= (byte as u128) << (i * 8);
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

/// Check hash against big-endian target (Bitcoin/stratum-style).
/// Valid if hash (interpreted as big-endian 256-bit) <= target.
pub fn check_hash_target(hash: &[u8], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal
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
