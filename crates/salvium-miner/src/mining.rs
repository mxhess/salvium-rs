//! Generic mining infrastructure: HashAlgorithm trait and MiningLoop driver.
//!
//! Any PoW algorithm (RandomX v1, RandomX v2, GhostRider, etc.) can implement
//! the `HashAlgorithm` trait and plug into `MiningLoop` to get multi-threaded
//! mining with job management, difficulty checking, and block submission.

use crate::miner::{check_hash, check_hash_target, find_nonce_offset, set_nonce, FoundBlock, MiningJob};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

/// Abstraction over a proof-of-work hashing algorithm.
pub trait HashAlgorithm: Send {
    /// Human-readable algorithm name (e.g. "RandomX", "GhostRider").
    fn name(&self) -> &str;

    /// Compute the PoW hash for the given input blob.
    /// Returns 32-byte hash.
    fn hash(&mut self, input: &[u8]) -> [u8; 32];

    /// Whether this algorithm needs re-initialization when the seed changes.
    fn needs_reinit_on_seed_change(&self) -> bool {
        true
    }
}

/// Generic mining loop that works with any HashAlgorithm.
///
/// Spawns worker threads, each with its own `HashAlgorithm` instance,
/// and manages job distribution, difficulty checking, and block reporting.
pub struct MiningLoop {
    pub hash_count: Arc<AtomicU64>,
    pub running: Arc<AtomicBool>,
    result_rx: mpsc::Receiver<FoundBlock>,
    job_senders: Vec<mpsc::Sender<MiningJob>>,
    _handles: Vec<thread::JoinHandle<()>>,
}

impl MiningLoop {
    /// Create a new mining loop with `num_threads` workers.
    ///
    /// `create_hasher` is called once per worker thread with `(worker_id)` and
    /// must return a boxed `HashAlgorithm`. This allows each thread to have its
    /// own independent hasher state.
    pub fn new<F>(num_threads: usize, create_hasher: F) -> Result<Self, String>
    where
        F: Fn(usize) -> Result<Box<dyn HashAlgorithm>, String> + Send + Sync + 'static,
    {
        let hash_count = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let (result_tx, result_rx) = mpsc::channel();
        let mut job_senders = Vec::new();
        let mut handles = Vec::new();

        let create_hasher = Arc::new(create_hasher);

        for worker_id in 0..num_threads {
            let (job_tx, job_rx) = mpsc::channel::<MiningJob>();
            job_senders.push(job_tx);

            let hash_count = Arc::clone(&hash_count);
            let running = Arc::clone(&running);
            let result_tx = result_tx.clone();
            let create_hasher = Arc::clone(&create_hasher);
            let nonce_start =
                (worker_id as u64 * (u32::MAX as u64 / num_threads as u64)) as u32;

            let handle = thread::spawn(move || {
                let mut hasher = match create_hasher(worker_id) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Worker {} init failed: {}", worker_id, e);
                        return;
                    }
                };

                eprintln!("Worker {} ready ({})", worker_id, hasher.name());

                generic_worker_loop(
                    &mut *hasher,
                    &job_rx,
                    &running,
                    &hash_count,
                    &result_tx,
                    nonce_start,
                );
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

/// Generic worker loop: hash blobs, check difficulty, submit found blocks.
fn generic_worker_loop(
    hasher: &mut dyn HashAlgorithm,
    job_rx: &mpsc::Receiver<MiningJob>,
    running: &AtomicBool,
    hash_count: &AtomicU64,
    result_tx: &mpsc::Sender<FoundBlock>,
    nonce_start: u32,
) {
    while running.load(Ordering::Relaxed) {
        let job = match job_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(j) => j,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };

        let nonce_offset = job.nonce_offset.unwrap_or_else(|| find_nonce_offset(&job.hashing_blob));
        let mut nonce = nonce_start;
        let mut blob = job.hashing_blob.clone();

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // Check for new job (non-blocking)
            if let Ok(new_job) = job_rx.try_recv() {
                mine_single_job(hasher, &new_job, running, hash_count, result_tx, nonce_start, job_rx);
                return;
            }

            set_nonce(&mut blob, nonce_offset, nonce);

            let hash_result = hasher.hash(&blob);
            hash_count.fetch_add(1, Ordering::Relaxed);

            let meets = match job.target {
                Some(ref t) => check_hash_target(&hash_result, t),
                None => check_hash(&hash_result, job.difficulty),
            };
            if meets {
                let mut template = job.template_blob.clone();
                let tmpl_offset = job.nonce_offset.unwrap_or_else(|| find_nonce_offset(&template));
                set_nonce(&mut template, tmpl_offset, nonce);

                let _ = result_tx.send(FoundBlock {
                    nonce,
                    hash: hash_result.to_vec(),
                    blob_hex: hex::encode(&template),
                    job_id: job.job_id,
                });
            }

            nonce = nonce.wrapping_add(1);
            if nonce == nonce_start {
                break; // Exhausted nonce space
            }
        }
    }
}

/// Mine a single job until interrupted by stop or a new job.
fn mine_single_job(
    hasher: &mut dyn HashAlgorithm,
    job: &MiningJob,
    running: &AtomicBool,
    hash_count: &AtomicU64,
    result_tx: &mpsc::Sender<FoundBlock>,
    nonce_start: u32,
    job_rx: &mpsc::Receiver<MiningJob>,
) {
    let nonce_offset = job.nonce_offset.unwrap_or_else(|| find_nonce_offset(&job.hashing_blob));
    let mut nonce = nonce_start;
    let mut blob = job.hashing_blob.clone();

    loop {
        if !running.load(Ordering::Relaxed) {
            return;
        }

        if let Ok(new_job) = job_rx.try_recv() {
            mine_single_job(hasher, &new_job, running, hash_count, result_tx, nonce_start, job_rx);
            return;
        }

        set_nonce(&mut blob, nonce_offset, nonce);

        let hash_result = hasher.hash(&blob);
        hash_count.fetch_add(1, Ordering::Relaxed);

        let meets = match job.target {
            Some(ref t) => check_hash_target(&hash_result, t),
            None => check_hash(&hash_result, job.difficulty),
        };
        if meets {
            let mut template = job.template_blob.clone();
            let tmpl_offset = job.nonce_offset.unwrap_or_else(|| find_nonce_offset(&template));
            set_nonce(&mut template, tmpl_offset, nonce);

            let _ = result_tx.send(FoundBlock {
                nonce,
                hash: hash_result.to_vec(),
                blob_hex: hex::encode(&template),
                job_id: job.job_id,
            });
        }

        nonce = nonce.wrapping_add(1);
        if nonce == nonce_start {
            return;
        }
    }
}
