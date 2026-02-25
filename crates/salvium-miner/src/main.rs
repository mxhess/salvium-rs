use clap::Parser;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use salvium_miner::daemon::DaemonClient;
use salvium_miner::miner::{MiningEngine, MiningJob};
use salvium_miner::stratum::{CryptoNoteEvent, CryptoNoteStratum};

#[derive(Parser)]
#[command(name = "salvium-miner")]
#[command(about = "Native RandomX CPU miner for Salvium")]
struct Args {
    /// Daemon RPC URL (solo mining mode)
    #[arg(short, long, default_value = "http://127.0.0.1:29081")]
    daemon: String,

    /// Wallet address for mining rewards (solo mode, or pool login)
    #[arg(short, long, default_value = "")]
    wallet: String,

    /// Stratum pool address (e.g. pool.example.com:3333)
    #[arg(short, long)]
    pool: Option<String>,

    /// Worker name for pool mining (usually wallet.worker)
    #[arg(short = 'u', long, default_value = "")]
    user: String,

    /// Password for pool mining
    #[arg(long, default_value = "x")]
    password: String,

    /// Number of mining threads
    #[arg(short, long, default_value_t = default_threads())]
    threads: usize,

    /// Use light mode (256MB shared cache instead of 2GB shared dataset — slower but much less RAM)
    #[arg(long)]
    light: bool,

    /// Run benchmark for 20 seconds and exit
    #[arg(long)]
    benchmark: bool,

    /// Disable large pages (large pages are tried by default with automatic fallback)
    #[arg(long)]
    no_large_pages: bool,

    /// Disable CPU core pinning (thread affinity is enabled by default on Linux)
    #[arg(long)]
    no_affinity: bool,

    /// IPC mode: read jobs from stdin, write results to stdout (JSON lines)
    #[arg(long)]
    ipc: bool,
}

fn default_threads() -> usize {
    std::cmp::max(1, num_cpus::get().saturating_sub(1))
}

fn format_hashrate(hr: f64) -> String {
    if hr >= 1_000_000.0 {
        format!("{:.2} MH/s", hr / 1_000_000.0)
    } else if hr >= 1_000.0 {
        format!("{:.2} KH/s", hr / 1_000.0)
    } else {
        format!("{:.2} H/s", hr)
    }
}

fn main() {
    let args = Args::parse();

    if args.ipc {
        salvium_miner::ipc::run_ipc(
            args.threads,
            args.light,
            !args.no_large_pages,
            args.no_affinity,
        );
        return;
    }

    if args.benchmark {
        run_benchmark(&args);
    } else if args.pool.is_some() {
        run_stratum(&args);
    } else {
        run_daemon(&args);
    }
}

/// Standalone benchmark: no daemon needed, mine synthetic jobs for 20 seconds.
fn run_benchmark(args: &Args) {
    eprintln!("Salvium RandomX Benchmark");
    eprintln!("=========================");
    eprintln!("Threads: {}", args.threads);
    eprintln!(
        "Mode:    {}",
        if args.light {
            "light (256MB shared cache)"
        } else {
            "full (2GB shared dataset)"
        }
    );
    eprintln!();

    // Fixed seed — no daemon needed
    let seed = [0u8; 32];
    let engine = init_engine(args, &seed);

    // Synthetic hashing blob: valid enough for RandomX (76+ bytes with nonce field)
    let mut blob = vec![0u8; 76];
    blob[0] = 10; // major version
    blob[1] = 10; // minor version
    blob[2] = 1; // timestamp (varint = 1)
                 // bytes 3..35 = prev_hash (zeros), bytes 35..39 = nonce, rest = zeros

    engine.send_job(MiningJob {
        job_id: 0,
        hashing_blob: blob.clone(),
        template_blob: blob,
        difficulty: u128::MAX, // impossibly high — we just want to hash, not find blocks
        height: 1,
        nonce_offset: Some(35),
        target: None,
    });

    let start_time = Instant::now();
    let mut last_print = Instant::now();

    // Mine for 20 seconds
    while start_time.elapsed() < Duration::from_secs(20) {
        if last_print.elapsed() > Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let total = engine.hash_count.load(Ordering::Relaxed);
            let hr = total as f64 / elapsed;
            eprint!(
                "\r  {:.0}s  {} ({} hashes)   ",
                elapsed,
                format_hashrate(hr),
                total
            );
            last_print = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let total = engine.hash_count.load(Ordering::Relaxed);
    let hr = total as f64 / elapsed;

    engine.stop();

    eprintln!();
    eprintln!();
    eprintln!("=== Benchmark Results ===");
    eprintln!("Threads:  {}", args.threads);
    eprintln!("Mode:     {}", if args.light { "light" } else { "full" });
    eprintln!("Duration: {:.1}s", elapsed);
    eprintln!("Hashes:   {}", total);
    eprintln!(
        "Hashrate: {} ({:.1} H/s per thread)",
        format_hashrate(hr),
        hr / args.threads as f64
    );
}

/// Initialize a MiningEngine for the given seed hash.
fn init_engine(args: &Args, seed_bytes: &[u8]) -> MiningEngine {
    let use_large_pages = !args.no_large_pages;
    let engine = if args.light {
        MiningEngine::new_light(args.threads, seed_bytes, use_large_pages, args.no_affinity)
    } else {
        MiningEngine::new_full(args.threads, seed_bytes, use_large_pages, args.no_affinity)
    };

    match engine {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to initialize mining engine: {}", e);
            std::process::exit(1);
        }
    }
}

/// Stratum pool mining mode (CryptoNote protocol for RandomX).
fn run_stratum(args: &Args) {
    let pool_url = args.pool.as_deref().unwrap();

    // Determine login: --user takes priority, falls back to --wallet
    let login = if !args.user.is_empty() {
        &args.user
    } else if !args.wallet.is_empty() {
        &args.wallet
    } else {
        eprintln!("Error: --user or --wallet is required for pool mining");
        std::process::exit(1);
    };

    eprintln!("Salvium Native RandomX Miner - Pool Mode");
    eprintln!("=========================================");
    eprintln!("Pool:    {}", pool_url);
    eprintln!("User:    {}...", &login[..20.min(login.len())]);
    eprintln!("Threads: {}", args.threads);
    eprintln!(
        "Mode:    {}",
        if args.light {
            "light (256MB shared)"
        } else {
            "full (2GB shared dataset)"
        }
    );
    eprintln!();

    // We need the first job's seed_hash before we can initialize RandomX.
    // Use a global running flag to share across engine reinits.
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    ctrlc_handler(running.clone());

    let mut shares_accepted = 0u64;
    let mut shares_rejected = 0u64;
    let start_time = Instant::now();
    let mut last_stats = Instant::now();
    let mut current_seed_hash = String::new();
    let mut engine: Option<MiningEngine> = None;

    // Outer reconnection loop
    while running.load(Ordering::Relaxed) {
        eprintln!("[stratum] Connecting to {}...", pool_url);

        let mut stratum = match CryptoNoteStratum::connect(pool_url) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stratum] Connection failed: {}", e);
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("[stratum] Reconnecting in 5s...");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let initial_job = match stratum.login(login, &args.password, "salvium-miner/0.1") {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[stratum] Login failed: {}", e);
                eprintln!("[stratum] Reconnecting in 5s...");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        eprintln!();
        eprintln!("Mining started (RandomX, pool). Press Ctrl+C to stop.");
        eprintln!();

        let mut job_counter = 0u64;
        // Maps internal job_id → stratum job_id
        let mut job_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();

        // Process initial job if present
        if let Some(ref job) = initial_job {
            // Initialize or reinitialize engine if seed changed
            if job.seed_hash != current_seed_hash {
                let seed_bytes = hex::decode(&job.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
                eprintln!(
                    "[stratum] Seed hash: {:.16}... — initializing RandomX",
                    job.seed_hash
                );
                // Drop old engine first to free memory
                drop(engine.take());
                let new_engine = init_engine(args, &seed_bytes);
                // Propagate our running flag
                if !running.load(Ordering::Relaxed) {
                    new_engine.running.store(false, Ordering::Relaxed);
                }
                engine = Some(new_engine);
                current_seed_hash = job.seed_hash.clone();
            }

            job_counter += 1;
            job_map.insert(job_counter, job.job_id.clone());

            if let Some(ref eng) = engine {
                eng.send_job(MiningJob {
                    job_id: job_counter,
                    hashing_blob: job.blob.clone(),
                    template_blob: job.blob.clone(),
                    difficulty: job.difficulty,
                    height: job.height,
                    nonce_offset: None,
                    target: None,
                });
            }

            eprintln!(
                "[stratum] Job {} (height={}, diff={})",
                job.job_id, job.height, job.difficulty
            );
        }

        // Inner mining loop (runs until disconnect)
        let disconnected = loop {
            if !running.load(Ordering::Relaxed) {
                break false;
            }

            // Poll stratum for events
            match stratum.poll() {
                Ok(Some(event)) => match event {
                    CryptoNoteEvent::Job(job) => {
                        // Check if seed hash changed
                        if job.seed_hash != current_seed_hash {
                            let seed_bytes =
                                hex::decode(&job.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
                            eprintln!(
                                "[stratum] Seed hash changed: {:.16}... — reinitializing RandomX",
                                job.seed_hash
                            );
                            drop(engine.take());
                            let new_engine = init_engine(args, &seed_bytes);
                            if !running.load(Ordering::Relaxed) {
                                new_engine.running.store(false, Ordering::Relaxed);
                            }
                            engine = Some(new_engine);
                            current_seed_hash = job.seed_hash.clone();
                            job_map.clear();
                        }

                        job_counter += 1;
                        job_map.insert(job_counter, job.job_id.clone());

                        if let Some(ref eng) = engine {
                            eng.send_job(MiningJob {
                                job_id: job_counter,
                                hashing_blob: job.blob.clone(),
                                template_blob: job.blob.clone(),
                                difficulty: job.difficulty,
                                height: job.height,
                                nonce_offset: None,
                                target: None,
                            });
                        }

                        eprintln!(
                            "[stratum] Job {} (height={}, diff={})",
                            job.job_id, job.height, job.difficulty
                        );
                    }
                    CryptoNoteEvent::Accepted => {
                        shares_accepted += 1;
                        eprintln!(
                            "[stratum] Share accepted ({}/{})",
                            shares_accepted,
                            shares_accepted + shares_rejected
                        );
                    }
                    CryptoNoteEvent::Rejected(msg) => {
                        shares_rejected += 1;
                        eprintln!("[stratum] Share rejected: {}", msg);
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[stratum] Connection error: {}", e);
                    break true;
                }
            }

            // Check for found shares
            if let Some(ref eng) = engine {
                while let Some(block) = eng.try_recv_block() {
                    if let Some(stratum_job_id) = job_map.get(&block.job_id) {
                        let hash: [u8; 32] = if block.hash.len() == 32 {
                            let mut h = [0u8; 32];
                            h.copy_from_slice(&block.hash);
                            h
                        } else {
                            continue;
                        };
                        eprintln!("[stratum] Submitting share (nonce={})", block.nonce);
                        if let Err(e) = stratum.submit_share(stratum_job_id, block.nonce, &hash) {
                            eprintln!("[stratum] Submit error: {}", e);
                            break;
                        }
                    }
                }
            }

            // Print stats every 10 seconds
            if last_stats.elapsed() > Duration::from_secs(10) {
                if let Some(ref eng) = engine {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let total = eng.hash_count.load(Ordering::Relaxed);
                    let hr = total as f64 / elapsed;

                    eprint!(
                        "\r{} | Shares: {}/{} | Hashes: {}   ",
                        format_hashrate(hr),
                        shares_accepted,
                        shares_accepted + shares_rejected,
                        total
                    );
                }
                last_stats = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(50));
        };

        if disconnected && running.load(Ordering::Relaxed) {
            eprintln!("[stratum] Reconnecting in 5s...");
            job_map.clear();
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    // Final stats
    let elapsed = start_time.elapsed().as_secs_f64();
    let total = engine
        .as_ref()
        .map(|e| e.hash_count.load(Ordering::Relaxed))
        .unwrap_or(0);
    eprintln!();
    eprintln!("Shutting down...");
    eprintln!("Total hashes:    {}", total);
    eprintln!("Shares accepted: {}", shares_accepted);
    eprintln!("Shares rejected: {}", shares_rejected);
    eprintln!(
        "Avg hashrate:    {}",
        format_hashrate(total as f64 / elapsed)
    );

    if let Some(eng) = engine {
        eng.stop();
    }
}

/// Solo daemon mining mode (original behavior).
fn run_daemon(args: &Args) {
    if args.wallet.is_empty() {
        eprintln!("Error: --wallet is required (unless using --ipc or --pool mode)");
        std::process::exit(1);
    }

    eprintln!("Salvium Native RandomX Miner");
    eprintln!("============================");
    eprintln!("Daemon:  {}", args.daemon);
    eprintln!("Wallet:  {}...", &args.wallet[..20.min(args.wallet.len())]);
    eprintln!("Threads: {}", args.threads);
    eprintln!(
        "Mode:    {}",
        if args.light {
            "light (256MB shared)"
        } else {
            "full (2GB shared dataset)"
        }
    );
    eprintln!();

    // Connect to daemon (retry up to 5 times)
    let client = DaemonClient::new(&args.daemon);

    let info = {
        let mut last_err = String::new();
        let mut result = None;
        for attempt in 1..=5 {
            match client.get_info() {
                Ok(i) => {
                    result = Some(i);
                    break;
                }
                Err(e) => {
                    last_err = e;
                    if attempt < 5 {
                        eprintln!(
                            "Cannot connect to daemon (attempt {}/5): {}",
                            attempt, last_err
                        );
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        match result {
            Some(i) => i,
            None => {
                eprintln!("Cannot connect to daemon after 5 attempts: {}", last_err);
                std::process::exit(1);
            }
        }
    };

    eprintln!(
        "Daemon height: {}, difficulty: {}",
        info.height, info.difficulty
    );

    // Get initial block template (retry up to 5 times for transient daemon errors)
    let template = {
        let mut last_err = String::new();
        let mut tmpl = None;
        for attempt in 1..=5 {
            match client.get_block_template(&args.wallet, 8) {
                Ok(t) => {
                    tmpl = Some(t);
                    break;
                }
                Err(e) => {
                    last_err = e;
                    if attempt < 5 {
                        eprintln!(
                            "Failed to get block template (attempt {}/5): {}",
                            attempt, last_err
                        );
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        match tmpl {
            Some(t) => t,
            None => {
                eprintln!(
                    "Failed to get block template after 5 attempts: {}",
                    last_err
                );
                std::process::exit(1);
            }
        }
    };

    let difficulty = salvium_miner::miner::parse_difficulty(
        template.difficulty,
        template.wide_difficulty.as_deref(),
    );

    eprintln!(
        "Template: height={}, difficulty={}",
        template.height, difficulty
    );

    let seed_bytes = hex::decode(&template.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
    let hashing_blob = hex::decode(&template.blockhashing_blob).expect("Invalid hashing blob");
    let template_blob = hex::decode(&template.blocktemplate_blob).expect("Invalid template blob");

    // Initialize mining engine
    let engine = init_engine(args, &seed_bytes);

    // Set up SIGINT handler
    let running = engine.running.clone();
    ctrlc_handler(running.clone());

    eprintln!();
    eprintln!("Mining started. Press Ctrl+C to stop.");
    eprintln!();

    // Send initial job
    let mut job_id = 0u64;
    let mut current_height = template.height;
    let mut current_difficulty = difficulty;
    let current_seed = template.seed_hash.clone();

    engine.send_job(MiningJob {
        job_id,
        hashing_blob: hashing_blob.clone(),
        template_blob: template_blob.clone(),
        difficulty,
        height: template.height,
        nonce_offset: None,
        target: None,
    });

    let start_time = Instant::now();
    let mut last_template_fetch = Instant::now();
    let mut last_stats = Instant::now();
    let mut blocks_found = 0u64;

    let mut current_prev_hash = template.prev_hash.clone();

    // Main loop
    while engine.running.load(Ordering::Relaxed) {
        // Check for found blocks — submit only the first, discard rest
        let mut block_found = false;
        if let Some(block) = engine.try_recv_block() {
            // Skip stale blocks from old jobs
            if block.job_id != job_id {
                continue;
            }
            block_found = true;

            // Drain any stale blocks
            let mut drained = 0;
            while engine.try_recv_block().is_some() {
                drained += 1;
            }

            eprintln!();
            eprintln!(
                "*** BLOCK FOUND at height {}! nonce={} ***",
                current_height, block.nonce
            );

            match client.submit_block(&block.blob_hex) {
                Ok(()) => {
                    blocks_found += 1;
                    eprintln!("Block accepted! Total: {}", blocks_found);
                }
                Err(e) => {
                    eprintln!("Block rejected: {}", e);
                }
            }
            if drained > 0 {
                eprintln!("(discarded {} stale blocks)", drained);
            }

            // Drain stale blocks, then immediately fetch new template.
            while engine.try_recv_block().is_some() {}

            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = salvium_miner::miner::parse_difficulty(
                    tmpl.difficulty,
                    tmpl.wide_difficulty.as_deref(),
                );

                if tmpl.seed_hash != current_seed {
                    eprintln!("Seed hash changed — need to restart with new dataset");
                    engine.stop();
                    break;
                }

                // Drain again right before sending new job
                while engine.try_recv_block().is_some() {}

                current_height = tmpl.height;
                current_difficulty = new_diff;
                current_prev_hash = tmpl.prev_hash.clone();
                job_id += 1;

                let hb = hex::decode(&tmpl.blockhashing_blob).unwrap_or_default();
                let tb = hex::decode(&tmpl.blocktemplate_blob).unwrap_or_default();

                engine.send_job(MiningJob {
                    job_id,
                    hashing_blob: hb,
                    template_blob: tb,
                    difficulty: new_diff,
                    height: tmpl.height,
                    nonce_offset: None,
                    target: None,
                });

                eprintln!(
                    "Template: height={} diff={} prev={:.16}...",
                    tmpl.height, new_diff, tmpl.prev_hash
                );
            }
            last_template_fetch = Instant::now();
        }

        // Refresh template every 5 seconds (routine poll)
        if !block_found && last_template_fetch.elapsed() > Duration::from_secs(5) {
            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = salvium_miner::miner::parse_difficulty(
                    tmpl.difficulty,
                    tmpl.wide_difficulty.as_deref(),
                );

                if tmpl.seed_hash != current_seed {
                    eprintln!("\nSeed hash changed — need to restart with new dataset");
                    engine.stop();
                    break;
                }

                // Send new job if anything changed
                if tmpl.prev_hash != current_prev_hash
                    || tmpl.height != current_height
                    || new_diff != current_difficulty
                {
                    current_height = tmpl.height;
                    current_difficulty = new_diff;
                    current_prev_hash = tmpl.prev_hash.clone();
                    job_id += 1;

                    let hb = hex::decode(&tmpl.blockhashing_blob).unwrap_or_default();
                    let tb = hex::decode(&tmpl.blocktemplate_blob).unwrap_or_default();

                    engine.send_job(MiningJob {
                        job_id,
                        hashing_blob: hb,
                        template_blob: tb,
                        difficulty: new_diff,
                        height: tmpl.height,
                        nonce_offset: None,
                        target: None,
                    });
                }
            }
            last_template_fetch = Instant::now();
        }

        // Print stats every 10 seconds
        if last_stats.elapsed() > Duration::from_secs(10) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let total = engine.hash_count.load(Ordering::Relaxed);
            let hr = total as f64 / elapsed;
            let est_block = current_difficulty as f64 / hr;

            eprint!(
                "\r[H={}] {} | Hashes: {} | Blocks: {} | Diff: {} | Est: {:.0}s/block   ",
                current_height,
                format_hashrate(hr),
                total,
                blocks_found,
                current_difficulty,
                est_block
            );
            last_stats = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    // Final stats
    let elapsed = start_time.elapsed().as_secs_f64();
    let total = engine.hash_count.load(Ordering::Relaxed);
    eprintln!();
    eprintln!("Shutting down...");
    eprintln!("Total hashes: {}", total);
    eprintln!("Blocks found: {}", blocks_found);
    eprintln!("Avg hashrate: {}", format_hashrate(total as f64 / elapsed));

    engine.stop();
}

fn ctrlc_handler(running: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let _ = std::thread::spawn(move || {});

    #[cfg(unix)]
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
        RUNNING_FLAG.store(running.as_ref() as *const _ as usize, Ordering::SeqCst);
    }
}

#[cfg(unix)]
static RUNNING_FLAG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn handle_sigint(_: libc::c_int) {
    let ptr = RUNNING_FLAG.load(Ordering::SeqCst);
    if ptr != 0 {
        let flag = unsafe { &*(ptr as *const std::sync::atomic::AtomicBool) };
        flag.store(false, Ordering::Relaxed);
    }
}
