use clap::Parser;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod engine;
mod ffi;

use engine::{RandomXV2Engine, SharedDataset};
use salvium_miner::daemon::DaemonClient;
use salvium_miner::miner::{parse_difficulty, MiningJob};
use salvium_miner::mining::MiningLoop;
use salvium_miner::stratum::{CryptoNoteEvent, CryptoNoteStratum};

#[derive(Parser)]
#[command(name = "salvium-miner-v2")]
#[command(about = "RandomX v2 CPU miner for Salvium (experimental)")]
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

    /// Run benchmark for 20 seconds and exit
    #[arg(long)]
    benchmark: bool,

    /// Disable large pages
    #[arg(long)]
    no_large_pages: bool,
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

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if args.pool.is_some() {
        run_stratum(&args);
    } else {
        run_daemon(&args);
    }
}

/// Initialize a MiningLoop with RandomX v2 engines for the given seed.
fn init_mining_loop(args: &Args, seed_bytes: &[u8]) -> Result<MiningLoop, String> {
    let use_large_pages = !args.no_large_pages;
    let dataset = SharedDataset::new(seed_bytes, args.threads, use_large_pages)?;
    let dataset_clone = dataset.clone();
    MiningLoop::new(args.threads, move |_worker_id| {
        let engine = RandomXV2Engine::new(dataset_clone.clone())?;
        Ok(Box::new(engine))
    })
}

/// Try to reinitialize the mining loop if seed hash changed. Returns true on success.
fn maybe_reinit_loop(
    args: &Args,
    seed_hash: &str,
    current_seed_hash: &mut String,
    mining_loop: &mut Option<MiningLoop>,
    running: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    if seed_hash == current_seed_hash.as_str() {
        return true;
    }
    let seed_bytes = hex::decode(seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
    eprintln!("[stratum] Seed hash: {:.16}... — initializing RandomX v2", seed_hash);
    if let Some(old) = mining_loop.take() {
        old.stop();
    }
    match init_mining_loop(args, &seed_bytes) {
        Ok(ml) => {
            if !running.load(Ordering::Relaxed) {
                ml.running.store(false, Ordering::Relaxed);
            }
            *mining_loop = Some(ml);
            *current_seed_hash = seed_hash.to_string();
            true
        }
        Err(e) => {
            log::error!("failed to initialize RandomX v2: {}", e);
            false
        }
    }
}

/// Send a CryptoNote job to the mining loop.
fn dispatch_job(
    job: &salvium_miner::stratum::CryptoNoteJob,
    job_counter: &mut u64,
    job_map: &mut std::collections::HashMap<u64, String>,
    mining_loop: &Option<MiningLoop>,
) {
    *job_counter += 1;
    job_map.insert(*job_counter, job.job_id.clone());
    if let Some(ref ml) = mining_loop {
        ml.send_job(MiningJob {
            job_id: *job_counter,
            hashing_blob: job.blob.clone(),
            template_blob: job.blob.clone(),
            difficulty: job.difficulty,
            height: job.height,
            nonce_offset: None,
            target: None,
        });
    }
    eprintln!("[stratum] Job {} (height={}, diff={})", job.job_id, job.height, job.difficulty);
}

/// Stratum pool mining mode (CryptoNote protocol for RandomX v2).
fn run_stratum(args: &Args) {
    let pool_url = args.pool.as_deref().unwrap();

    let login = if !args.user.is_empty() {
        &args.user
    } else if !args.wallet.is_empty() {
        &args.wallet
    } else {
        log::error!("--user or --wallet is required for pool mining");
        std::process::exit(1);
    };

    eprintln!("Salvium RandomX v2 Miner - Pool Mode");
    eprintln!("=====================================");
    eprintln!("Pool:    {}", pool_url);
    eprintln!("User:    {}...", &login[..20.min(login.len())]);
    eprintln!("Threads: {}", args.threads);
    eprintln!();

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    ctrlc_handler(running.clone());

    let mut shares_accepted = 0u64;
    let mut shares_rejected = 0u64;
    let start_time = Instant::now();
    let mut last_stats = Instant::now();
    let mut current_seed_hash = String::new();
    let mut mining_loop: Option<MiningLoop> = None;

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

        let initial_job = match stratum.login(login, &args.password, "salvium-miner-v2/0.1") {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[stratum] Login failed: {}", e);
                eprintln!("[stratum] Reconnecting in 5s...");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        eprintln!();
        eprintln!("Mining started (RandomX v2, pool). Press Ctrl+C to stop.");
        eprintln!();

        let mut job_counter = 0u64;
        let mut job_map: std::collections::HashMap<u64, String> = std::collections::HashMap::new();

        // Process initial job
        if let Some(ref job) = initial_job {
            if maybe_reinit_loop(
                args,
                &job.seed_hash,
                &mut current_seed_hash,
                &mut mining_loop,
                &running,
            ) {
                dispatch_job(job, &mut job_counter, &mut job_map, &mining_loop);
            }
        }

        // Inner mining loop
        let disconnected = loop {
            if !running.load(Ordering::Relaxed) {
                break false;
            }

            match stratum.poll() {
                Ok(Some(event)) => match event {
                    CryptoNoteEvent::Job(job) => {
                        if maybe_reinit_loop(
                            args,
                            &job.seed_hash,
                            &mut current_seed_hash,
                            &mut mining_loop,
                            &running,
                        ) {
                            dispatch_job(&job, &mut job_counter, &mut job_map, &mining_loop);
                        }
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
            if let Some(ref ml) = mining_loop {
                while let Some(block) = ml.try_recv_block() {
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
                if let Some(ref ml) = mining_loop {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let total = ml.hash_count.load(Ordering::Relaxed);
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
    let total = mining_loop.as_ref().map(|ml| ml.hash_count.load(Ordering::Relaxed)).unwrap_or(0);
    eprintln!();
    eprintln!("Shutting down...");
    eprintln!("Total hashes:    {}", total);
    eprintln!("Shares accepted: {}", shares_accepted);
    eprintln!("Shares rejected: {}", shares_rejected);
    eprintln!("Avg hashrate:    {}", format_hashrate(total as f64 / elapsed));

    if let Some(ml) = mining_loop {
        ml.stop();
    }
}

/// Solo daemon mining mode (original behavior).
fn run_daemon(args: &Args) {
    if args.wallet.is_empty() {
        log::error!("--wallet is required for solo mining, or use --pool for pool mining");
        std::process::exit(1);
    }

    eprintln!("Salvium RandomX v2 Miner (experimental)");
    eprintln!("=======================================");
    eprintln!("Daemon:  {}", args.daemon);
    eprintln!("Wallet:  {}...", &args.wallet[..20.min(args.wallet.len())]);
    eprintln!("Threads: {}", args.threads);
    eprintln!();

    // Connect to daemon
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
                        log::warn!(
                            "cannot connect to daemon (attempt {}/5): {}",
                            attempt,
                            last_err
                        );
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        match result {
            Some(i) => i,
            None => {
                log::error!("cannot connect to daemon after 5 attempts: {}", last_err);
                std::process::exit(1);
            }
        }
    };

    eprintln!("Daemon height: {}, difficulty: {}", info.height, info.difficulty);

    // Get initial block template
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
                        log::warn!(
                            "failed to get block template (attempt {}/5): {}",
                            attempt,
                            last_err
                        );
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        match tmpl {
            Some(t) => t,
            None => {
                log::error!("failed to get block template after 5 attempts: {}", last_err);
                std::process::exit(1);
            }
        }
    };

    let difficulty = parse_difficulty(template.difficulty, template.wide_difficulty.as_deref());

    eprintln!("Template: height={}, difficulty={}", template.height, difficulty);

    let seed_bytes = hex::decode(&template.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
    let hashing_blob = hex::decode(&template.blockhashing_blob).expect("Invalid hashing blob");
    let template_blob = hex::decode(&template.blocktemplate_blob).expect("Invalid template blob");

    // Initialize shared RandomX v2 dataset
    let mining_loop = match init_mining_loop(args, &seed_bytes) {
        Ok(ml) => ml,
        Err(e) => {
            log::error!("failed to initialize RandomX v2: {}", e);
            std::process::exit(1);
        }
    };

    // Set up SIGINT handler
    let running = mining_loop.running.clone();
    ctrlc_handler(running.clone());

    eprintln!();
    eprintln!("Mining started (RandomX v2). Press Ctrl+C to stop.");
    eprintln!();

    // Send initial job
    let mut job_id = 0u64;
    let mut current_height = template.height;
    let mut current_difficulty = difficulty;
    let current_seed = template.seed_hash.clone();

    mining_loop.send_job(MiningJob {
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
    while mining_loop.running.load(Ordering::Relaxed) {
        // Check for found blocks
        let mut block_found = false;
        if let Some(block) = mining_loop.try_recv_block() {
            if block.job_id != job_id {
                continue;
            }
            block_found = true;

            let mut drained = 0;
            while mining_loop.try_recv_block().is_some() {
                drained += 1;
            }

            eprintln!();
            eprintln!("*** BLOCK FOUND at height {}! nonce={} ***", current_height, block.nonce);

            match client.submit_block(&block.blob_hex) {
                Ok(()) => {
                    blocks_found += 1;
                    eprintln!("Block accepted! Total: {}", blocks_found);
                }
                Err(e) => {
                    log::error!("block rejected: {}", e);
                }
            }
            if drained > 0 {
                log::debug!("discarded {} stale blocks", drained);
            }

            while mining_loop.try_recv_block().is_some() {}

            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = parse_difficulty(tmpl.difficulty, tmpl.wide_difficulty.as_deref());

                if tmpl.seed_hash != current_seed {
                    log::warn!("seed hash changed — need to restart with new dataset");
                    mining_loop.stop();
                    break;
                }

                while mining_loop.try_recv_block().is_some() {}

                current_height = tmpl.height;
                current_difficulty = new_diff;
                current_prev_hash = tmpl.prev_hash.clone();
                job_id += 1;

                let hb = hex::decode(&tmpl.blockhashing_blob).unwrap_or_default();
                let tb = hex::decode(&tmpl.blocktemplate_blob).unwrap_or_default();

                mining_loop.send_job(MiningJob {
                    job_id,
                    hashing_blob: hb,
                    template_blob: tb,
                    difficulty: new_diff,
                    height: tmpl.height,
                    nonce_offset: None,
                    target: None,
                });
            }
            last_template_fetch = Instant::now();
        }

        // Refresh template every 5 seconds
        if !block_found && last_template_fetch.elapsed() > Duration::from_secs(5) {
            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = parse_difficulty(tmpl.difficulty, tmpl.wide_difficulty.as_deref());

                if tmpl.seed_hash != current_seed {
                    log::warn!("seed hash changed — need to restart with new dataset");
                    mining_loop.stop();
                    break;
                }

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

                    mining_loop.send_job(MiningJob {
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
            let total = mining_loop.hash_count.load(Ordering::Relaxed);
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

            if args.benchmark && elapsed > 20.0 {
                eprintln!();
                eprintln!();
                eprintln!("=== RandomX v2 Benchmark Results ===");
                eprintln!("Threads:  {}", args.threads);
                eprintln!("Duration: {:.1}s", elapsed);
                eprintln!("Hashes:   {}", total);
                eprintln!(
                    "Hashrate: {} ({:.1} H/s per thread)",
                    format_hashrate(hr),
                    hr / args.threads as f64
                );
                mining_loop.stop();
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    // Final stats
    let elapsed = start_time.elapsed().as_secs_f64();
    let total = mining_loop.hash_count.load(Ordering::Relaxed);
    eprintln!();
    eprintln!("Shutting down...");
    eprintln!("Total hashes: {}", total);
    eprintln!("Blocks found: {}", blocks_found);
    eprintln!("Avg hashrate: {}", format_hashrate(total as f64 / elapsed));

    mining_loop.stop();
}

fn ctrlc_handler(running: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let _ = std::thread::spawn(move || {});

    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGINT, handle_sigint as *const () as libc::sighandler_t);
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
