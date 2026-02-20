use clap::Parser;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod engine;
mod ffi;

use engine::GhostRiderEngine;
use salvium_miner::daemon::DaemonClient;
use salvium_miner::miner::{MiningJob, parse_difficulty};
use salvium_miner::mining::MiningLoop;
use salvium_miner::stratum::{difficulty_to_target, StratumClient, StratumEvent};

#[derive(Parser)]
#[command(name = "salvium-miner-gr")]
#[command(about = "GhostRider CPU miner for Salvium (experimental)")]
struct Args {
    /// Daemon RPC URL (solo mining mode)
    #[arg(short, long, default_value = "http://127.0.0.1:29081")]
    daemon: String,

    /// Wallet address for mining rewards (solo mode)
    #[arg(short, long, default_value = "")]
    wallet: String,

    /// Stratum pool URL (e.g. stratum+tcp://pool.example.com:3333)
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

    if args.pool.is_some() {
        run_stratum(&args);
    } else {
        run_daemon(&args);
    }
}

/// Stratum pool mining mode.
fn run_stratum(args: &Args) {
    let pool_url = args.pool.as_deref().unwrap();

    if args.user.is_empty() {
        eprintln!("Error: --user is required for pool mining (usually wallet.worker)");
        std::process::exit(1);
    }

    eprintln!("Salvium GhostRider Miner - Pool Mode");
    eprintln!("=====================================");
    eprintln!("Pool:    {}", pool_url);
    eprintln!("User:    {}", args.user);
    eprintln!("Threads: {}", args.threads);
    eprintln!();

    // Create mining loop
    let mining_loop = match MiningLoop::new(args.threads, |_worker_id| {
        Ok(Box::new(GhostRiderEngine::new()))
    }) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to create mining loop: {}", e);
            std::process::exit(1);
        }
    };

    // Set up SIGINT handler
    let running = mining_loop.running.clone();
    ctrlc_handler(running.clone());

    let mut shares_accepted = 0u64;
    let mut shares_rejected = 0u64;
    let start_time = Instant::now();
    let mut last_stats = Instant::now();

    // Outer reconnection loop
    while mining_loop.running.load(Ordering::Relaxed) {
        eprintln!("[stratum] Connecting to {}...", pool_url);

        let mut stratum = match StratumClient::connect(pool_url) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stratum] Connection failed: {}", e);
                if !mining_loop.running.load(Ordering::Relaxed) {
                    break;
                }
                eprintln!("[stratum] Reconnecting in 5s...");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        if let Err(e) = stratum.subscribe("salvium-miner-gr/0.1") {
            eprintln!("[stratum] Subscribe failed: {}", e);
            eprintln!("[stratum] Reconnecting in 5s...");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        if let Err(e) = stratum.authorize(&args.user, &args.password) {
            eprintln!("[stratum] Authorize failed: {}", e);
            eprintln!("[stratum] Reconnecting in 5s...");
            std::thread::sleep(Duration::from_secs(5));
            continue;
        }

        eprintln!();
        eprintln!("Mining started (GhostRider, pool). Press Ctrl+C to stop.");
        eprintln!();

        let en2_size = stratum.extranonce2_size();
        let mut difficulty = 1.0_f64;
        let mut job_counter = 0u64;
        // Maps internal job_id → (stratum_job_id, extranonce2, ntime)
        let mut job_map: HashMap<u64, (String, Vec<u8>, u32)> = HashMap::new();
        let mut extranonce2_counter = 0u64;

        // Inner mining loop (runs until disconnect)
        let disconnected = loop {
            if !mining_loop.running.load(Ordering::Relaxed) {
                break false;
            }

            // Poll stratum for events
            match stratum.poll() {
                Ok(Some(event)) => match event {
                    StratumEvent::SetDifficulty(d) => {
                        eprintln!("[stratum] Difficulty set to {}", d);
                        difficulty = d;
                    }
                    StratumEvent::Job(job) => {
                        extranonce2_counter += 1;
                        let mut en2 = vec![0u8; en2_size];
                        let counter_bytes = extranonce2_counter.to_le_bytes();
                        let copy_len = en2_size.min(counter_bytes.len());
                        en2[..copy_len].copy_from_slice(&counter_bytes[..copy_len]);

                        let header = stratum.build_header(&job, &en2);
                        let target = difficulty_to_target(difficulty);
                        job_counter += 1;

                        if job.clean_jobs {
                            job_map.clear();
                        }
                        job_map.insert(job_counter, (job.job_id.clone(), en2, job.ntime));

                        mining_loop.send_job(MiningJob {
                            job_id: job_counter,
                            hashing_blob: header.to_vec(),
                            template_blob: header.to_vec(),
                            difficulty: 1, // unused when target is set
                            height: 0,
                            nonce_offset: Some(76),
                            target: Some(target),
                        });

                        eprintln!(
                            "[stratum] New job {} (diff={:.4})",
                            job.job_id, difficulty
                        );
                    }
                    StratumEvent::Accepted => {
                        shares_accepted += 1;
                        eprintln!(
                            "[stratum] Share accepted ({}/{})",
                            shares_accepted,
                            shares_accepted + shares_rejected
                        );
                    }
                    StratumEvent::Rejected(msg) => {
                        shares_rejected += 1;
                        eprintln!("[stratum] Share rejected: {}", msg);
                    }
                },
                Ok(None) => {
                    // No data available, continue
                }
                Err(e) => {
                    eprintln!("[stratum] Connection error: {}", e);
                    break true; // disconnected
                }
            }

            // Check for found shares
            while let Some(block) = mining_loop.try_recv_block() {
                if let Some((ref stratum_job_id, ref en2, ntime)) = job_map.get(&block.job_id) {
                    eprintln!(
                        "[stratum] Submitting share (nonce={})",
                        block.nonce
                    );
                    if let Err(e) =
                        stratum.submit_share(stratum_job_id, en2, *ntime, block.nonce)
                    {
                        eprintln!("[stratum] Submit error: {}", e);
                        break;
                    }
                }
            }

            // Print stats every 10 seconds
            if last_stats.elapsed() > Duration::from_secs(10) {
                let elapsed = start_time.elapsed().as_secs_f64();
                let total = mining_loop.hash_count.load(Ordering::Relaxed);
                let hr = total as f64 / elapsed;

                eprint!(
                    "\r{} | Shares: {}/{} | Diff: {:.4}   ",
                    format_hashrate(hr),
                    shares_accepted,
                    shares_accepted + shares_rejected,
                    difficulty
                );
                last_stats = Instant::now();
            }

            std::thread::sleep(Duration::from_millis(50));
        };

        if disconnected && mining_loop.running.load(Ordering::Relaxed) {
            eprintln!("[stratum] Reconnecting in 5s...");
            job_map.clear();
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    // Final stats
    let elapsed = start_time.elapsed().as_secs_f64();
    let total = mining_loop.hash_count.load(Ordering::Relaxed);
    eprintln!();
    eprintln!("Shutting down...");
    eprintln!("Total hashes:    {}", total);
    eprintln!("Shares accepted: {}", shares_accepted);
    eprintln!("Shares rejected: {}", shares_rejected);
    eprintln!("Avg hashrate:    {}", format_hashrate(total as f64 / elapsed));

    mining_loop.stop();
}

/// Solo daemon mining mode (original behavior).
fn run_daemon(args: &Args) {
    if args.wallet.is_empty() {
        eprintln!("Error: --wallet is required for solo mining, or use --pool for pool mining");
        std::process::exit(1);
    }

    eprintln!("Salvium GhostRider Miner (experimental)");
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
                eprintln!(
                    "Cannot connect to daemon after 5 attempts: {}",
                    last_err
                );
                std::process::exit(1);
            }
        }
    };

    eprintln!(
        "Daemon height: {}, difficulty: {}",
        info.height, info.difficulty
    );

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

    let difficulty = parse_difficulty(template.difficulty, template.wide_difficulty.as_deref());

    eprintln!(
        "Template: height={}, difficulty={}",
        template.height, difficulty
    );

    let hashing_blob = hex::decode(&template.blockhashing_blob).expect("Invalid hashing blob");
    let template_blob =
        hex::decode(&template.blocktemplate_blob).expect("Invalid template blob");

    // Create mining loop
    let mining_loop = MiningLoop::new(args.threads, |_worker_id| {
        Ok(Box::new(GhostRiderEngine::new()))
    });

    let mining_loop = match mining_loop {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to create mining loop: {}", e);
            std::process::exit(1);
        }
    };

    // Set up SIGINT handler
    let running = mining_loop.running.clone();
    ctrlc_handler(running.clone());

    eprintln!();
    eprintln!("Mining started (GhostRider). Press Ctrl+C to stop.");
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

            while mining_loop.try_recv_block().is_some() {}

            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff =
                    parse_difficulty(tmpl.difficulty, tmpl.wide_difficulty.as_deref());

                if tmpl.seed_hash != current_seed {
                    eprintln!(
                        "Seed hash changed (GhostRider doesn't use seeds, continuing)"
                    );
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
                let new_diff =
                    parse_difficulty(tmpl.difficulty, tmpl.wide_difficulty.as_deref());

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
                eprintln!("=== GhostRider Benchmark Results ===");
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
    eprintln!(
        "Avg hashrate: {}",
        format_hashrate(total as f64 / elapsed)
    );

    mining_loop.stop();
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
static RUNNING_FLAG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn handle_sigint(_: libc::c_int) {
    let ptr = RUNNING_FLAG.load(Ordering::SeqCst);
    if ptr != 0 {
        let flag = unsafe { &*(ptr as *const std::sync::atomic::AtomicBool) };
        flag.store(false, Ordering::Relaxed);
    }
}
