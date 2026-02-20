use clap::Parser;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod engine;
mod ffi;

use engine::{RandomXV2Engine, SharedDataset};
use salvium_miner::daemon::DaemonClient;
use salvium_miner::miner::{MiningJob, parse_difficulty};
use salvium_miner::mining::MiningLoop;

#[derive(Parser)]
#[command(name = "salvium-miner-v2")]
#[command(about = "RandomX v2 CPU miner for Salvium (experimental)")]
struct Args {
    /// Daemon RPC URL
    #[arg(short, long, default_value = "http://127.0.0.1:29081")]
    daemon: String,

    /// Wallet address for mining rewards
    #[arg(short, long, default_value = "")]
    wallet: String,

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

    if args.wallet.is_empty() {
        eprintln!("Error: --wallet is required");
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
                Ok(i) => { result = Some(i); break; }
                Err(e) => {
                    last_err = e;
                    if attempt < 5 {
                        eprintln!("Cannot connect to daemon (attempt {}/5): {}", attempt, last_err);
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

    eprintln!("Daemon height: {}, difficulty: {}", info.height, info.difficulty);

    // Get initial block template
    let template = {
        let mut last_err = String::new();
        let mut tmpl = None;
        for attempt in 1..=5 {
            match client.get_block_template(&args.wallet, 8) {
                Ok(t) => { tmpl = Some(t); break; }
                Err(e) => {
                    last_err = e;
                    if attempt < 5 {
                        eprintln!("Failed to get block template (attempt {}/5): {}", attempt, last_err);
                        std::thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        }
        match tmpl {
            Some(t) => t,
            None => {
                eprintln!("Failed to get block template after 5 attempts: {}", last_err);
                std::process::exit(1);
            }
        }
    };

    let difficulty = parse_difficulty(
        template.difficulty,
        template.wide_difficulty.as_deref(),
    );

    eprintln!("Template: height={}, difficulty={}", template.height, difficulty);

    let seed_bytes = hex::decode(&template.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
    let hashing_blob = hex::decode(&template.blockhashing_blob).expect("Invalid hashing blob");
    let template_blob = hex::decode(&template.blocktemplate_blob).expect("Invalid template blob");

    // Initialize shared RandomX v2 dataset
    let use_large_pages = !args.no_large_pages;
    let dataset = match SharedDataset::new(&seed_bytes, args.threads, use_large_pages) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to initialize RandomX v2: {}", e);
            std::process::exit(1);
        }
    };

    // Create mining loop with per-thread RandomX v2 engines
    let mining_loop = {
        let dataset = dataset.clone();
        MiningLoop::new(args.threads, move |_worker_id| {
            let engine = RandomXV2Engine::new(dataset.clone())?;
            Ok(Box::new(engine))
        })
    };

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
            while mining_loop.try_recv_block().is_some() { drained += 1; }

            eprintln!();
            eprintln!("*** BLOCK FOUND at height {}! nonce={} ***", current_height, block.nonce);

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
                let new_diff = parse_difficulty(
                    tmpl.difficulty,
                    tmpl.wide_difficulty.as_deref(),
                );

                if tmpl.seed_hash != current_seed {
                    eprintln!("Seed hash changed — need to restart with new dataset");
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
                });
            }
            last_template_fetch = Instant::now();
        }

        // Refresh template every 5 seconds
        if !block_found && last_template_fetch.elapsed() > Duration::from_secs(5) {
            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = parse_difficulty(
                    tmpl.difficulty,
                    tmpl.wide_difficulty.as_deref(),
                );

                if tmpl.seed_hash != current_seed {
                    eprintln!("\nSeed hash changed — need to restart with new dataset");
                    mining_loop.stop();
                    break;
                }

                if tmpl.prev_hash != current_prev_hash || tmpl.height != current_height || new_diff != current_difficulty {
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
                eprintln!("Hashrate: {} ({:.1} H/s per thread)",
                    format_hashrate(hr), hr / args.threads as f64);
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
