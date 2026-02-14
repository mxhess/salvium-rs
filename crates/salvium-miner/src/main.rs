use clap::Parser;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod daemon;
mod ipc;
mod miner;
mod stratum;

use daemon::DaemonClient;
use miner::{MiningEngine, MiningJob};

#[derive(Parser)]
#[command(name = "salvium-miner")]
#[command(about = "Native RandomX CPU miner for Salvium")]
struct Args {
    /// Daemon RPC URL
    #[arg(short, long, default_value = "http://127.0.0.1:29081")]
    daemon: String,

    /// Wallet address for mining rewards (not required in IPC mode)
    #[arg(short, long, default_value = "")]
    wallet: String,

    /// Number of mining threads
    #[arg(short, long, default_value_t = default_threads())]
    threads: usize,

    /// Use light mode (256MB per thread instead of 2GB shared dataset)
    #[arg(long)]
    light: bool,

    /// Run benchmark for 20 seconds and exit
    #[arg(long)]
    benchmark: bool,

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
        ipc::run_ipc(args.threads, args.light);
        return;
    }

    if args.wallet.is_empty() {
        eprintln!("Error: --wallet is required (unless using --ipc mode)");
        std::process::exit(1);
    }

    eprintln!("Salvium Native RandomX Miner");
    eprintln!("============================");
    eprintln!("Daemon:  {}", args.daemon);
    eprintln!("Wallet:  {}...", &args.wallet[..20.min(args.wallet.len())]);
    eprintln!("Threads: {}", args.threads);
    eprintln!("Mode:    {}", if args.light { "light (256MB/thread)" } else { "full (2GB shared dataset)" });
    eprintln!();

    // Connect to daemon (retry up to 5 times)
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

    // Get initial block template (retry up to 5 times for transient daemon errors)
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

    let difficulty = miner::parse_difficulty(
        template.difficulty,
        template.wide_difficulty.as_deref(),
    );

    eprintln!("Template: height={}, difficulty={}", template.height, difficulty);

    let seed_bytes = hex::decode(&template.seed_hash).unwrap_or_else(|_| vec![0u8; 32]);
    let hashing_blob = hex::decode(&template.blockhashing_blob).expect("Invalid hashing blob");
    let template_blob = hex::decode(&template.blocktemplate_blob).expect("Invalid template blob");

    // Initialize mining engine
    let engine = if args.light {
        MiningEngine::new_light(args.threads, &seed_bytes)
    } else {
        MiningEngine::new_full(args.threads, &seed_bytes)
    };

    let engine = match engine {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to initialize mining engine: {}", e);
            std::process::exit(1);
        }
    };

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
            while engine.try_recv_block().is_some() { drained += 1; }

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

            // Drain stale blocks, then immediately fetch new template.
            while engine.try_recv_block().is_some() {}

            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = miner::parse_difficulty(
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
                });

                eprintln!("Template: height={} diff={} prev={:.16}...",
                    tmpl.height, new_diff, tmpl.prev_hash);
            }
            last_template_fetch = Instant::now();
        }

        // Refresh template every 5 seconds (routine poll)
        if !block_found && last_template_fetch.elapsed() > Duration::from_secs(5) {
            if let Ok(tmpl) = client.get_block_template(&args.wallet, 8) {
                let new_diff = miner::parse_difficulty(
                    tmpl.difficulty,
                    tmpl.wide_difficulty.as_deref(),
                );

                if tmpl.seed_hash != current_seed {
                    eprintln!("\nSeed hash changed — need to restart with new dataset");
                    engine.stop();
                    break;
                }

                // Send new job if anything changed
                if tmpl.prev_hash != current_prev_hash || tmpl.height != current_height || new_diff != current_difficulty {
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

            // Benchmark mode: exit after 20 seconds
            if args.benchmark && elapsed > 20.0 {
                eprintln!();
                eprintln!();
                eprintln!("=== Benchmark Results ===");
                eprintln!("Threads:  {}", args.threads);
                eprintln!("Mode:     {}", if args.light { "light" } else { "full" });
                eprintln!("Duration: {:.1}s", elapsed);
                eprintln!("Hashes:   {}", total);
                eprintln!("Hashrate: {} ({:.1} H/s per thread)",
                    format_hashrate(hr), hr / args.threads as f64);
                engine.stop();
                break;
            }
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
