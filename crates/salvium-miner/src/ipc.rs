//! IPC mode: JSON-lines protocol over stdin/stdout
//!
//! The parent process (Node.js/browser bridge) sends commands on stdin
//! and receives events on stdout. All messages are single-line JSON.
//!
//! ## Protocol
//!
//! ### Parent → Miner (stdin)
//!
//! **init** — Initialize RandomX with a seed hash. Must be sent first.
//! ```json
//! {"method":"init","seed_hash":"abc123..."}
//! ```
//!
//! **job** — Start mining a new job.
//! ```json
//! {"method":"job","job_id":"1","hashing_blob":"...","template_blob":"...","difficulty":99401,"height":46}
//! ```
//!
//! **stop** — Stop mining (keeps engine alive for next job).
//! ```json
//! {"method":"stop"}
//! ```
//!
//! **shutdown** — Exit the process.
//! ```json
//! {"method":"shutdown"}
//! ```
//!
//! ### Miner → Parent (stdout)
//!
//! **ready** — Engine initialized, workers spawned.
//! ```json
//! {"event":"ready","threads":7,"mode":"full"}
//! ```
//!
//! **hashrate** — Periodic stats (every 5s).
//! ```json
//! {"event":"hashrate","hashrate":2720.5,"hashes":54570,"elapsed":20.1}
//! ```
//!
//! **block** — Block found!
//! ```json
//! {"event":"block","job_id":"1","nonce":12345,"hash":"...","blob_hex":"..."}
//! ```
//!
//! **error** — Something went wrong.
//! ```json
//! {"event":"error","message":"..."}
//! ```
//!
//! **stopped** — Mining stopped (in response to stop command).
//! ```json
//! {"event":"stopped"}
//! ```

use crate::miner::{MiningEngine, MiningJob};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct InMessage {
    method: String,
    #[serde(default)]
    seed_hash: String,
    #[serde(default)]
    job_id: String,
    #[serde(default)]
    hashing_blob: String,
    #[serde(default)]
    template_blob: String,
    #[serde(default)]
    difficulty: u64,
    #[serde(default)]
    wide_difficulty: Option<String>,
    #[serde(default)]
    height: u64,
}

#[derive(Serialize)]
struct OutMessage {
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    threads: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashrate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl OutMessage {
    fn new(event: &str) -> Self {
        Self {
            event: event.to_string(),
            threads: None,
            mode: None,
            hashrate: None,
            hashes: None,
            elapsed: None,
            job_id: None,
            nonce: None,
            hash: None,
            blob_hex: None,
            message: None,
        }
    }
}

fn send(msg: &OutMessage) {
    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer(&mut stdout, msg);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

fn send_error(msg: &str) {
    let mut out = OutMessage::new("error");
    out.message = Some(msg.to_string());
    send(&out);
}

/// Stdin line or EOF signal
enum StdinEvent {
    Line(String),
    Eof,
}

pub fn run_ipc(threads: usize, light: bool, use_large_pages: bool) {
    let mode_str = if light { "light" } else { "full" };
    eprintln!("[IPC] Waiting for commands on stdin (threads={}, mode={})", threads, mode_str);

    // Read stdin on a dedicated thread so the main loop stays non-blocking
    let (stdin_tx, stdin_rx) = mpsc::channel::<StdinEvent>();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let reader = stdin.lock();
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if stdin_tx.send(StdinEvent::Line(l)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stdin_tx.send(StdinEvent::Eof);
    });

    let mut engine: Option<MiningEngine> = None;
    let mut current_job_id = String::new();
    let mut start_time = Instant::now();
    let mut last_stats = Instant::now();

    loop {
        // Check for found blocks
        if let Some(ref eng) = engine {
            while let Some(block) = eng.try_recv_block() {
                let mut out = OutMessage::new("block");
                out.job_id = Some(current_job_id.clone());
                out.nonce = Some(block.nonce);
                out.hash = Some(hex::encode(&block.hash));
                out.blob_hex = Some(block.blob_hex);
                send(&out);
            }

            // Send hashrate stats every 5 seconds
            if last_stats.elapsed() > Duration::from_secs(5) {
                let elapsed = start_time.elapsed().as_secs_f64();
                let total = eng.hash_count.load(Ordering::Relaxed);
                let hr = if elapsed > 0.0 { total as f64 / elapsed } else { 0.0 };

                let mut out = OutMessage::new("hashrate");
                out.hashrate = Some(hr);
                out.hashes = Some(total);
                out.elapsed = Some(elapsed);
                send(&out);
                last_stats = Instant::now();
            }
        }

        // Poll stdin (non-blocking, 100ms timeout)
        let event = stdin_rx.recv_timeout(Duration::from_millis(100));
        let line = match event {
            Ok(StdinEvent::Line(l)) => l,
            Ok(StdinEvent::Eof) => {
                eprintln!("[IPC] stdin closed, shutting down");
                if let Some(ref eng) = engine {
                    eng.stop();
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!("[IPC] stdin thread disconnected");
                break;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let msg: InMessage = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(e) => {
                send_error(&format!("Invalid JSON: {}", e));
                continue;
            }
        };

        match msg.method.as_str() {
            "init" => {
                if let Some(ref eng) = engine {
                    eng.stop();
                }

                let seed_bytes = match hex::decode(&msg.seed_hash) {
                    Ok(b) => b,
                    Err(e) => {
                        send_error(&format!("Invalid seed_hash hex: {}", e));
                        continue;
                    }
                };

                eprintln!("[IPC] Initializing RandomX (seed={}...)", &msg.seed_hash[..16.min(msg.seed_hash.len())]);

                let result = if light {
                    MiningEngine::new_light(threads, &seed_bytes, use_large_pages)
                } else {
                    MiningEngine::new_full(threads, &seed_bytes, use_large_pages)
                };

                match result {
                    Ok(eng) => {
                        engine = Some(eng);
                        start_time = Instant::now();
                        last_stats = Instant::now();

                        let mut out = OutMessage::new("ready");
                        out.threads = Some(threads);
                        out.mode = Some(mode_str.to_string());
                        send(&out);
                    }
                    Err(e) => {
                        send_error(&format!("Init failed: {}", e));
                    }
                }
            }

            "job" => {
                let eng = match engine {
                    Some(ref e) => e,
                    None => {
                        send_error("Engine not initialized. Send 'init' first.");
                        continue;
                    }
                };

                let hashing_blob = match hex::decode(&msg.hashing_blob) {
                    Ok(b) => b,
                    Err(e) => {
                        send_error(&format!("Invalid hashing_blob hex: {}", e));
                        continue;
                    }
                };
                let template_blob = match hex::decode(&msg.template_blob) {
                    Ok(b) => b,
                    Err(e) => {
                        send_error(&format!("Invalid template_blob hex: {}", e));
                        continue;
                    }
                };

                let difficulty = crate::miner::parse_difficulty(
                    msg.difficulty,
                    msg.wide_difficulty.as_deref(),
                );

                current_job_id = msg.job_id.clone();

                eng.hash_count.store(0, Ordering::Relaxed);
                start_time = Instant::now();
                last_stats = Instant::now();

                eng.send_job(MiningJob {
                    job_id: 0,
                    hashing_blob,
                    template_blob,
                    difficulty,
                    height: msg.height,
                });

                eprintln!("[IPC] Job {} started (height={}, diff={})", current_job_id, msg.height, difficulty);
            }

            "stop" => {
                eprintln!("[IPC] Mining stopped");
                send(&OutMessage::new("stopped"));
            }

            "shutdown" => {
                eprintln!("[IPC] Shutdown requested");
                if let Some(ref eng) = engine {
                    eng.stop();
                }
                break;
            }

            other => {
                send_error(&format!("Unknown method: {}", other));
            }
        }
    }
}
