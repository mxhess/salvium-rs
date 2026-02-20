//! Stratum v1 protocol client for pool mining.
//!
//! Implements the Bitcoin-derived stratum protocol used by GhostRider pools
//! (e.g. Raptoreum). Communication is line-delimited JSON-RPC over TCP.
//!
//! ## Protocol flow
//! 1. `mining.subscribe` → pool returns extranonce1 and extranonce2_size
//! 2. `mining.authorize` → authenticate worker
//! 3. `mining.set_difficulty` ← pool sets share difficulty
//! 4. `mining.notify` ← pool sends new jobs
//! 5. `mining.submit` → miner submits shares

use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Stratum v1 client managing a TCP connection to a mining pool.
pub struct StratumClient {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    worker: String,
    next_id: u64,
}

/// A mining job received from the pool via `mining.notify`.
#[derive(Clone, Debug)]
pub struct StratumJob {
    pub job_id: String,
    pub prevhash: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub merkle_branches: Vec<[u8; 32]>,
    pub version: u32,
    pub nbits: u32,
    pub ntime: u32,
    pub clean_jobs: bool,
}

/// Events produced by polling the stratum connection.
pub enum StratumEvent {
    Job(StratumJob),
    SetDifficulty(f64),
    Accepted,
    Rejected(String),
}

/// Convert stratum pool difficulty to 32-byte big-endian target.
///
/// The base target for difficulty 1 is `0x00000000FFFF0000...0` (the Bitcoin
/// difficulty-1 target used by stratum). target = base_target / difficulty.
pub fn difficulty_to_target(difficulty: f64) -> [u8; 32] {
    if difficulty <= 0.0 {
        return [0xff; 32];
    }

    // Base target for difficulty 1 (Bitcoin stratum convention):
    // 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    // As a floating-point: 0xFFFF * 2^208
    //
    // We compute target = base / difficulty as a 256-bit big-endian integer.
    // Use the approach: target_f64 = (0xFFFF as f64) * 2^208 / difficulty,
    // then convert to 256-bit.

    // Work in 64-bit chunks (big-endian: [most significant ... least significant])
    // base_target as 4x u64 BE: [0x0000_0000_FFFF_0000, 0, 0, 0]
    // That's 0xFFFF << 48 in the first u64, shifted left by 192 bits total = 0xFFFF * 2^(48+192) = 2^240
    // Wait, let's be precise:
    // 0x00000000FFFF0000 00000000 00000000 00000000 00000000 00000000 00000000
    // byte 0..3 = 0x00000000
    // byte 4..5 = 0xFFFF
    // byte 6..31 = 0x00..00
    // As a number: 0xFFFF << (26*8) = 0xFFFF << 208

    // Simple approach: compute in f64 then write bytes
    // For very high difficulty this loses precision, but stratum pools rarely
    // need more than ~53 bits of precision.

    let base = 0xFFFF_u64 as f64 * (2.0_f64).powi(208);
    let target_f64 = base / difficulty;

    if target_f64 >= (2.0_f64).powi(256) {
        return [0xff; 32];
    }
    if target_f64 < 1.0 {
        return [0u8; 32];
    }

    // Convert f64 to 256-bit big-endian by extracting 32-bit chunks
    let mut target = [0u8; 32];
    let mut remaining = target_f64;

    for i in 0..8 {
        let shift = (7 - i) as u32 * 32;
        let chunk_value = (2.0_f64).powi(shift as i32);
        let chunk = (remaining / chunk_value) as u32;
        remaining -= chunk as f64 * chunk_value;
        let bytes = chunk.to_be_bytes();
        target[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    target
}

/// Double-SHA256 hash (used for coinbase and merkle tree).
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Decode a hex string into bytes. Returns empty vec on error.
fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_default()
}

/// Parse a stratum hex prevhash (64 hex chars) into 32 bytes.
/// Stratum sends prevhash as 8 groups of 4 bytes, each group in LE order
/// but groups in BE order. We just decode straight hex since most pools
/// send it as a flat 64-char hex string.
fn parse_prevhash(hex_str: &str) -> [u8; 32] {
    let bytes = hex_decode(hex_str);
    let mut out = [0u8; 32];
    if bytes.len() >= 32 {
        out.copy_from_slice(&bytes[..32]);
    }
    out
}

impl StratumClient {
    /// Connect to a stratum pool. URL should be `host:port` or
    /// `stratum+tcp://host:port`.
    pub fn connect(url: &str) -> io::Result<Self> {
        let addr = url
            .trim_start_matches("stratum+tcp://")
            .trim_start_matches("stratum://")
            .trim_end_matches('/');

        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_nodelay(true)?;

        let reader = BufReader::new(stream.try_clone()?);

        Ok(Self {
            stream,
            reader,
            extranonce1: Vec::new(),
            extranonce2_size: 4,
            worker: String::new(),
            next_id: 1,
        })
    }

    /// Send a JSON-RPC request and return the assigned ID.
    fn send_request(&mut self, method: &str, params: serde_json::Value) -> io::Result<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let req = serde_json::json!({
            "id": id,
            "method": method,
            "params": params,
        });

        let mut line = serde_json::to_string(&req)
            .map_err(io::Error::other)?;
        line.push('\n');
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;

        Ok(id)
    }

    /// Read a single line from the connection (blocking, with timeout from socket).
    fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )),
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(trimmed))
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Read a line, blocking until one arrives (with a longer timeout).
    fn read_line_blocking(&mut self) -> io::Result<String> {
        // Temporarily set a longer timeout for blocking reads
        self.stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let result = loop {
            match self.read_line()? {
                Some(line) => break Ok(line),
                None => continue,
            }
        };
        // Restore short timeout for non-blocking polling
        self.stream.set_read_timeout(Some(Duration::from_millis(100)))?;
        result
    }

    /// Send `mining.subscribe` and parse the response to get extranonce1 and
    /// extranonce2_size.
    pub fn subscribe(&mut self, agent: &str) -> io::Result<()> {
        self.send_request(
            "mining.subscribe",
            serde_json::json!([agent]),
        )?;

        // Read response — may need to skip notifications that arrive first
        loop {
            let line = self.read_line_blocking()?;
            let msg: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // If this is a response (has "result" and numeric "id"), process it
            if msg.get("result").is_some() && msg.get("id").is_some() {
                if let Some(err) = msg.get("error") {
                    if !err.is_null() {
                        return Err(io::Error::other(
                            format!("subscribe error: {}", err),
                        ));
                    }
                }

                let result = msg.get("result").unwrap();
                // Result format: [[["mining.set_difficulty", "sub_id"], ["mining.notify", "sub_id"]], extranonce1_hex, extranonce2_size]
                if let Some(arr) = result.as_array() {
                    if arr.len() >= 3 {
                        if let Some(en1_hex) = arr[1].as_str() {
                            self.extranonce1 = hex_decode(en1_hex);
                        }
                        if let Some(en2_size) = arr[2].as_u64() {
                            self.extranonce2_size = en2_size as usize;
                        }
                    }
                }

                eprintln!(
                    "[stratum] Subscribed: extranonce1={}, extranonce2_size={}",
                    hex::encode(&self.extranonce1),
                    self.extranonce2_size
                );
                return Ok(());
            }
            // Otherwise it's a notification (mining.set_difficulty, etc.) — skip for now
        }
    }

    /// Send `mining.authorize` to authenticate the worker.
    pub fn authorize(&mut self, worker: &str, password: &str) -> io::Result<()> {
        self.worker = worker.to_string();
        self.send_request(
            "mining.authorize",
            serde_json::json!([worker, password]),
        )?;

        // Read response
        loop {
            let line = self.read_line_blocking()?;
            let msg: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if msg.get("result").is_some() && msg.get("id").is_some() {
                let result = msg.get("result").unwrap();
                if result.as_bool() == Some(true) {
                    eprintln!("[stratum] Authorized as {}", worker);
                    return Ok(());
                }
                let err = msg.get("error").cloned().unwrap_or(serde_json::Value::Null);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("authorize failed: {}", err),
                ));
            }
            // Skip notifications
        }
    }

    /// Non-blocking poll for stratum events (jobs, difficulty changes, submit results).
    pub fn poll(&mut self) -> io::Result<Option<StratumEvent>> {
        let line = match self.read_line()? {
            Some(l) => l,
            None => return Ok(None),
        };

        let msg: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Check if it's a notification (has "method")
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            match method {
                "mining.notify" => {
                    if let Some(params) = msg.get("params").and_then(|p| p.as_array()) {
                        if let Some(job) = Self::parse_notify(params) {
                            return Ok(Some(StratumEvent::Job(job)));
                        }
                    }
                }
                "mining.set_difficulty" => {
                    if let Some(params) = msg.get("params").and_then(|p| p.as_array()) {
                        if let Some(diff) = params.first().and_then(|d| d.as_f64()) {
                            return Ok(Some(StratumEvent::SetDifficulty(diff)));
                        }
                    }
                }
                _ => {
                    // Unknown notification, ignore
                }
            }
        }

        // Check if it's a response to a submit (has "id" and "result")
        if msg.get("id").is_some() && msg.get("result").is_some() {
            let result = msg.get("result").unwrap();
            if result.as_bool() == Some(true) {
                return Ok(Some(StratumEvent::Accepted));
            } else {
                let err = msg
                    .get("error")
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                return Ok(Some(StratumEvent::Rejected(err)));
            }
        }

        Ok(None)
    }

    /// Parse a `mining.notify` params array into a StratumJob.
    fn parse_notify(params: &[serde_json::Value]) -> Option<StratumJob> {
        // params: [job_id, prevhash, coinb1, coinb2, merkle_branches[], version, nbits, ntime, clean_jobs]
        if params.len() < 9 {
            return None;
        }

        let job_id = params[0].as_str()?.to_string();
        let prevhash = parse_prevhash(params[1].as_str()?);
        let coinb1 = hex_decode(params[2].as_str()?);
        let coinb2 = hex_decode(params[3].as_str()?);

        let branches_arr = params[4].as_array()?;
        let mut merkle_branches = Vec::with_capacity(branches_arr.len());
        for branch in branches_arr {
            let bytes = hex_decode(branch.as_str()?);
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            merkle_branches.push(arr);
        }

        let version = u32::from_str_radix(params[5].as_str()?, 16).ok()?;
        let nbits = u32::from_str_radix(params[6].as_str()?, 16).ok()?;
        let ntime = u32::from_str_radix(params[7].as_str()?, 16).ok()?;
        let clean_jobs = params[8].as_bool().unwrap_or(false);

        Some(StratumJob {
            job_id,
            prevhash,
            coinb1,
            coinb2,
            merkle_branches,
            version,
            nbits,
            ntime,
            clean_jobs,
        })
    }

    /// Submit a share to the pool.
    pub fn submit_share(
        &mut self,
        job_id: &str,
        extranonce2: &[u8],
        ntime: u32,
        nonce: u32,
    ) -> io::Result<()> {
        let en2_hex = hex::encode(extranonce2);
        let ntime_hex = format!("{:08x}", ntime);
        let nonce_hex = format!("{:08x}", nonce);

        self.send_request(
            "mining.submit",
            serde_json::json!([
                self.worker,
                job_id,
                en2_hex,
                ntime_hex,
                nonce_hex,
            ]),
        )?;

        Ok(())
    }

    /// Build an 80-byte block header from a stratum job and extranonce2.
    pub fn build_header(&self, job: &StratumJob, extranonce2: &[u8]) -> [u8; 80] {
        build_header(&self.extranonce1, job, extranonce2)
    }

    /// Get the extranonce2 size configured by the pool.
    pub fn extranonce2_size(&self) -> usize {
        self.extranonce2_size
    }
}

/// Build an 80-byte block header from a stratum job, extranonce1, and extranonce2.
///
/// 1. Coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
/// 2. Coinbase hash = SHA256d(coinbase)
/// 3. Merkle root = fold coinbase_hash through branches with SHA256d(acc + branch)
/// 4. Header = version_le(4) + prevhash(32) + merkle_root(32) + ntime_le(4) + nbits_le(4) + nonce(4)
pub fn build_header(extranonce1: &[u8], job: &StratumJob, extranonce2: &[u8]) -> [u8; 80] {
    // Build coinbase transaction
    let mut coinbase = Vec::with_capacity(
        job.coinb1.len() + extranonce1.len() + extranonce2.len() + job.coinb2.len(),
    );
    coinbase.extend_from_slice(&job.coinb1);
    coinbase.extend_from_slice(extranonce1);
    coinbase.extend_from_slice(extranonce2);
    coinbase.extend_from_slice(&job.coinb2);

    // Hash coinbase
    let mut merkle_root = sha256d(&coinbase);

    // Build merkle root by folding through branches
    for branch in &job.merkle_branches {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&merkle_root);
        combined[32..].copy_from_slice(branch);
        merkle_root = sha256d(&combined);
    }

    // Assemble 80-byte header
    let mut header = [0u8; 80];
    header[0..4].copy_from_slice(&job.version.to_le_bytes());
    header[4..36].copy_from_slice(&job.prevhash);
    header[36..68].copy_from_slice(&merkle_root);
    header[68..72].copy_from_slice(&job.ntime.to_le_bytes());
    header[72..76].copy_from_slice(&job.nbits.to_le_bytes());
    // bytes 76..80 = nonce placeholder (zeroed, miner fills it)

    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_to_target_diff1() {
        let target = difficulty_to_target(1.0);
        // Should be 0x00000000FFFF0000...0
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x00);
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xFF);
        assert_eq!(target[5], 0xFF);
        // Rest should be zeros
        for &b in &target[6..] {
            assert_eq!(b, 0x00);
        }
    }

    #[test]
    fn test_difficulty_to_target_diff2() {
        let target = difficulty_to_target(2.0);
        // Should be half of diff1 target
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x00);
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0x7F);
        assert_eq!(target[5], 0xFF);
        assert_eq!(target[6], 0x80);
    }

    #[test]
    fn test_difficulty_to_target_zero() {
        let target = difficulty_to_target(0.0);
        assert_eq!(target, [0xff; 32]);
    }

    #[test]
    fn test_difficulty_to_target_negative() {
        let target = difficulty_to_target(-1.0);
        assert_eq!(target, [0xff; 32]);
    }

    #[test]
    fn test_sha256d() {
        // SHA256d("") = SHA256(SHA256(""))
        let result = sha256d(b"");
        let expected = hex::decode(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        )
        .unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_build_header_structure() {
        let extranonce1 = vec![0x01, 0x02, 0x03, 0x04];

        let job = StratumJob {
            job_id: "test".to_string(),
            prevhash: [0xAA; 32],
            coinb1: vec![0x01, 0x02],
            coinb2: vec![0x03, 0x04],
            merkle_branches: vec![],
            version: 0x20000000,
            nbits: 0x1a00e1fd,
            ntime: 0x60000000,
            clean_jobs: true,
        };

        let en2 = vec![0x00, 0x00, 0x00, 0x01];
        let header = build_header(&extranonce1, &job, &en2);

        // Check version (LE)
        assert_eq!(&header[0..4], &0x20000000_u32.to_le_bytes());
        // Check prevhash
        assert_eq!(&header[4..36], &[0xAA; 32]);
        // Merkle root should be SHA256d of coinbase (since no branches)
        let coinbase = vec![0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01, 0x03, 0x04];
        let expected_root = sha256d(&coinbase);
        assert_eq!(&header[36..68], &expected_root);
        // Check ntime (LE)
        assert_eq!(&header[68..72], &0x60000000_u32.to_le_bytes());
        // Check nbits (LE)
        assert_eq!(&header[72..76], &0x1a00e1fd_u32.to_le_bytes());
        // Nonce placeholder should be zero
        assert_eq!(&header[76..80], &[0, 0, 0, 0]);

        // Total length
        assert_eq!(header.len(), 80);
    }

    #[test]
    fn test_check_hash_target() {
        use crate::miner::check_hash_target;

        // Hash less than target → valid
        let hash = [0u8; 32]; // all zeros = smallest possible
        let target = [0xFF; 32]; // all 0xFF = largest possible
        assert!(check_hash_target(&hash, &target));

        // Hash greater than target → invalid
        let hash = [0xFF; 32];
        let target = [0u8; 32];
        assert!(!check_hash_target(&hash, &target));

        // Hash equal to target → valid
        let hash = [0x42; 32];
        let target = [0x42; 32];
        assert!(check_hash_target(&hash, &target));
    }

    #[test]
    fn test_parse_notify() {
        let params: Vec<serde_json::Value> = serde_json::from_str(r#"[
            "job_123",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "01020304",
            "05060708",
            ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "20000000",
            "1a00e1fd",
            "60000000",
            true
        ]"#).unwrap();

        let job = StratumClient::parse_notify(&params).unwrap();
        assert_eq!(job.job_id, "job_123");
        assert_eq!(job.version, 0x20000000);
        assert_eq!(job.nbits, 0x1a00e1fd);
        assert_eq!(job.ntime, 0x60000000);
        assert!(job.clean_jobs);
        assert_eq!(job.merkle_branches.len(), 1);
        assert_eq!(job.coinb1, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(job.coinb2, vec![0x05, 0x06, 0x07, 0x08]);
    }
}
