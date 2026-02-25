//! Background mining: monitors system idle % and battery status, throttles
//! mining CPU usage accordingly. Matches C++ `background_worker_thread()` behavior.

use crate::miner::ThrottleState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Configuration for background mining behavior.
pub struct BackgroundConfig {
    /// System idle % threshold to start mining (0-99, default 90).
    pub idle_threshold: u8,
    /// Minimum interval between idle checks in seconds (10-3600, default 10).
    pub min_idle_interval_secs: u64,
    /// Target CPU usage % for the miner when active (1-100, default 40).
    pub mining_target_pct: u8,
}

impl Default for BackgroundConfig {
    fn default() -> Self {
        Self {
            idle_threshold: 90,
            min_idle_interval_secs: 10,
            mining_target_pct: 40,
        }
    }
}

const EXTRA_SLEEP_INITIAL_US: u64 = 400_000; // 400ms — very conservative start
const EXTRA_SLEEP_MIN_US: u64 = 5_000; // 5ms floor

// ── Platform: Linux ──────────────────────────────────────────────────────────

/// Raw CPU time snapshot from /proc/stat.
#[derive(Clone, Copy, Debug)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub rest: u64, // iowait + irq + softirq + steal + guest + guest_nice
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.rest
    }
}

/// Compute idle percentage between two snapshots.
pub fn idle_percentage(prev: &CpuTimes, curr: &CpuTimes) -> f64 {
    let total_delta = curr.total().saturating_sub(prev.total());
    if total_delta == 0 {
        return 100.0;
    }
    let idle_delta = curr.idle.saturating_sub(prev.idle);
    (idle_delta as f64 / total_delta as f64) * 100.0
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// Read aggregate CPU times from /proc/stat (first "cpu" line).
    pub fn read_cpu_times() -> Option<CpuTimes> {
        let data = std::fs::read_to_string("/proc/stat").ok()?;
        let line = data.lines().next()?;
        if !line.starts_with("cpu ") {
            return None;
        }
        let mut vals = line[4..]
            .split_whitespace()
            .filter_map(|s| s.parse::<u64>().ok());
        let user = vals.next()?;
        let nice = vals.next()?;
        let system = vals.next()?;
        let idle = vals.next()?;
        let rest: u64 = vals.sum();
        Some(CpuTimes {
            user,
            nice,
            system,
            idle,
            rest,
        })
    }

    /// Check if system is on AC power.
    ///
    /// Reads `/sys/class/power_supply/*/type` looking for "Mains" supplies,
    /// then checks their `/online` status. If no mains supply is found, assumes
    /// desktop (always on AC).
    pub fn on_ac_power() -> bool {
        let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") else {
            return true; // no sysfs = assume desktop
        };

        let mut found_mains = false;
        for entry in entries.flatten() {
            let path = entry.path();
            let type_path = path.join("type");
            if let Ok(psu_type) = std::fs::read_to_string(&type_path) {
                if psu_type.trim() == "Mains" {
                    found_mains = true;
                    let online_path = path.join("online");
                    if let Ok(val) = std::fs::read_to_string(&online_path) {
                        if val.trim() == "1" {
                            return true;
                        }
                    }
                }
            }
        }

        // No mains supply found → desktop → assume AC
        if !found_mains {
            return true;
        }

        false // mains found but none online → on battery
    }

    /// Get process CPU ticks (user + system) via libc::times().
    pub fn process_cpu_ticks() -> u64 {
        unsafe {
            let mut tms: libc::tms = std::mem::zeroed();
            libc::times(&mut tms);
            (tms.tms_utime + tms.tms_stime) as u64
        }
    }

    /// Clock ticks per second.
    pub fn ticks_per_second() -> u64 {
        unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    // TODO: macOS implementation using host_statistics / IOPSCopyPowerSourcesInfo
    pub fn read_cpu_times() -> Option<CpuTimes> {
        // Stub: report 100% idle
        Some(CpuTimes {
            user: 0,
            nice: 0,
            system: 0,
            idle: 1_000_000,
            rest: 0,
        })
    }

    pub fn on_ac_power() -> bool {
        true // assume AC on non-Linux
    }

    pub fn process_cpu_ticks() -> u64 {
        0
    }

    pub fn ticks_per_second() -> u64 {
        100
    }
}

pub use platform::{on_ac_power, process_cpu_ticks, read_cpu_times, ticks_per_second};

// ── Background Monitor ──────────────────────────────────────────────────────

/// Background mining monitor that adjusts throttle state based on system idle %
/// and AC power status.
pub struct BackgroundMonitor {
    handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl BackgroundMonitor {
    /// Start the background monitor thread.
    ///
    /// Sets `throttle.paused = true` and `extra_sleep_us = 400ms` initially.
    /// Mining will only begin once the system is idle enough and on AC power.
    pub fn start(
        throttle: ThrottleState,
        engine_running: Arc<AtomicBool>,
        config: BackgroundConfig,
    ) -> Self {
        let monitor_running = Arc::new(AtomicBool::new(true));

        // Start paused with conservative initial sleep
        throttle.paused.store(true, Ordering::Relaxed);
        throttle
            .extra_sleep_us
            .store(EXTRA_SLEEP_INITIAL_US, Ordering::Relaxed);

        let running = monitor_running.clone();
        let handle = thread::Builder::new()
            .name("bg-monitor".into())
            .spawn(move || {
                background_monitor_loop(&throttle, &engine_running, &running, &config);
            })
            .expect("failed to spawn bg-monitor thread");

        Self {
            handle: Some(handle),
            running: monitor_running,
        }
    }
}

impl Drop for BackgroundMonitor {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Sleep for `duration` but wake early if `running` becomes false.
/// Polls every 500ms.
fn interruptible_sleep(duration: Duration, running: &AtomicBool) {
    let poll = Duration::from_millis(500);
    let mut remaining = duration;
    while remaining > Duration::ZERO && running.load(Ordering::Relaxed) {
        let sleep_time = remaining.min(poll);
        thread::sleep(sleep_time);
        remaining = remaining.saturating_sub(sleep_time);
    }
}

fn background_monitor_loop(
    throttle: &ThrottleState,
    engine_running: &AtomicBool,
    monitor_running: &AtomicBool,
    config: &BackgroundConfig,
) {
    // Initial CPU time snapshot
    let mut prev_cpu = match read_cpu_times() {
        Some(t) => t,
        None => {
            eprintln!("[bg-monitor] Cannot read CPU times, background mining disabled");
            return;
        }
    };
    let mut prev_proc_ticks = process_cpu_ticks();
    let tps = ticks_per_second();

    // Wait one interval before first decision
    interruptible_sleep(
        Duration::from_secs(config.min_idle_interval_secs),
        monitor_running,
    );

    let mut is_mining = false;

    while monitor_running.load(Ordering::Relaxed) && engine_running.load(Ordering::Relaxed) {
        // Sample system idle
        let curr_cpu = match read_cpu_times() {
            Some(t) => t,
            None => {
                interruptible_sleep(Duration::from_secs(1), monitor_running);
                continue;
            }
        };
        let idle_pct = idle_percentage(&prev_cpu, &curr_cpu);

        // Sample process CPU %
        let curr_proc_ticks = process_cpu_ticks();
        let total_delta = curr_cpu.total().saturating_sub(prev_cpu.total());
        let proc_delta = curr_proc_ticks.saturating_sub(prev_proc_ticks);
        let miner_pct = if total_delta > 0 && tps > 0 {
            // Convert process ticks to same scale as /proc/stat jiffies
            (proc_delta as f64 / tps as f64) / (total_delta as f64 / tps as f64) * 100.0
        } else {
            0.0
        };

        let ac = on_ac_power();

        prev_cpu = curr_cpu;
        prev_proc_ticks = curr_proc_ticks;

        if !is_mining {
            // Not mining → check if we should start
            if idle_pct >= config.idle_threshold as f64 && ac {
                eprintln!(
                    "[bg-monitor] System idle ({:.0}%), on AC — starting mining",
                    idle_pct
                );
                throttle.paused.store(false, Ordering::Relaxed);
                is_mining = true;
            }
        } else {
            // Currently mining → check if we should stop
            if (idle_pct + miner_pct) < config.idle_threshold as f64 || !ac {
                eprintln!(
                    "[bg-monitor] System busy (idle={:.0}%, miner={:.0}%) or on battery — pausing",
                    idle_pct, miner_pct
                );
                throttle.paused.store(true, Ordering::Relaxed);
                throttle
                    .extra_sleep_us
                    .store(EXTRA_SLEEP_INITIAL_US, Ordering::Relaxed);
                is_mining = false;
            } else {
                // Adjust throttle: try to converge miner_pct toward target
                let target = config.mining_target_pct as f64;
                let error = miner_pct - target; // positive = too hot, negative = too cold
                let adjustment = (error * 10_000.0) as i64; // ~10ms per 1% error

                let current = throttle.extra_sleep_us.load(Ordering::Relaxed);
                let new_sleep = (current as i64 + adjustment).max(EXTRA_SLEEP_MIN_US as i64) as u64;
                throttle.extra_sleep_us.store(new_sleep, Ordering::Relaxed);
            }
        }

        interruptible_sleep(
            Duration::from_secs(config.min_idle_interval_secs),
            monitor_running,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_throttle_state_default() {
        let ts = ThrottleState::default();
        assert_eq!(ts.extra_sleep_us.load(Ordering::Relaxed), 0);
        assert!(!ts.paused.load(Ordering::Relaxed));
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_idle_percentage_math() {
        let prev = CpuTimes {
            user: 100,
            nice: 0,
            system: 50,
            idle: 800,
            rest: 50,
        };
        let curr = CpuTimes {
            user: 200,
            nice: 0,
            system: 100,
            idle: 1600,
            rest: 100,
        };
        let pct = idle_percentage(&prev, &curr);
        // idle_delta = 800, total_delta = 1000 → 80%
        assert!((pct - 80.0).abs() < 0.01, "got {pct}");
    }

    #[test]
    fn test_idle_percentage_zero_delta() {
        let snap = CpuTimes {
            user: 100,
            nice: 0,
            system: 50,
            idle: 800,
            rest: 50,
        };
        assert_eq!(idle_percentage(&snap, &snap), 100.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_cpu_times_parse() {
        let times = read_cpu_times();
        assert!(times.is_some(), "/proc/stat should be readable on Linux");
        let t = times.unwrap();
        assert!(t.total() > 0);
    }

    #[test]
    fn test_on_ac_power_no_panic() {
        // Just verify it doesn't panic
        let _ = on_ac_power();
    }

    #[test]
    fn test_sleep_interruptible_early_exit() {
        let flag = Arc::new(AtomicBool::new(true));
        let flag2 = flag.clone();

        // Set flag to false after 100ms
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag2.store(false, Ordering::Relaxed);
        });

        let start = Instant::now();
        interruptible_sleep(Duration::from_secs(10), &flag);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "Should exit early, took {:?}",
            elapsed
        );
    }

    #[test]
    fn test_monitor_starts_paused() {
        let throttle = ThrottleState::default();
        let engine_running = Arc::new(AtomicBool::new(true));

        // Start monitor — it should set paused=true
        let monitor = BackgroundMonitor::start(
            throttle.clone(),
            engine_running.clone(),
            BackgroundConfig::default(),
        );

        assert!(throttle.paused.load(Ordering::Relaxed));
        assert_eq!(
            throttle.extra_sleep_us.load(Ordering::Relaxed),
            EXTRA_SLEEP_INITIAL_US
        );

        // Clean shutdown
        engine_running.store(false, Ordering::Relaxed);
        drop(monitor);
    }

    #[test]
    fn test_pause_resume() {
        let ts = ThrottleState::default();
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 0);

        ts.pause();
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 1);

        ts.pause();
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 2);

        ts.resume();
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 1);

        ts.resume();
        assert_eq!(ts.pausers_count.load(Ordering::Relaxed), 0);
    }
}
