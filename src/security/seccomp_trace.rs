//! Seccomp trace mode: record syscalls for profile generation.
//!
//! In trace mode, an allow-all seccomp filter is installed with
//! `SECCOMP_FILTER_FLAG_LOG`, causing the kernel to log every syscall to
//! the audit subsystem. A reader thread monitors `/dev/kmsg` for
//! SECCOMP audit records matching the container PID and writes unique
//! syscalls to an NDJSON trace file.
//!
//! This is a development tool — requires root or CAP_SYSLOG for
//! `/dev/kmsg` access.

use crate::error::{NucleusError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

/// A single trace record in the NDJSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    /// Syscall number (e.g. 0 for read on x86_64).
    pub syscall: i64,
    /// Syscall name if known.
    pub name: Option<String>,
    /// Number of times this syscall was observed.
    pub count: u64,
}

/// Reads `/dev/kmsg` for SECCOMP audit records and collects unique syscalls.
pub struct SeccompTraceReader {
    pid: u32,
    output_path: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SeccompTraceReader {
    /// Create a new trace reader for the given child PID.
    pub fn new(pid: u32, output_path: &Path) -> Self {
        Self {
            pid,
            output_path: output_path.to_path_buf(),
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Start the background reader thread.
    ///
    /// Opens `/dev/kmsg` and filters for `audit: type=1326` (SECCOMP)
    /// messages matching the target PID.
    pub fn start_recording(&mut self) -> Result<()> {
        let pid = self.pid;
        let output_path = self.output_path.clone();
        let stop = self.stop.clone();

        let handle = std::thread::spawn(move || {
            if let Err(e) = record_loop(pid, &output_path, &stop) {
                warn!("Seccomp trace reader error: {}", e);
            }
        });

        self.handle = Some(handle);
        info!("Seccomp trace reader started for PID {}", self.pid);
        Ok(())
    }

    /// Signal the reader to stop and wait for it to flush.
    pub fn stop_and_flush(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        info!(
            "Seccomp trace reader stopped, output at {:?}",
            self.output_path
        );
    }
}

/// Main recording loop — reads /dev/kmsg and extracts SECCOMP records.
fn record_loop(pid: u32, output_path: &Path, stop: &AtomicBool) -> Result<()> {
    let mut syscalls: BTreeMap<i64, u64> = BTreeMap::new();

    // Open /dev/kmsg for reading (requires CAP_SYSLOG or root)
    let file = match std::fs::File::open("/dev/kmsg") {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "Cannot open /dev/kmsg for seccomp tracing: {} \
                 (requires root or CAP_SYSLOG). Falling back to no-trace mode.",
                e
            );
            // Write empty trace file
            write_trace_file(output_path, &syscalls)?;
            return Ok(());
        }
    };

    // Set a read timeout on /dev/kmsg so the thread doesn't block indefinitely
    // if the stop flag is never set (e.g., parent thread panics). Without this,
    // the thread holds /dev/kmsg open forever.
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let reader = BufReader::new(file);
    let pid_pattern = format!("pid={}", pid);

    for line in reader.lines() {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    // Read timeout expired — check stop flag and retry
                    continue;
                }
                debug!("kmsg read error: {}", e);
                continue;
            }
        };

        // SECCOMP audit lines look like:
        // audit: type=1326 ... pid=<PID> ... syscall=<NR> ...
        if line.contains("type=1326") && line.contains(&pid_pattern) {
            if let Some(nr) = extract_syscall_nr(&line) {
                *syscalls.entry(nr).or_insert(0) += 1;
            }
        }
    }

    write_trace_file(output_path, &syscalls)?;
    info!("Seccomp trace: recorded {} unique syscalls", syscalls.len());
    Ok(())
}

/// Extract the syscall number from an audit SECCOMP line.
fn extract_syscall_nr(line: &str) -> Option<i64> {
    // Look for "syscall=NNN" in the line
    line.split_whitespace()
        .find(|s| s.starts_with("syscall="))
        .and_then(|s| s.strip_prefix("syscall="))
        .and_then(|s| s.parse().ok())
}

/// Write the accumulated trace data as NDJSON.
fn write_trace_file(path: &Path, syscalls: &BTreeMap<i64, u64>) -> Result<()> {
    let mut file = std::fs::File::create(path).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to create trace file {:?}: {}", path, e))
    })?;

    for (&nr, &count) in syscalls {
        let record = TraceRecord {
            syscall: nr,
            name: super::seccomp_generate::syscall_number_to_name(nr).map(String::from),
            count,
        };
        let line = serde_json::to_string(&record).unwrap_or_default();
        writeln!(file, "{}", line).map_err(|e| {
            NucleusError::ConfigError(format!("Failed to write trace record: {}", e))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_syscall_nr() {
        let line = "6,1234,5678,-;audit: type=1326 audit(123:456): auid=0 uid=0 gid=0 ses=1 pid=42 comm=\"test\" exe=\"/bin/test\" sig=0 arch=c000003e syscall=257 compat=0 ip=0x7f action=0x7fff0000";
        assert_eq!(extract_syscall_nr(line), Some(257));
    }

    #[test]
    fn test_extract_syscall_nr_missing() {
        assert_eq!(extract_syscall_nr("no syscall here"), None);
    }

    #[test]
    fn test_trace_record_serialization() {
        let record = TraceRecord {
            syscall: 0,
            name: Some("read".to_string()),
            count: 42,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"syscall\":0"));
        assert!(json.contains("\"name\":\"read\""));
        assert!(json.contains("\"count\":42"));
    }
}
