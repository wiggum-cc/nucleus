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
        self.stop.store(true, Ordering::Release);
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

    // Verify /dev/kmsg is not a symlink before opening
    let kmsg_path = std::path::Path::new("/dev/kmsg");
    if let Ok(meta) = std::fs::symlink_metadata(kmsg_path) {
        if meta.file_type().is_symlink() {
            warn!("/dev/kmsg is a symlink — refusing to open for seccomp tracing");
            write_trace_file(output_path, &syscalls)?;
            return Ok(());
        }
    }

    // Open /dev/kmsg for reading (requires CAP_SYSLOG or root)
    let file = match std::fs::File::open(kmsg_path) {
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

    // Set O_NONBLOCK so reads don't block indefinitely. We use poll() with a
    // timeout to periodically check the stop flag. The previous setsockopt(SO_RCVTIMEO)
    // approach was incorrect: /dev/kmsg is a character device, not a socket, so
    // setsockopt silently fails with ENOTSOCK.
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let reader = BufReader::new(file);
    let pid_pattern = format!("pid={}", pid);

    for line in reader.lines() {
        if stop.load(Ordering::Acquire) {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // No data available — poll with 2s timeout, then check stop flag
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, 2000) };
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
        let line = serde_json::to_string(&record)
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
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

    /// Extract the body of a function from source text by brace-matching,
    /// avoiding fragile hardcoded character-window offsets (SEC-MED-03).
    fn extract_fn_body<'a>(source: &'a str, fn_signature: &str) -> &'a str {
        let fn_start = source.find(fn_signature)
            .unwrap_or_else(|| panic!("function '{}' not found in source", fn_signature));
        let after = &source[fn_start..];
        let open = after.find('{')
            .unwrap_or_else(|| panic!("no opening brace found for '{}'", fn_signature));
        let mut depth = 0u32;
        let mut end = open;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 { end = open + i + 1; break; }
                }
                _ => {}
            }
        }
        &after[..end]
    }

    #[test]
    fn test_reader_uses_nonblocking_io() {
        // Verify record_loop uses O_NONBLOCK + poll, not socket-only APIs.
        // /dev/kmsg is a character device; socket APIs like SO_RCVTIMEO silently fail.
        // NOTE: Uses brace-matched function body extraction (SEC-MED-03).
        let source = include_str!("seccomp_trace.rs");
        let fn_body = extract_fn_body(source, "fn record_loop");
        assert!(
            fn_body.contains("O_NONBLOCK"),
            "record_loop must use O_NONBLOCK for non-blocking reads on /dev/kmsg"
        );
        assert!(
            fn_body.contains("libc::poll"),
            "record_loop must use poll() for timed waits on /dev/kmsg"
        );
        // setsockopt must not appear in the function (socket API doesn't work on char devices)
        let setsockopt_lines: Vec<&str> = fn_body
            .lines()
            .filter(|l| !l.trim().starts_with("//"))
            .filter(|l| l.contains("setsockopt"))
            .collect();
        assert!(
            setsockopt_lines.is_empty(),
            "record_loop must not call setsockopt on /dev/kmsg"
        );
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
