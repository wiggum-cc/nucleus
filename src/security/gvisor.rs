use crate::error::{NucleusError, Result};
use crate::oci::OciBundle;
use nix::unistd::Uid;
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

/// Network mode for gVisor runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GVisorNetworkMode {
    /// No networking (fully isolated). Default for agent workloads.
    None,
    /// gVisor user-space network stack. Suitable for networked production services
    /// that need gVisor isolation with network access.
    Sandbox,
    /// Share host network namespace. Use with caution.
    Host,
}

/// Platform backend for gVisor's Sentry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum GVisorPlatform {
    /// systrap backend, the current default and most broadly compatible option.
    #[default]
    Systrap,
    /// KVM-backed sandboxing for the Sentry itself.
    Kvm,
    /// ptrace backend for maximal compatibility where systrap/KVM are unavailable.
    Ptrace,
}

impl GVisorPlatform {
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::Systrap => "systrap",
            Self::Kvm => "kvm",
            Self::Ptrace => "ptrace",
        }
    }
}

/// GVisor runtime manager
///
/// Implements the gVisor state machine from
/// NucleusSecurity_GVisor_GVisorRuntime.tla
pub struct GVisorRuntime {
    runsc_path: String,
}

impl GVisorRuntime {
    /// Create a new GVisor runtime manager
    ///
    /// This checks for runsc binary availability
    pub fn new() -> Result<Self> {
        let runsc_path = Self::find_runsc()?;
        info!("Found runsc at: {}", runsc_path);
        Ok(Self { runsc_path })
    }

    /// Create a GVisor runtime with a pre-resolved runsc path.
    ///
    /// Use this when the path was resolved before privilege changes
    /// (e.g. before entering a user namespace where UID 0 would block
    /// PATH-based lookup).
    pub fn with_path(runsc_path: String) -> Self {
        Self { runsc_path }
    }

    /// Resolve the runsc path without constructing a full runtime.
    /// Call this before fork/unshare so the path is resolved while
    /// still unprivileged.
    pub fn resolve_path() -> Result<String> {
        Self::find_runsc()
    }

    /// Find the runsc binary
    fn find_runsc() -> Result<String> {
        // Try common locations
        let paths = vec![
            "/usr/local/bin/runsc",
            "/usr/bin/runsc",
            "/opt/gvisor/runsc",
        ];

        for path in &paths {
            if let Some(validated) = Self::validate_runsc_path(Path::new(path))? {
                return Ok(validated);
            }
        }

        // For privileged execution, do not resolve runtime binaries via PATH.
        // This avoids environment-based binary hijacking when running as root.
        if Uid::effective().is_root() {
            return Err(NucleusError::GVisorError(
                "runsc binary not found in trusted system paths".to_string(),
            ));
        }

        // Try to find in PATH without invoking a shell command.
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("runsc");
                if let Some(validated) = Self::validate_runsc_path(&candidate)? {
                    return Ok(validated);
                }
            }
        }

        Err(NucleusError::GVisorError(
            "runsc binary not found. Please install gVisor.".to_string(),
        ))
    }

    fn validate_runsc_path(path: &Path) -> Result<Option<String>> {
        if !path.exists() {
            return Ok(None);
        }
        if !path.is_file() {
            return Ok(None);
        }

        let canonical = std::fs::canonicalize(path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to canonicalize runsc path {:?}: {}",
                path, e
            ))
        })?;

        // If the candidate is a shell wrapper script (common on NixOS where
        // nix wraps binaries to inject PATH), look for the real ELF binary
        // next to it.  runsc's gofer subprocess re-execs via /proc/self/exe,
        // which must point to the real binary — not a bash wrapper.
        let resolved = Self::unwrap_nix_wrapper(&canonical).unwrap_or_else(|| canonical.clone());

        let metadata = std::fs::metadata(&resolved).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to stat runsc path {:?}: {}", resolved, e))
        })?;

        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::GVisorError(format!(
                "Refusing insecure runsc binary permissions at {:?} (mode {:o})",
                resolved, mode
            )));
        }
        if mode & 0o111 == 0 {
            return Ok(None);
        }

        // Reject binaries owned by other non-root users — a malicious user
        // could place a trojan runsc earlier in PATH.
        use std::os::unix::fs::MetadataExt;
        let owner = metadata.uid();
        let current_uid = nix::unistd::Uid::effective().as_raw();
        if !Self::is_trusted_runsc_owner(&resolved, owner, current_uid) {
            return Err(NucleusError::GVisorError(format!(
                "Refusing runsc binary at {:?} owned by uid {} (expected root, current user {}, or immutable /nix/store artifact)",
                resolved, owner, current_uid
            )));
        }

        Ok(Some(resolved.to_string_lossy().to_string()))
    }

    fn is_trusted_runsc_owner(path: &Path, owner: u32, current_uid: u32) -> bool {
        if owner == 0 || owner == current_uid {
            return true;
        }

        // Nix store artifacts are immutable content-addressed paths and are
        // commonly owned by `nobody` rather than root/current user.
        // Extra hardening: verify the binary is not writable by *anyone* and
        // the parent directory is also not writable, to guard against a
        // compromised or mutable store.
        if path.starts_with("/nix/store") {
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
                // Reject if owner-writable (group/other already checked by caller)
                if mode & 0o200 != 0 {
                    return false;
                }
            } else {
                return false;
            }
            // Verify the immediate parent directory is not writable
            if let Some(parent) = path.parent() {
                if let Ok(parent_meta) = std::fs::metadata(parent) {
                    let parent_mode = parent_meta.permissions().mode();
                    if parent_mode & 0o222 != 0 {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            return true;
        }

        false
    }

    /// If `path` is a Nix wrapper script, extract the real binary path.
    ///
    /// Nix wrapper scripts end with a line like:
    ///   exec -a "$0" "/nix/store/…/.runsc-wrapped"  "$@"
    /// We parse that to find the actual ELF binary.
    fn unwrap_nix_wrapper(path: &Path) -> Option<std::path::PathBuf> {
        let content = std::fs::read_to_string(path).ok()?;
        // Only process short scripts (wrapper scripts are small)
        if content.len() > 4096 || !content.starts_with("#!") {
            return None;
        }
        // Look for the exec line that references the wrapped binary
        for line in content.lines().rev() {
            let trimmed = line.trim();
            if trimmed.starts_with("exec ") {
                // Parse: exec -a "$0" "/nix/store/.../bin/.runsc-wrapped"  "$@"
                // or:    exec "/nix/store/.../bin/.runsc-wrapped"  "$@"
                for token in trimmed.split_whitespace() {
                    let unquoted = token.trim_matches('"');
                    if unquoted.starts_with('/') && unquoted.contains("runsc") {
                        let candidate = std::path::PathBuf::from(unquoted);
                        if candidate.exists() && candidate.is_file() {
                            debug!("Resolved Nix wrapper {:?} → {:?}", path, candidate);
                            return Some(candidate);
                        }
                    }
                }
            }
        }
        None
    }

    /// Execute using gVisor with an OCI bundle
    ///
    /// This is the OCI-compliant way to run containers with gVisor.
    /// The `network_mode` parameter controls gVisor's --network flag:
    /// - `GVisorNetworkMode::None` → `--network none` (fully isolated, original behavior)
    /// - `GVisorNetworkMode::Sandbox` → `--network sandbox` (gVisor user-space network stack)
    /// - `GVisorNetworkMode::Host` → `--network host` (share host network namespace)
    pub fn exec_with_oci_bundle(&self, container_id: &str, bundle: &OciBundle) -> Result<()> {
        self.exec_with_oci_bundle_network(
            container_id,
            bundle,
            GVisorNetworkMode::None,
            false,
            GVisorPlatform::Systrap,
        )
    }

    /// Execute using gVisor with an OCI bundle and explicit network mode.
    ///
    /// When `rootless` is true, the OCI spec is expected to carry explicit
    /// user namespace mappings. In that mode we do not pass runsc's CLI
    /// `--rootless` flag, because gVisor documents that flag as the
    /// `runsc do`-oriented path rather than the OCI `run` path. We still skip runsc's
    /// internal cgroup configuration because Nucleus already manages cgroups
    /// externally and unprivileged callers cannot configure them directly.
    pub fn exec_with_oci_bundle_network(
        &self,
        container_id: &str,
        bundle: &OciBundle,
        network_mode: GVisorNetworkMode,
        rootless: bool,
        platform: GVisorPlatform,
    ) -> Result<()> {
        info!(
            "Executing with gVisor using OCI bundle at {:?} (network: {:?}, platform: {:?})",
            bundle.bundle_path(),
            network_mode,
            platform,
        );

        let network_flag = match network_mode {
            GVisorNetworkMode::None => "none",
            GVisorNetworkMode::Sandbox => "sandbox",
            GVisorNetworkMode::Host => "host",
        };

        // Create a per-container root directory for runsc state.
        // By default runsc uses /var/run/runsc which requires root privileges.
        // We place it next to the OCI bundle so it is cleaned up together.
        let runsc_root = bundle
            .bundle_path()
            .parent()
            .unwrap_or(bundle.bundle_path())
            .join("runsc-root");
        std::fs::create_dir_all(&runsc_root).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create runsc root directory: {}", e))
        })?;
        std::fs::set_permissions(&runsc_root, std::fs::Permissions::from_mode(0o700)).map_err(
            |e| {
                NucleusError::GVisorError(format!(
                    "Failed to secure runsc root directory permissions: {}",
                    e
                ))
            },
        )?;

        let runsc_runtime_dir = runsc_root.join("runtime");
        std::fs::create_dir_all(&runsc_runtime_dir).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create runsc runtime directory: {}", e))
        })?;
        std::fs::set_permissions(&runsc_runtime_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| {
                NucleusError::GVisorError(format!(
                    "Failed to secure runsc runtime directory permissions: {}",
                    e
                ))
            })?;

        // Build runsc command with OCI bundle.
        // Global flags (--root, --network, --platform) must come BEFORE the subcommand.
        // runsc --root <dir> --network <mode> --platform <plat> run --bundle <path> <id>
        let mut args = vec![
            self.runsc_path.clone(),
            "--root".to_string(),
            runsc_root.to_string_lossy().to_string(),
        ];

        // Rootless OCI mode relies on user namespace mappings in config.json.
        // We intentionally do not pass runsc's CLI `--rootless` flag here.
        if rootless {
            args.push("--ignore-cgroups".to_string());
        }

        args.extend([
            "--network".to_string(),
            network_flag.to_string(),
            "--platform".to_string(),
            platform.as_flag().to_string(),
            "run".to_string(),
            "--bundle".to_string(),
            bundle.bundle_path().to_string_lossy().to_string(),
            container_id.to_string(),
        ]);

        debug!("runsc OCI args: {:?}", args);

        // Convert to CStrings for exec
        let program = CString::new(self.runsc_path.as_str())
            .map_err(|e| NucleusError::GVisorError(format!("Invalid runsc path: {}", e)))?;

        let c_args: Result<Vec<CString>> = args
            .iter()
            .map(|arg| {
                CString::new(arg.as_str())
                    .map_err(|e| NucleusError::GVisorError(format!("Invalid argument: {}", e)))
            })
            .collect();
        let c_args = c_args?;

        let c_env = self.exec_environment(&runsc_runtime_dir)?;

        // Defense-in-depth: even though gVisor provides its own sandboxing,
        // apply PR_SET_NO_NEW_PRIVS so the runsc process (and anything it
        // spawns) cannot gain privileges via setuid/setgid binaries.
        //
        // PR_SET_NO_NEW_PRIVS only affects the calling thread. Verify we are
        // single-threaded so no sibling thread can race to exec a setuid binary.
        let thread_count = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Threads:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|n| n.parse::<u32>().ok())
            });
        if thread_count != Some(1) {
            return Err(NucleusError::GVisorError(format!(
                "PR_SET_NO_NEW_PRIVS requires single-threaded process, found {:?} threads",
                thread_count
            )));
        }
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(NucleusError::GVisorError(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS before gVisor exec: {}",
                std::io::Error::last_os_error()
            )));
        }
        info!("PR_SET_NO_NEW_PRIVS applied before gVisor exec (defense-in-depth)");

        // execve - this replaces the current process with runsc
        nix::unistd::execve::<std::ffi::CString, std::ffi::CString>(&program, &c_args, &c_env)?;

        // Should never reach here
        Ok(())
    }

    /// Check if gVisor is available on this system
    pub fn is_available() -> bool {
        Self::find_runsc().is_ok()
    }

    /// Get runsc version
    pub fn version(&self) -> Result<String> {
        let output = Command::new(&self.runsc_path)
            .arg("--version")
            .output()
            .map_err(|e| NucleusError::GVisorError(format!("Failed to get version: {}", e)))?;

        if !output.status.success() {
            return Err(NucleusError::GVisorError(
                "Failed to get runsc version".to_string(),
            ));
        }

        let version = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(version.trim().to_string())
    }

    fn exec_environment(&self, runtime_dir: &Path) -> Result<Vec<CString>> {
        let mut env = Vec::new();
        let mut push = |key: &str, value: String| -> Result<()> {
            env.push(
                CString::new(format!("{}={}", key, value))
                    .map_err(|e| NucleusError::GVisorError(format!("Invalid {}: {}", key, e)))?,
            );
            Ok(())
        };

        // Use a hardcoded PATH for the runsc supervisor process to prevent
        // host PATH from leaking into the gVisor environment.
        push("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string())?;
        let runtime_dir = runtime_dir.to_string_lossy().to_string();
        push("TMPDIR", runtime_dir.clone())?;
        push("XDG_RUNTIME_DIR", runtime_dir)?;

        // Hardcode safe values instead of leaking host identity/paths.
        // HOME could point to an attacker-controlled directory; USER/LOGNAME
        // leak host identity information — none of which gVisor needs.
        push("HOME", "/root".to_string())?;
        push("USER", "root".to_string())?;
        push("LOGNAME", "root".to_string())?;

        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_gvisor_availability() {
        // This test just checks if we can determine availability
        // It may pass or fail depending on whether gVisor is installed
        let available = GVisorRuntime::is_available();
        println!("gVisor available: {}", available);
    }

    #[test]
    fn test_gvisor_new() {
        let runtime = GVisorRuntime::new();
        if let Ok(rt) = runtime {
            println!("Found runsc at: {}", rt.runsc_path);
            if let Ok(version) = rt.version() {
                println!("runsc version: {}", version);
            }
        }
    }

    #[test]
    fn test_find_runsc() {
        // Test that find_runsc either succeeds or returns appropriate error
        match GVisorRuntime::find_runsc() {
            Ok(path) => {
                println!("Found runsc at: {}", path);
                assert!(!path.is_empty());
            }
            Err(e) => {
                println!("runsc not found (expected if gVisor not installed): {}", e);
            }
        }
    }

    #[test]
    fn test_validate_runsc_rejects_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let fake_runsc = dir.path().join("runsc");
        std::fs::write(&fake_runsc, "#!/bin/sh\necho fake").unwrap();
        // Make world-writable
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o777)).unwrap();

        let result = GVisorRuntime::validate_runsc_path(&fake_runsc);
        assert!(
            result.is_err(),
            "validate_runsc_path must reject world-writable binaries"
        );
    }

    #[test]
    fn test_validate_runsc_rejects_group_writable() {
        let dir = tempfile::tempdir().unwrap();
        let fake_runsc = dir.path().join("runsc");
        std::fs::write(&fake_runsc, "#!/bin/sh\necho fake").unwrap();
        // Make group-writable
        std::fs::set_permissions(&fake_runsc, std::fs::Permissions::from_mode(0o775)).unwrap();

        let result = GVisorRuntime::validate_runsc_path(&fake_runsc);
        assert!(
            result.is_err(),
            "validate_runsc_path must reject group-writable binaries"
        );
    }

    #[test]
    fn test_runsc_owner_accepts_nix_store_artifact_owner() {
        // Use a real Nix store binary so the metadata/permission checks pass.
        // The /nix/store contents are read-only and content-addressed, so any
        // existing file with mode 555 works.
        let nix_binary = std::fs::read_dir("/nix/store")
            .ok()
            .and_then(|mut entries| {
                entries.find_map(|e| {
                    let dir = e.ok()?.path();
                    let candidate = dir.join("bin/runsc");
                    if candidate.exists() {
                        Some(candidate)
                    } else {
                        None
                    }
                })
            });

        let path = match nix_binary {
            Some(p) => p,
            None => {
                eprintln!("skipping: no runsc binary found in /nix/store");
                return;
            }
        };

        assert!(GVisorRuntime::is_trusted_runsc_owner(&path, 65534, 1000));
    }

    #[test]
    fn test_exec_environment_uses_hardcoded_path() {
        // The gVisor supervisor must NOT inherit the host PATH, to prevent
        // host filesystem layout leaking into the container environment.
        // Verify by setting a distinctive PATH and checking exec_environment
        // returns a hardcoded value instead.
        std::env::set_var("PATH", "/tmp/evil-inject/bin:/opt/attacker/sbin");
        let rt = GVisorRuntime::with_path("/fake/runsc".to_string());
        let tmp = tempfile::tempdir().unwrap();
        let env = rt.exec_environment(tmp.path()).unwrap();
        let path_entry = env.iter()
            .find(|e| e.to_str().is_ok_and(|s| s.starts_with("PATH=")))
            .expect("exec_environment must set PATH");
        let path_val = path_entry.to_str().unwrap();
        assert!(
            !path_val.contains("evil-inject") && !path_val.contains("attacker"),
            "exec_environment must use hardcoded PATH, not host PATH. Got: {}",
            path_val
        );
        assert_eq!(
            path_val,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "exec_environment PATH must be the standard hardcoded value"
        );
    }

    #[test]
    fn test_runsc_owner_rejects_untrusted_non_store_owner() {
        assert!(!GVisorRuntime::is_trusted_runsc_owner(
            Path::new("/tmp/runsc"),
            4242,
            1000
        ));
    }
}
