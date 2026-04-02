use crate::error::{NucleusError, Result};
use crate::security::OciBundle;
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

        Ok(Some(resolved.to_string_lossy().to_string()))
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
        self.exec_with_oci_bundle_network(container_id, bundle, GVisorNetworkMode::None, false)
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
    ) -> Result<()> {
        info!(
            "Executing with gVisor using OCI bundle at {:?} (network: {:?})",
            bundle.bundle_path(),
            network_mode,
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
            .join(format!("runsc-root-{}", container_id));
        std::fs::create_dir_all(&runsc_root).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create runsc root directory: {}", e))
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
            "systrap".to_string(), // Use systrap platform (works without KVM)
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

        let c_env = self.exec_environment()?;

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

    fn exec_environment(&self) -> Result<Vec<CString>> {
        let mut env = Vec::new();
        let mut push = |key: &str, value: String| -> Result<()> {
            env.push(
                CString::new(format!("{}={}", key, value))
                    .map_err(|e| NucleusError::GVisorError(format!("Invalid {}: {}", key, e)))?,
            );
            Ok(())
        };

        let path = std::env::var("PATH").unwrap_or_else(|_| {
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()
        });
        push("PATH", path)?;

        for key in ["HOME", "TMPDIR", "XDG_RUNTIME_DIR", "USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(key) {
                push(key, value)?;
            }
        }

        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gvisor_availability() {
        // This test just checks if we can determine availability
        // It may pass or fail depending on whether gVisor is installed
        let available = GVisorRuntime::is_available();
        println!("gVisor available: {}", available);
    }

    #[test]
    #[ignore] // Only run if gVisor is installed
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
}
