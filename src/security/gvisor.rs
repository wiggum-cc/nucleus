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
        let metadata = std::fs::metadata(&canonical).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to stat runsc path {:?}: {}", canonical, e))
        })?;

        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::GVisorError(format!(
                "Refusing insecure runsc binary permissions at {:?} (mode {:o})",
                canonical, mode
            )));
        }
        if mode & 0o111 == 0 {
            return Ok(None);
        }

        Ok(Some(canonical.to_string_lossy().to_string()))
    }

    /// Execute using gVisor with an OCI bundle
    ///
    /// This is the OCI-compliant way to run containers with gVisor.
    /// The `network_mode` parameter controls gVisor's --network flag:
    /// - `GVisorNetworkMode::None` → `--network none` (fully isolated, original behavior)
    /// - `GVisorNetworkMode::Sandbox` → `--network sandbox` (gVisor user-space network stack)
    /// - `GVisorNetworkMode::Host` → `--network host` (share host network namespace)
    pub fn exec_with_oci_bundle(
        &self,
        container_id: &str,
        bundle: &OciBundle,
    ) -> Result<()> {
        self.exec_with_oci_bundle_network(container_id, bundle, GVisorNetworkMode::None)
    }

    /// Execute using gVisor with an OCI bundle and explicit network mode.
    pub fn exec_with_oci_bundle_network(
        &self,
        container_id: &str,
        bundle: &OciBundle,
        network_mode: GVisorNetworkMode,
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

        // Build runsc run command with OCI bundle
        // runsc run --bundle <bundle-path> <container-id>
        let args = vec![
            self.runsc_path.clone(),
            "run".to_string(),
            "--bundle".to_string(),
            bundle.bundle_path().to_string_lossy().to_string(),
            "--network".to_string(),
            network_flag.to_string(),
            "--platform".to_string(),
            "ptrace".to_string(), // Use ptrace platform (works without KVM)
            container_id.to_string(),
        ];

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

        // execve - this replaces the current process with runsc
        nix::unistd::execve::<std::ffi::CString, std::ffi::CString>(&program, &c_args, &[])?;

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
