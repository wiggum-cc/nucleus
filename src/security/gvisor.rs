use crate::error::{NucleusError, Result};
use crate::security::OciBundle;
use std::ffi::CString;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

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
            if Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }

        // Try to find in PATH
        if let Ok(output) = Command::new("which").arg("runsc").output() {
            if output.status.success() {
                if let Ok(path) = String::from_utf8(output.stdout) {
                    let path = path.trim();
                    if !path.is_empty() {
                        return Ok(path.to_string());
                    }
                }
            }
        }

        Err(NucleusError::GVisorError(
            "runsc binary not found. Please install gVisor.".to_string(),
        ))
    }

    /// Execute a command using gVisor (runsc) - legacy non-OCI mode
    ///
    /// This implements the transition: native_kernel -> gvisor_kernel
    pub fn exec_with_gvisor(
        &self,
        container_id: &str,
        root_path: &Path,
        command: &[String],
    ) -> Result<()> {
        if command.is_empty() {
            return Err(NucleusError::GVisorError(
                "No command specified".to_string(),
            ));
        }

        info!(
            "Executing command with gVisor: {:?} (root: {:?})",
            command, root_path
        );

        // Build runsc run command
        // runsc run --root <root> --bundle <bundle> <container-id>
        let mut args = vec![
            "run".to_string(),
            "--root".to_string(),
            root_path.to_string_lossy().to_string(),
            "--network".to_string(),
            "none".to_string(),
            "--platform".to_string(),
            "ptrace".to_string(), // Use ptrace platform (works without KVM)
        ];

        // Add container ID
        args.push(container_id.to_string());

        debug!("runsc args: {:?}", args);

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

    /// Execute using gVisor with an OCI bundle
    ///
    /// This is the OCI-compliant way to run containers with gVisor
    pub fn exec_with_oci_bundle(&self, container_id: &str, bundle: &OciBundle) -> Result<()> {
        info!(
            "Executing with gVisor using OCI bundle at {:?}",
            bundle.bundle_path()
        );

        // Build runsc run command with OCI bundle
        // runsc run --bundle <bundle-path> <container-id>
        let args = vec![
            "run".to_string(),
            "--bundle".to_string(),
            bundle.bundle_path().to_string_lossy().to_string(),
            "--network".to_string(),
            "none".to_string(),
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
