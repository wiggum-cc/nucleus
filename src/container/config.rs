use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::resources::ResourceLimits;
use std::path::PathBuf;
use std::time::SystemTime;

/// Generate a unique 12-hex-char container ID using /dev/urandom
pub fn generate_container_id() -> String {
    use std::io::Read;

    let mut buf = [0u8; 6];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf).map(|_| ())) {
        Ok(()) => {}
        Err(_) => {
            // Fallback to timestamp-based if /dev/urandom unavailable
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            buf.copy_from_slice(&nanos.to_le_bytes()[..6]);
        }
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

/// Trust level for a container workload.
///
/// Determines the minimum isolation guarantees the runtime must enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Native kernel isolation (namespaces + seccomp + Landlock) is acceptable.
    Trusted,
    /// Requires gVisor; refuses to start without it unless degraded mode is allowed.
    Untrusted,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Untrusted
    }
}

/// Container configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Unique container ID (auto-generated 12 hex chars)
    pub id: String,

    /// User-supplied container name (optional, defaults to ID)
    pub name: String,

    /// Command to execute in the container
    pub command: Vec<String>,

    /// Context directory to pre-populate (optional)
    pub context_dir: Option<PathBuf>,

    /// Resource limits
    pub limits: ResourceLimits,

    /// Namespace configuration
    pub namespaces: NamespaceConfig,

    /// User namespace configuration (for rootless mode)
    pub user_ns_config: Option<UserNamespaceConfig>,

    /// Hostname to set in UTS namespace (optional)
    pub hostname: Option<String>,

    /// Whether to use gVisor runtime
    pub use_gvisor: bool,

    /// Trust level for this workload
    pub trust_level: TrustLevel,

    /// Network mode
    pub network: crate::network::NetworkMode,

    /// Context mode (copy or bind mount)
    pub context_mode: crate::filesystem::ContextMode,

    /// Allow degraded security behavior if a hardening layer cannot be applied
    pub allow_degraded_security: bool,

    /// Allow chroot fallback when pivot_root fails (weaker isolation)
    pub allow_chroot_fallback: bool,

    /// Require explicit opt-in for host networking
    pub allow_host_network: bool,

    /// Mount /proc read-only inside the container
    pub proc_readonly: bool,
}

impl ContainerConfig {
    pub fn new(name: Option<String>, command: Vec<String>) -> Self {
        let id = generate_container_id();
        let name = name.unwrap_or_else(|| id.clone());
        Self {
            id,
            name: name.clone(),
            command,
            context_dir: None,
            limits: ResourceLimits::default(),
            namespaces: NamespaceConfig::default(),
            user_ns_config: None,
            hostname: Some(name),
            use_gvisor: false,
            trust_level: TrustLevel::default(),
            network: crate::network::NetworkMode::None,
            context_mode: crate::filesystem::ContextMode::Copy,
            allow_degraded_security: false,
            allow_chroot_fallback: false,
            allow_host_network: false,
            proc_readonly: true,
        }
    }

    /// Enable rootless mode with user namespace mapping
    pub fn with_rootless(mut self) -> Self {
        self.namespaces.user = true;
        self.user_ns_config = Some(UserNamespaceConfig::rootless());
        self
    }

    /// Configure custom user namespace mapping
    pub fn with_user_namespace(mut self, config: UserNamespaceConfig) -> Self {
        self.namespaces.user = true;
        self.user_ns_config = Some(config);
        self
    }

    pub fn with_context(mut self, dir: PathBuf) -> Self {
        self.context_dir = Some(dir);
        self
    }

    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_namespaces(mut self, namespaces: NamespaceConfig) -> Self {
        self.namespaces = namespaces;
        self
    }

    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }

    pub fn with_gvisor(mut self, enabled: bool) -> Self {
        self.use_gvisor = enabled;
        self
    }

    pub fn with_trust_level(mut self, level: TrustLevel) -> Self {
        self.trust_level = level;
        self
    }

    /// Enable OCI bundle runtime path (always OCI for gVisor).
    pub fn with_oci_bundle(mut self) -> Self {
        self.use_gvisor = true;
        self
    }

    pub fn with_network(mut self, mode: crate::network::NetworkMode) -> Self {
        self.network = mode;
        self
    }

    pub fn with_context_mode(mut self, mode: crate::filesystem::ContextMode) -> Self {
        self.context_mode = mode;
        self
    }

    pub fn with_allow_degraded_security(mut self, allow: bool) -> Self {
        self.allow_degraded_security = allow;
        self
    }

    pub fn with_allow_chroot_fallback(mut self, allow: bool) -> Self {
        self.allow_chroot_fallback = allow;
        self
    }

    pub fn with_allow_host_network(mut self, allow: bool) -> Self {
        self.allow_host_network = allow;
        self
    }

    pub fn with_proc_readonly(mut self, proc_readonly: bool) -> Self {
        self.proc_readonly = proc_readonly;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkMode;

    #[test]
    fn test_config_security_defaults_are_hardened() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(!cfg.allow_degraded_security);
        assert!(!cfg.allow_chroot_fallback);
        assert!(!cfg.allow_host_network);
        assert!(cfg.proc_readonly);
    }

    #[test]
    fn test_config_security_builders_override_defaults() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_allow_degraded_security(true)
            .with_allow_chroot_fallback(true)
            .with_allow_host_network(true)
            .with_proc_readonly(false)
            .with_network(NetworkMode::Host);

        assert!(cfg.allow_degraded_security);
        assert!(cfg.allow_chroot_fallback);
        assert!(cfg.allow_host_network);
        assert!(!cfg.proc_readonly);
        assert!(matches!(cfg.network, NetworkMode::Host));
    }
}
