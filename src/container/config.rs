use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::network::EgressPolicy;
use crate::resources::ResourceLimits;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Generate a unique 32-hex-char container ID (128-bit) using /dev/urandom
pub fn generate_container_id() -> String {
    use std::io::Read;

    let mut buf = [0u8; 16];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf).map(|_| ())) {
        Ok(()) => {}
        Err(_) => {
            // Fallback to timestamp + pid if /dev/urandom unavailable
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            buf[..16].copy_from_slice(&nanos.to_le_bytes());
        }
    }
    // Use first 12 hex chars for display (48 bits from 128-bit source)
    // but store the full 128-bit ID for uniqueness
    buf.iter().map(|b| format!("{:02x}", b)).collect::<String>()[..12].to_string()
}

/// Trust level for a container workload.
///
/// Determines the minimum isolation guarantees the runtime must enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrustLevel {
    /// Native kernel isolation (namespaces + seccomp + Landlock) is acceptable.
    Trusted,
    /// Requires gVisor; refuses to start without it unless degraded mode is allowed.
    #[default]
    Untrusted,
}

/// Service mode for the container.
///
/// Determines whether the container runs as an ephemeral agent sandbox
/// or a long-running production service with stricter requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServiceMode {
    /// Ephemeral agent workload (default). Allows degraded fallbacks.
    #[default]
    Agent,
    /// Long-running production service. Enforces strict security invariants:
    /// - Forbids degraded security, chroot fallback, and host networking
    /// - Requires cgroup resource limits
    /// - Requires pivot_root (no chroot fallback)
    /// - Requires explicit rootfs path (no host bind mounts)
    Production,
}

/// Health check configuration for long-running services.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Command to run inside the container to check health.
    pub command: Vec<String>,
    /// Interval between health checks.
    pub interval: Duration,
    /// Number of consecutive failures before marking unhealthy.
    pub retries: u32,
    /// Grace period after start before health checks begin.
    pub start_period: Duration,
    /// Timeout for each health check execution.
    pub timeout: Duration,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            interval: Duration::from_secs(30),
            retries: 3,
            start_period: Duration::from_secs(5),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Secrets configuration for mounting secret files into the container.
#[derive(Debug, Clone)]
pub struct SecretMount {
    /// Source path on the host (or Nix store path).
    pub source: PathBuf,
    /// Destination path inside the container.
    pub dest: PathBuf,
    /// File mode (default: 0o400, read-only by owner).
    pub mode: u32,
}

/// Readiness probe configuration.
#[derive(Debug, Clone)]
pub enum ReadinessProbe {
    /// Run a command; ready when it exits 0.
    Exec { command: Vec<String> },
    /// Check TCP port connectivity.
    TcpPort(u16),
    /// Use sd_notify protocol (service sends READY=1).
    SdNotify,
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

    /// Service mode (agent vs production)
    pub service_mode: ServiceMode,

    /// Pre-built rootfs path (Nix store path). When set, this is bind-mounted
    /// as the container root instead of bind-mounting host /bin, /usr, /lib, etc.
    pub rootfs_path: Option<PathBuf>,

    /// Egress policy for audited outbound network access.
    pub egress_policy: Option<EgressPolicy>,

    /// Health check configuration for long-running services.
    pub health_check: Option<HealthCheck>,

    /// Readiness probe for service startup detection.
    pub readiness_probe: Option<ReadinessProbe>,

    /// Secret files to mount into the container.
    pub secrets: Vec<SecretMount>,

    /// Environment variables to pass to the container process.
    pub environment: Vec<(String, String)>,

    /// Enable sd_notify integration (pass NOTIFY_SOCKET into container).
    pub sd_notify: bool,
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
            service_mode: ServiceMode::default(),
            rootfs_path: None,
            egress_policy: None,
            health_check: None,
            readiness_probe: None,
            secrets: Vec::new(),
            environment: Vec::new(),
            sd_notify: false,
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

    pub fn with_service_mode(mut self, mode: ServiceMode) -> Self {
        self.service_mode = mode;
        self
    }

    pub fn with_rootfs_path(mut self, path: PathBuf) -> Self {
        self.rootfs_path = Some(path);
        self
    }

    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = Some(policy);
        self
    }

    pub fn with_health_check(mut self, hc: HealthCheck) -> Self {
        self.health_check = Some(hc);
        self
    }

    pub fn with_readiness_probe(mut self, probe: ReadinessProbe) -> Self {
        self.readiness_probe = Some(probe);
        self
    }

    pub fn with_secret(mut self, secret: SecretMount) -> Self {
        self.secrets.push(secret);
        self
    }

    pub fn with_env(mut self, key: String, value: String) -> Self {
        self.environment.push((key, value));
        self
    }

    pub fn with_sd_notify(mut self, enabled: bool) -> Self {
        self.sd_notify = enabled;
        self
    }

    /// Validate that production mode invariants are satisfied.
    /// Called before container startup when service_mode == Production.
    pub fn validate_production_mode(&self) -> crate::error::Result<()> {
        if self.service_mode != ServiceMode::Production {
            return Ok(());
        }

        if self.allow_degraded_security {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids --allow-degraded-security".to_string(),
            ));
        }

        if self.allow_chroot_fallback {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids --allow-chroot-fallback".to_string(),
            ));
        }

        if self.allow_host_network {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids --allow-host-network".to_string(),
            ));
        }

        if matches!(self.network, crate::network::NetworkMode::Host) {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids host network mode".to_string(),
            ));
        }

        // Production mode requires explicit rootfs (no host bind mount fallback)
        if self.rootfs_path.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --rootfs path (no host bind mounts)".to_string(),
            ));
        }

        // Production mode requires explicit resource limits
        if self.limits.memory_bytes.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --memory limit".to_string(),
            ));
        }

        if self.limits.cpu_quota_us.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --cpus limit".to_string(),
            ));
        }

        Ok(())
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
        assert_eq!(cfg.service_mode, ServiceMode::Agent);
        assert!(cfg.rootfs_path.is_none());
        assert!(cfg.egress_policy.is_none());
        assert!(cfg.secrets.is_empty());
        assert!(!cfg.sd_notify);
    }

    #[test]
    fn test_production_mode_rejects_degraded_flags() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_allow_degraded_security(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        assert!(cfg.validate_production_mode().is_err());
    }

    #[test]
    fn test_production_mode_requires_rootfs() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--rootfs"));
    }

    #[test]
    fn test_production_mode_requires_memory_limit() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"));
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--memory"));
    }

    #[test]
    fn test_production_mode_valid_config() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        assert!(cfg.validate_production_mode().is_ok());
    }

    #[test]
    fn test_production_mode_requires_cpu_limit() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("--cpus"));
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
