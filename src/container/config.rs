use crate::filesystem::normalize_container_destination;
use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::network::EgressPolicy;
use crate::resources::ResourceLimits;
use crate::security::GVisorPlatform;
use std::path::PathBuf;
use std::time::Duration;

/// Generate a unique 32-hex-char container ID (128-bit) using /dev/urandom.
pub fn generate_container_id() -> crate::error::Result<String> {
    use std::io::Read;

    let mut buf = [0u8; 16];
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| {
        crate::error::NucleusError::ConfigError(format!(
            "Failed to open /dev/urandom for container ID generation: {}",
            e
        ))
    })?;
    file.read_exact(&mut buf).map_err(|e| {
        crate::error::NucleusError::ConfigError(format!(
            "Failed to read secure random bytes for container ID generation: {}",
            e
        ))
    })?;
    Ok(hex::encode(buf))
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

/// Required host kernel lockdown mode, when asserted by the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelLockdownMode {
    /// Integrity mode blocks kernel writes from privileged userspace.
    Integrity,
    /// Confidentiality mode additionally blocks kernel data disclosure paths.
    Confidentiality,
}

impl KernelLockdownMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Confidentiality => "confidentiality",
        }
    }

    pub fn accepts(self, active: Self) -> bool {
        match self {
            Self::Integrity => matches!(active, Self::Integrity | Self::Confidentiality),
            Self::Confidentiality => matches!(active, Self::Confidentiality),
        }
    }
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
    /// Unique container ID (auto-generated 32 hex chars, 128-bit)
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

    /// Desired topology config hash for reconciliation change detection.
    pub config_hash: Option<u64>,

    /// Enable sd_notify integration (pass NOTIFY_SOCKET into container).
    pub sd_notify: bool,

    /// Require the host kernel to be in at least this lockdown mode.
    pub required_kernel_lockdown: Option<KernelLockdownMode>,

    /// Verify context contents before executing the workload.
    pub verify_context_integrity: bool,

    /// Verify rootfs attestation manifest before mounting it.
    pub verify_rootfs_attestation: bool,

    /// Request kernel logging for denied seccomp decisions when supported.
    pub seccomp_log_denied: bool,

    /// Select the gVisor platform backend.
    pub gvisor_platform: GVisorPlatform,

    /// Path to a per-service seccomp profile (JSON, OCI subset format).
    /// When set, this profile is used instead of the built-in allowlist.
    pub seccomp_profile: Option<PathBuf>,

    /// Expected SHA-256 hash of the seccomp profile file for integrity verification.
    pub seccomp_profile_sha256: Option<String>,

    /// Seccomp operating mode.
    pub seccomp_mode: SeccompMode,

    /// Path to write seccomp trace log (NDJSON) when seccomp_mode == Trace.
    pub seccomp_trace_log: Option<PathBuf>,

    /// Path to capability policy file (TOML).
    pub caps_policy: Option<PathBuf>,

    /// Expected SHA-256 hash of the capability policy file.
    pub caps_policy_sha256: Option<String>,

    /// Path to Landlock policy file (TOML).
    pub landlock_policy: Option<PathBuf>,

    /// Expected SHA-256 hash of the Landlock policy file.
    pub landlock_policy_sha256: Option<String>,

    /// OCI lifecycle hooks to execute at various container lifecycle points.
    pub hooks: Option<crate::security::OciHooks>,

    /// Path to write the container PID (OCI --pid-file).
    pub pid_file: Option<PathBuf>,

    /// Path to AF_UNIX socket for console pseudo-terminal master (OCI --console-socket).
    pub console_socket: Option<PathBuf>,

    /// Override OCI bundle directory path (OCI --bundle).
    pub bundle_dir: Option<PathBuf>,
}

/// Seccomp operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// Normal enforcement — deny unlisted syscalls.
    #[default]
    Enforce,
    /// Trace mode — allow all syscalls but log them for profile generation.
    /// Development only; rejected in production mode.
    Trace,
}

impl ContainerConfig {
    pub fn new(name: Option<String>, command: Vec<String>) -> Self {
        Self::try_new(name, command).expect("secure container ID generation failed")
    }

    pub fn try_new(name: Option<String>, command: Vec<String>) -> crate::error::Result<Self> {
        let id = generate_container_id()?;
        let name = name.unwrap_or_else(|| id.clone());
        Ok(Self {
            id,
            name: name.clone(),
            command,
            context_dir: None,
            limits: ResourceLimits::default(),
            namespaces: NamespaceConfig::default(),
            user_ns_config: None,
            hostname: Some(name),
            use_gvisor: true,
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
            config_hash: None,
            sd_notify: false,
            required_kernel_lockdown: None,
            verify_context_integrity: false,
            verify_rootfs_attestation: false,
            seccomp_log_denied: false,
            gvisor_platform: GVisorPlatform::default(),
            seccomp_profile: None,
            seccomp_profile_sha256: None,
            seccomp_mode: SeccompMode::default(),
            seccomp_trace_log: None,
            caps_policy: None,
            caps_policy_sha256: None,
            landlock_policy: None,
            landlock_policy_sha256: None,
            hooks: None,
            pid_file: None,
            console_socket: None,
            bundle_dir: None,
        })
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

    pub fn with_config_hash(mut self, hash: u64) -> Self {
        self.config_hash = Some(hash);
        self
    }

    pub fn with_sd_notify(mut self, enabled: bool) -> Self {
        self.sd_notify = enabled;
        self
    }

    pub fn with_required_kernel_lockdown(mut self, mode: KernelLockdownMode) -> Self {
        self.required_kernel_lockdown = Some(mode);
        self
    }

    pub fn with_verify_context_integrity(mut self, enabled: bool) -> Self {
        self.verify_context_integrity = enabled;
        self
    }

    pub fn with_verify_rootfs_attestation(mut self, enabled: bool) -> Self {
        self.verify_rootfs_attestation = enabled;
        self
    }

    pub fn with_seccomp_log_denied(mut self, enabled: bool) -> Self {
        self.seccomp_log_denied = enabled;
        self
    }

    pub fn with_gvisor_platform(mut self, platform: GVisorPlatform) -> Self {
        self.gvisor_platform = platform;
        self
    }

    pub fn with_seccomp_profile(mut self, path: PathBuf) -> Self {
        self.seccomp_profile = Some(path);
        self
    }

    pub fn with_seccomp_profile_sha256(mut self, hash: String) -> Self {
        self.seccomp_profile_sha256 = Some(hash);
        self
    }

    pub fn with_seccomp_mode(mut self, mode: SeccompMode) -> Self {
        self.seccomp_mode = mode;
        self
    }

    pub fn with_seccomp_trace_log(mut self, path: PathBuf) -> Self {
        self.seccomp_trace_log = Some(path);
        self
    }

    pub fn with_caps_policy(mut self, path: PathBuf) -> Self {
        self.caps_policy = Some(path);
        self
    }

    pub fn with_caps_policy_sha256(mut self, hash: String) -> Self {
        self.caps_policy_sha256 = Some(hash);
        self
    }

    pub fn with_landlock_policy(mut self, path: PathBuf) -> Self {
        self.landlock_policy = Some(path);
        self
    }

    pub fn with_landlock_policy_sha256(mut self, hash: String) -> Self {
        self.landlock_policy_sha256 = Some(hash);
        self
    }

    pub fn with_pid_file(mut self, path: PathBuf) -> Self {
        self.pid_file = Some(path);
        self
    }

    pub fn with_console_socket(mut self, path: PathBuf) -> Self {
        self.console_socket = Some(path);
        self
    }

    pub fn with_bundle_dir(mut self, path: PathBuf) -> Self {
        self.bundle_dir = Some(path);
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
        let Some(rootfs_path) = self.rootfs_path.as_ref() else {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires explicit --rootfs path (no host bind mounts)".to_string(),
            ));
        };

        if !rootfs_path.starts_with("/nix/store") {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires a /nix/store rootfs path".to_string(),
            ));
        }

        if self.seccomp_mode == SeccompMode::Trace {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode forbids --seccomp-mode trace".to_string(),
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

        if !self.verify_rootfs_attestation {
            return Err(crate::error::NucleusError::ConfigError(
                "Production mode requires --verify-rootfs-attestation".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate runtime-specific feature support.
    pub fn validate_runtime_support(&self) -> crate::error::Result<()> {
        if self.seccomp_mode == SeccompMode::Trace && self.seccomp_trace_log.is_none() {
            return Err(crate::error::NucleusError::ConfigError(
                "Seccomp trace mode requires --seccomp-log / seccomp_trace_log".to_string(),
            ));
        }

        for secret in &self.secrets {
            normalize_container_destination(&secret.dest)?;
        }

        if !self.use_gvisor {
            return Ok(());
        }

        if self.seccomp_mode == SeccompMode::Trace {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support --seccomp-mode trace; use --runtime native"
                    .to_string(),
            ));
        }

        if self.seccomp_profile.is_some() || self.seccomp_log_denied {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support custom seccomp profiles or seccomp deny logging; use --runtime native"
                    .to_string(),
            ));
        }

        if self.caps_policy.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support capability policy files; use --runtime native"
                    .to_string(),
            ));
        }

        if self.landlock_policy.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support Landlock policy files; use --runtime native"
                    .to_string(),
            ));
        }

        if self.health_check.is_some() {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support exec health checks; use --runtime native or remove --health-cmd"
                    .to_string(),
            ));
        }

        if matches!(
            self.readiness_probe.as_ref(),
            Some(ReadinessProbe::Exec { .. }) | Some(ReadinessProbe::TcpPort(_))
        ) {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime does not support exec/TCP readiness probes; use --runtime native or --readiness-sd-notify"
                    .to_string(),
            ));
        }

        if self.verify_context_integrity
            && self.context_dir.is_some()
            && matches!(self.context_mode, crate::filesystem::ContextMode::BindMount)
        {
            return Err(crate::error::NucleusError::ConfigError(
                "gVisor runtime cannot verify bind-mounted context integrity; use --context-mode copy or disable --verify-context-integrity"
                    .to_string(),
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
    fn test_generate_container_id_is_32_hex_chars() {
        let id = generate_container_id().unwrap();
        assert_eq!(id.len(), 32, "Container ID must be full 128-bit (32 hex chars), got {}", id.len());
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "Container ID must be hex: {}",
            id
        );
    }

    #[test]
    fn test_generate_container_id_is_unique() {
        let id1 = generate_container_id().unwrap();
        let id2 = generate_container_id().unwrap();
        assert_ne!(id1, id2, "Two consecutive IDs must differ");
    }

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
        assert!(cfg.required_kernel_lockdown.is_none());
        assert!(!cfg.verify_context_integrity);
        assert!(!cfg.verify_rootfs_attestation);
        assert!(!cfg.seccomp_log_denied);
        assert_eq!(cfg.gvisor_platform, GVisorPlatform::Systrap);
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
    fn test_production_mode_rejects_chroot_fallback() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_allow_chroot_fallback(true)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(
            err.to_string().contains("chroot"),
            "Production mode must reject chroot fallback"
        );
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
            .with_verify_rootfs_attestation(true)
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
    fn test_production_mode_requires_rootfs_attestation() {
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
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(err.to_string().contains("attestation"));
    }

    #[test]
    fn test_production_mode_rejects_seccomp_trace() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_service_mode(ServiceMode::Production)
            .with_rootfs_path(std::path::PathBuf::from("/nix/store/fake-rootfs"))
            .with_seccomp_mode(SeccompMode::Trace)
            .with_limits(
                crate::resources::ResourceLimits::default()
                    .with_memory("512M")
                    .unwrap()
                    .with_cpu_cores(2.0)
                    .unwrap(),
            );
        let err = cfg.validate_production_mode().unwrap_err();
        assert!(
            err.to_string().contains("trace"),
            "Production mode must reject seccomp trace mode"
        );
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

    #[test]
    fn test_hardening_builders_override_defaults() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_required_kernel_lockdown(KernelLockdownMode::Confidentiality)
            .with_verify_context_integrity(true)
            .with_verify_rootfs_attestation(true)
            .with_seccomp_log_denied(true)
            .with_gvisor_platform(GVisorPlatform::Kvm);

        assert_eq!(
            cfg.required_kernel_lockdown,
            Some(KernelLockdownMode::Confidentiality)
        );
        assert!(cfg.verify_context_integrity);
        assert!(cfg.verify_rootfs_attestation);
        assert!(cfg.seccomp_log_denied);
        assert_eq!(cfg.gvisor_platform, GVisorPlatform::Kvm);
    }

    #[test]
    fn test_seccomp_trace_requires_log_path() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_gvisor(false)
            .with_seccomp_mode(SeccompMode::Trace);

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("seccomp-log"));
    }

    #[test]
    fn test_gvisor_rejects_native_security_policy_files() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_seccomp_profile(PathBuf::from("/tmp/seccomp.json"))
            .with_caps_policy(PathBuf::from("/tmp/caps.toml"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("gVisor runtime"));
    }

    #[test]
    fn test_gvisor_rejects_landlock_policy_file() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_landlock_policy(PathBuf::from("/tmp/landlock.toml"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("Landlock"));
    }

    #[test]
    fn test_gvisor_rejects_trace_mode_even_with_log_path() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_seccomp_mode(SeccompMode::Trace)
            .with_seccomp_trace_log(PathBuf::from("/tmp/trace.ndjson"));

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("gVisor runtime"));
    }

    #[test]
    fn test_secret_dest_must_be_absolute() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]).with_secret(
            crate::container::SecretMount {
                source: PathBuf::from("/run/secrets/api-key"),
                dest: PathBuf::from("secrets/api-key"),
                mode: 0o400,
            },
        );

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn test_secret_dest_rejects_parent_traversal() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]).with_secret(
            crate::container::SecretMount {
                source: PathBuf::from("/run/secrets/api-key"),
                dest: PathBuf::from("/../../etc/passwd"),
                mode: 0o400,
            },
        );

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("parent traversal"));
    }

    #[test]
    fn test_gvisor_rejects_bind_mount_context_integrity_verification() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_context(PathBuf::from("/tmp/context"))
            .with_context_mode(crate::filesystem::ContextMode::BindMount)
            .with_verify_context_integrity(true);

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("context integrity"));
    }

    #[test]
    fn test_gvisor_rejects_exec_health_checks() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]).with_health_check(
            HealthCheck {
                command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                interval: Duration::from_secs(30),
                retries: 3,
                start_period: Duration::from_secs(1),
                timeout: Duration::from_secs(5),
            },
        );

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("health checks"));
    }

    #[test]
    fn test_gvisor_rejects_exec_readiness_probes() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]).with_readiness_probe(
            ReadinessProbe::Exec {
                command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
            },
        );

        let err = cfg.validate_runtime_support().unwrap_err();
        assert!(err.to_string().contains("readiness"));
    }

    #[test]
    fn test_gvisor_allows_copy_mode_context_integrity_verification() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_context(PathBuf::from("/tmp/context"))
            .with_context_mode(crate::filesystem::ContextMode::Copy)
            .with_verify_context_integrity(true);

        assert!(cfg.validate_runtime_support().is_ok());
    }

    #[test]
    fn test_native_runtime_disables_gvisor() {
        // --runtime native must explicitly disable gVisor and set Trusted trust level
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()])
            .with_gvisor(false)
            .with_trust_level(TrustLevel::Trusted);
        assert!(!cfg.use_gvisor, "native runtime must disable gVisor");
        assert_eq!(cfg.trust_level, TrustLevel::Trusted, "native runtime must set Trusted trust level");
    }

    #[test]
    fn test_default_config_has_gvisor_enabled() {
        let cfg = ContainerConfig::new(None, vec!["/bin/sh".to_string()]);
        assert!(cfg.use_gvisor, "default must have gVisor enabled");
        assert_eq!(cfg.trust_level, TrustLevel::Untrusted, "default must be Untrusted");
    }

    #[test]
    fn test_generate_container_id_returns_result() {
        // BUG-07: generate_container_id must return Result, not panic.
        // Verify by calling it and checking the Ok value is valid hex.
        let id: crate::error::Result<String> = generate_container_id();
        let id = id.expect("generate_container_id must return Ok, not panic");
        assert_eq!(id.len(), 32, "container ID must be 32 hex chars");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit()),
            "container ID must be valid hex: {}",
            id
        );
    }
}
