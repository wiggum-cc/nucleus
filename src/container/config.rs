use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::resources::ResourceLimits;
use std::path::PathBuf;
use std::time::SystemTime;

/// Generate a unique 12-hex-char container ID from timestamp and PID
pub fn generate_container_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    format!("{:012x}", (nanos ^ pid) & 0xFFFF_FFFF_FFFF)
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

    /// Whether to use OCI bundle format (for gVisor)
    pub use_oci_bundle: bool,

    /// Network mode
    pub network: crate::network::NetworkMode,

    /// Context mode (copy or bind mount)
    pub context_mode: crate::filesystem::ContextMode,
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
            use_oci_bundle: false,
            network: crate::network::NetworkMode::None,
            context_mode: crate::filesystem::ContextMode::Copy,
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

    /// Enable OCI bundle format (automatically enables gVisor)
    pub fn with_oci_bundle(mut self) -> Self {
        self.use_oci_bundle = true;
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
}
