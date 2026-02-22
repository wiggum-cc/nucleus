use crate::isolation::{NamespaceConfig, UserNamespaceConfig};
use crate::resources::ResourceLimits;
use std::path::PathBuf;

/// Container configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Container name/ID
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
}

impl ContainerConfig {
    pub fn new(name: String, command: Vec<String>) -> Self {
        Self {
            name: name.clone(),
            command,
            context_dir: None,
            limits: ResourceLimits::default(),
            namespaces: NamespaceConfig::default(),
            user_ns_config: None,
            hostname: Some(name), // Default hostname to container name
            use_gvisor: false,
            use_oci_bundle: false,
        }
    }

    /// Enable rootless mode with user namespace mapping
    ///
    /// This enables the user namespace and configures UID/GID mapping
    /// to map container root (UID/GID 0) to the current user
    pub fn with_rootless(mut self) -> Self {
        // Enable user namespace
        self.namespaces.user = true;
        // Configure UID/GID mapping for rootless mode
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
        self.use_gvisor = true; // OCI bundle requires gVisor
        self
    }
}
