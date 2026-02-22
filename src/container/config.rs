use crate::isolation::NamespaceConfig;
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

    /// Whether to use gVisor runtime
    pub use_gvisor: bool,
}

impl ContainerConfig {
    pub fn new(name: String, command: Vec<String>) -> Self {
        Self {
            name,
            command,
            context_dir: None,
            limits: ResourceLimits::default(),
            namespaces: NamespaceConfig::default(),
            use_gvisor: false,
        }
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

    pub fn with_gvisor(mut self, enabled: bool) -> Self {
        self.use_gvisor = enabled;
        self
    }
}
