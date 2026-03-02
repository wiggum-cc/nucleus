use crate::error::{NucleusError, Result};
use crate::isolation::usermap::{UserNamespaceConfig, UserNamespaceMapper};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::sethostname;
use tracing::{debug, info};

/// Namespace configuration
///
/// Defines which Linux namespaces to create for isolation
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    /// PID namespace - process isolation
    pub pid: bool,
    /// Mount namespace - filesystem isolation
    pub mnt: bool,
    /// Network namespace - network isolation
    pub net: bool,
    /// UTS namespace - hostname isolation
    pub uts: bool,
    /// IPC namespace - inter-process communication isolation
    pub ipc: bool,
    /// User namespace - user/group ID isolation
    pub user: bool,
}

impl NamespaceConfig {
    /// Create config with all namespaces enabled
    pub fn all() -> Self {
        Self {
            pid: true,
            mnt: true,
            net: true,
            uts: true,
            ipc: true,
            user: false, // User namespace requires special setup
        }
    }

    /// Create config with minimal namespaces for isolation
    pub fn minimal() -> Self {
        Self {
            pid: true,
            mnt: true,
            net: true,
            uts: false,
            ipc: false,
            user: false,
        }
    }

    /// Convert to CloneFlags for unshare(2)
    fn to_clone_flags(&self) -> CloneFlags {
        let mut flags = CloneFlags::empty();

        if self.pid {
            flags |= CloneFlags::CLONE_NEWPID;
        }
        if self.mnt {
            flags |= CloneFlags::CLONE_NEWNS;
        }
        if self.net {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        if self.uts {
            flags |= CloneFlags::CLONE_NEWUTS;
        }
        if self.ipc {
            flags |= CloneFlags::CLONE_NEWIPC;
        }
        if self.user {
            flags |= CloneFlags::CLONE_NEWUSER;
        }

        flags
    }
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self::all()
    }
}

/// Namespace manager
///
/// Implements the namespace lifecycle state machine from
/// Nucleus_Isolation_NamespaceLifecycle.tla
pub struct NamespaceManager {
    config: NamespaceConfig,
    unshared: bool,
    user_mapper: Option<UserNamespaceMapper>,
}

impl NamespaceManager {
    pub fn new(config: NamespaceConfig) -> Self {
        Self {
            config,
            unshared: false,
            user_mapper: None,
        }
    }

    /// Create a new namespace manager with user namespace mapping
    pub fn with_user_mapping(mut self, user_config: UserNamespaceConfig) -> Self {
        self.user_mapper = Some(UserNamespaceMapper::new(user_config));
        self
    }

    /// Create namespaces via unshare(2)
    ///
    /// This implements the transition: uninitialized -> unshared
    /// in the namespace state machine
    pub fn unshare_namespaces(&mut self) -> Result<()> {
        if self.unshared {
            debug!("Namespaces already created, skipping");
            return Ok(());
        }

        info!("Creating namespaces: {:?}", self.config);

        let flags = self.config.to_clone_flags();

        unshare(flags).map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to unshare namespaces: {}", e))
        })?;

        // If user namespace is enabled and we have a mapper, setup UID/GID mappings
        // This must be done immediately after unshare(CLONE_NEWUSER)
        if self.config.user {
            if let Some(mapper) = &self.user_mapper {
                info!("Setting up user namespace UID/GID mappings");
                mapper.setup_mappings()?;
            } else {
                debug!("User namespace enabled but no mapper configured");
            }
        }

        self.unshared = true;
        info!("Successfully created namespaces");

        Ok(())
    }

    /// Check if namespaces have been created
    pub fn is_unshared(&self) -> bool {
        self.unshared
    }

    /// Get namespace configuration
    pub fn config(&self) -> &NamespaceConfig {
        &self.config
    }

    /// Set hostname in UTS namespace
    ///
    /// This only works if the UTS namespace is enabled in the config
    pub fn set_hostname(&self, hostname: &str) -> Result<()> {
        if !self.config.uts {
            debug!("UTS namespace not enabled, skipping hostname setting");
            return Ok(());
        }

        info!("Setting hostname to: {}", hostname);

        sethostname(hostname)
            .map_err(|e| NucleusError::NamespaceError(format!("Failed to set hostname: {}", e)))?;

        info!("Successfully set hostname to: {}", hostname);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_all() {
        let config = NamespaceConfig::all();
        assert!(config.pid);
        assert!(config.mnt);
        assert!(config.net);
        assert!(config.uts);
        assert!(config.ipc);
        assert!(!config.user); // User namespace disabled by default
    }

    #[test]
    fn test_namespace_config_minimal() {
        let config = NamespaceConfig::minimal();
        assert!(config.pid);
        assert!(config.mnt);
        assert!(config.net);
        assert!(!config.uts);
        assert!(!config.ipc);
        assert!(!config.user);
    }

    #[test]
    fn test_namespace_manager_initial_state() {
        let mgr = NamespaceManager::new(NamespaceConfig::minimal());
        assert!(!mgr.is_unshared());
    }

    // Note: Testing actual unshare requires root or user namespace setup
    // This is tested in integration tests
}
