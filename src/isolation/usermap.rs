use crate::error::{NucleusError, Result};
use std::fs;
use tracing::{debug, info};

/// UID/GID mapping configuration for user namespaces
///
/// Maps a range of UIDs/GIDs inside the container to a range outside
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapping {
    /// ID inside the container
    pub container_id: u32,
    /// ID outside the container (on the host)
    pub host_id: u32,
    /// Number of IDs to map
    pub count: u32,
}

impl IdMapping {
    /// Create a new ID mapping
    pub fn new(container_id: u32, host_id: u32, count: u32) -> Self {
        Self {
            container_id,
            host_id,
            count,
        }
    }

    /// Create a mapping for root inside container to current user outside
    pub fn rootless() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        Self::new(0, uid, 1)
    }

    /// Format as a line for uid_map/gid_map file
    fn format(&self) -> String {
        format!("{} {} {}\n", self.container_id, self.host_id, self.count)
    }
}

/// User namespace configuration
#[derive(Debug, Clone)]
pub struct UserNamespaceConfig {
    /// UID mappings
    pub uid_mappings: Vec<IdMapping>,
    /// GID mappings
    pub gid_mappings: Vec<IdMapping>,
}

impl UserNamespaceConfig {
    /// Create config for rootless mode
    ///
    /// Maps container root (UID/GID 0) to current user
    pub fn rootless() -> Self {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        Self {
            uid_mappings: vec![IdMapping::new(0, uid, 1)],
            gid_mappings: vec![IdMapping::new(0, gid, 1)],
        }
    }

    /// Create config with custom mappings
    pub fn custom(uid_mappings: Vec<IdMapping>, gid_mappings: Vec<IdMapping>) -> Self {
        Self {
            uid_mappings,
            gid_mappings,
        }
    }
}

/// User namespace mapper
///
/// Handles UID/GID mapping for rootless container execution
pub struct UserNamespaceMapper {
    config: UserNamespaceConfig,
}

impl UserNamespaceMapper {
    pub fn new(config: UserNamespaceConfig) -> Self {
        Self { config }
    }

    /// Setup UID/GID mappings for the current process
    ///
    /// This must be called after unshare(CLONE_NEWUSER) and before any other
    /// namespace operations
    pub fn setup_mappings(&self) -> Result<()> {
        info!("Setting up user namespace mappings");

        // Disable setgroups to allow GID mapping without CAP_SETGID
        self.write_setgroups_deny()?;

        // Write UID mappings
        self.write_uid_map()?;

        // Write GID mappings
        self.write_gid_map()?;

        info!("Successfully configured user namespace mappings");
        Ok(())
    }

    /// Write to /proc/self/setgroups to deny setgroups(2)
    ///
    /// This is required for unprivileged user namespace mapping
    fn write_setgroups_deny(&self) -> Result<()> {
        let path = "/proc/self/setgroups";
        debug!("Writing 'deny' to {}", path);

        fs::write(path, "deny\n").map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write to {}: {}", path, e))
        })?;

        Ok(())
    }

    /// Write UID mappings to /proc/self/uid_map
    fn write_uid_map(&self) -> Result<()> {
        let path = "/proc/self/uid_map";
        let mut content = String::new();

        for mapping in &self.config.uid_mappings {
            content.push_str(&mapping.format());
        }

        debug!("Writing UID mappings to {}: {}", path, content.trim());

        fs::write(path, &content).map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write UID mappings: {}", e))
        })?;

        Ok(())
    }

    /// Write GID mappings to /proc/self/gid_map
    fn write_gid_map(&self) -> Result<()> {
        let path = "/proc/self/gid_map";
        let mut content = String::new();

        for mapping in &self.config.gid_mappings {
            content.push_str(&mapping.format());
        }

        debug!("Writing GID mappings to {}: {}", path, content.trim());

        fs::write(path, &content).map_err(|e| {
            NucleusError::NamespaceError(format!("Failed to write GID mappings: {}", e))
        })?;

        Ok(())
    }

    /// Get the user namespace configuration
    pub fn config(&self) -> &UserNamespaceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_mapping_format() {
        let mapping = IdMapping::new(0, 1000, 1);
        assert_eq!(mapping.format(), "0 1000 1\n");

        let mapping = IdMapping::new(1000, 2000, 100);
        assert_eq!(mapping.format(), "1000 2000 100\n");
    }

    #[test]
    fn test_id_mapping_rootless() {
        let mapping = IdMapping::rootless();
        assert_eq!(mapping.container_id, 0);
        assert_eq!(mapping.count, 1);
        // host_id will be the current UID
    }

    #[test]
    fn test_user_namespace_config_rootless() {
        let config = UserNamespaceConfig::rootless();
        assert_eq!(config.uid_mappings.len(), 1);
        assert_eq!(config.gid_mappings.len(), 1);
        assert_eq!(config.uid_mappings[0].container_id, 0);
        assert_eq!(config.gid_mappings[0].container_id, 0);
    }

    #[test]
    fn test_user_namespace_config_custom() {
        let uid_mappings = vec![IdMapping::new(0, 1000, 1), IdMapping::new(1000, 2000, 100)];
        let gid_mappings = vec![IdMapping::new(0, 1000, 1)];

        let config = UserNamespaceConfig::custom(uid_mappings.clone(), gid_mappings.clone());
        assert_eq!(config.uid_mappings, uid_mappings);
        assert_eq!(config.gid_mappings, gid_mappings);
    }

    // Note: Testing actual mapping setup requires user namespace creation
    // This is tested in integration tests
}
