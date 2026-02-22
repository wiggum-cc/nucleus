use crate::error::{NucleusError, Result};
use crate::resources::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// OCI Runtime Specification configuration
///
/// This implements a subset of the OCI runtime spec for gVisor compatibility
/// Spec: https://github.com/opencontainers/runtime-spec/blob/main/config.md
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciConfig {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,

    pub root: OciRoot,
    pub process: OciProcess,
    pub hostname: Option<String>,
    pub mounts: Vec<OciMount>,
    pub linux: Option<OciLinux>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Option<OciCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_gids: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCapabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    pub source: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciLinux {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<OciNamespace>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciResources>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub namespace_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<OciMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<OciCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<OciPids>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciPids {
    pub limit: i64,
}

impl OciConfig {
    /// Create a minimal OCI config for Nucleus containers
    pub fn new(command: Vec<String>, hostname: Option<String>) -> Self {
        Self {
            oci_version: "1.0.2".to_string(),
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: false,
            },
            process: OciProcess {
                terminal: false,
                user: OciUser {
                    uid: 0,
                    gid: 0,
                    additional_gids: None,
                },
                args: command,
                env: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                        .to_string(),
                ],
                cwd: "/".to_string(),
                capabilities: Some(OciCapabilities {
                    bounding: vec![],
                    effective: vec![],
                    inheritable: vec![],
                    permitted: vec![],
                    ambient: vec![],
                }),
            },
            hostname,
            mounts: vec![
                OciMount {
                    destination: "/proc".to_string(),
                    source: "proc".to_string(),
                    mount_type: "proc".to_string(),
                    options: vec!["nosuid".to_string(), "noexec".to_string(), "nodev".to_string()],
                },
                OciMount {
                    destination: "/dev".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                OciMount {
                    destination: "/sys".to_string(),
                    source: "sysfs".to_string(),
                    mount_type: "sysfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                        "ro".to_string(),
                    ],
                },
            ],
            linux: Some(OciLinux {
                namespaces: Some(vec![
                    OciNamespace {
                        namespace_type: "pid".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "network".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "ipc".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "uts".to_string(),
                    },
                    OciNamespace {
                        namespace_type: "mount".to_string(),
                    },
                ]),
                resources: None,
            }),
        }
    }

    /// Add resource limits to the config
    pub fn with_resources(mut self, limits: &ResourceLimits) -> Self {
        let mut resources = OciResources {
            memory: None,
            cpu: None,
            pids: None,
        };

        if let Some(memory_bytes) = limits.memory_bytes {
            resources.memory = Some(OciMemory {
                limit: Some(memory_bytes as i64),
            });
        }

        if let Some(quota_us) = limits.cpu_quota_us {
            resources.cpu = Some(OciCpu {
                quota: Some(quota_us as i64),
                period: Some(limits.cpu_period_us),
            });
        }

        if let Some(pids_max) = limits.pids_max {
            resources.pids = Some(OciPids {
                limit: pids_max as i64,
            });
        }

        if let Some(linux) = &mut self.linux {
            linux.resources = Some(resources);
        }

        self
    }

    /// Add user namespace configuration
    pub fn with_user_namespace(mut self) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.push(OciNamespace {
                    namespace_type: "user".to_string(),
                });
            }
        }
        self
    }
}

/// OCI Bundle manager
///
/// Creates and manages OCI-compliant bundles for gVisor
pub struct OciBundle {
    bundle_path: PathBuf,
    config: OciConfig,
}

impl OciBundle {
    /// Create a new OCI bundle
    pub fn new(bundle_path: PathBuf, config: OciConfig) -> Self {
        Self {
            bundle_path,
            config,
        }
    }

    /// Create the bundle directory structure and write config.json
    pub fn create(&self) -> Result<()> {
        info!("Creating OCI bundle at {:?}", self.bundle_path);

        // Create bundle directory
        fs::create_dir_all(&self.bundle_path).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to create bundle directory {:?}: {}",
                self.bundle_path, e
            ))
        })?;

        // Create rootfs directory
        let rootfs = self.bundle_path.join("rootfs");
        fs::create_dir_all(&rootfs).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create rootfs directory: {}", e))
        })?;

        // Write config.json
        let config_path = self.bundle_path.join("config.json");
        let config_json = serde_json::to_string_pretty(&self.config).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to serialize OCI config: {}", e))
        })?;

        fs::write(&config_path, config_json).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to write config.json: {}", e))
        })?;

        debug!("Created OCI bundle structure at {:?}", self.bundle_path);

        Ok(())
    }

    /// Get the rootfs path
    pub fn rootfs_path(&self) -> PathBuf {
        self.bundle_path.join("rootfs")
    }

    /// Get the bundle path
    pub fn bundle_path(&self) -> &Path {
        &self.bundle_path
    }

    /// Clean up the bundle
    pub fn cleanup(&self) -> Result<()> {
        if self.bundle_path.exists() {
            fs::remove_dir_all(&self.bundle_path).map_err(|e| {
                NucleusError::GVisorError(format!("Failed to cleanup bundle: {}", e))
            })?;
            debug!("Cleaned up OCI bundle at {:?}", self.bundle_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_oci_config_new() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()));

        assert_eq!(config.oci_version, "1.0.2");
        assert_eq!(config.root.path, "rootfs");
        assert_eq!(config.process.args, vec!["/bin/sh"]);
        assert_eq!(config.hostname, Some("test".to_string()));
    }

    #[test]
    fn test_oci_config_with_resources() {
        let limits = ResourceLimits::unlimited()
            .with_memory("512M")
            .unwrap()
            .with_cpu_cores(2.0)
            .unwrap();

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None).with_resources(&limits);

        assert!(config.linux.is_some());
        let linux = config.linux.unwrap();
        assert!(linux.resources.is_some());

        let resources = linux.resources.unwrap();
        assert!(resources.memory.is_some());
        assert!(resources.cpu.is_some());
    }

    #[test]
    fn test_oci_bundle_create() {
        let temp_dir = TempDir::new().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");

        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let bundle = OciBundle::new(bundle_path.clone(), config);

        bundle.create().unwrap();

        assert!(bundle_path.exists());
        assert!(bundle_path.join("rootfs").exists());
        assert!(bundle_path.join("config.json").exists());

        bundle.cleanup().unwrap();
        assert!(!bundle_path.exists());
    }

    #[test]
    fn test_oci_config_serialization() {
        let config = OciConfig::new(vec!["/bin/sh".to_string()], Some("test".to_string()));

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("ociVersion"));
        assert!(json.contains("1.0.2"));
        assert!(json.contains("/bin/sh"));

        // Test deserialization
        let deserialized: OciConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.oci_version, config.oci_version);
        assert_eq!(deserialized.process.args, config.process.args);
    }
}
