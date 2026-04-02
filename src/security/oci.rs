use crate::filesystem::normalize_container_destination;
use crate::error::{NucleusError, Result};
use crate::isolation::{IdMapping, NamespaceConfig, UserNamespaceConfig};
use crate::resources::ResourceLimits;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
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
    #[serde(rename = "uidMappings", skip_serializing_if = "Vec::is_empty", default)]
    pub uid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "gidMappings", skip_serializing_if = "Vec::is_empty", default)]
    pub gid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "maskedPaths", skip_serializing_if = "Vec::is_empty", default)]
    pub masked_paths: Vec<String>,
    #[serde(
        rename = "readonlyPaths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub readonly_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub namespace_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OciIdMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
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
                readonly: true,
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
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                ],
                cwd: "/".to_string(),
                no_new_privileges: true,
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
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "nodev".to_string(),
                    ],
                },
                OciMount {
                    destination: "/dev".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "noexec".to_string(),
                        "strictatime".to_string(),
                        "mode=755".to_string(),
                        "size=65536k".to_string(),
                    ],
                },
                OciMount {
                    destination: "/tmp".to_string(),
                    source: "tmpfs".to_string(),
                    mount_type: "tmpfs".to_string(),
                    options: vec![
                        "nosuid".to_string(),
                        "nodev".to_string(),
                        "noexec".to_string(),
                        "mode=1777".to_string(),
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
                uid_mappings: vec![],
                gid_mappings: vec![],
                masked_paths: vec![
                    "/proc/acpi".to_string(),
                    "/proc/asound".to_string(),
                    "/proc/kcore".to_string(),
                    "/proc/keys".to_string(),
                    "/proc/latency_stats".to_string(),
                    "/proc/sched_debug".to_string(),
                    "/proc/scsi".to_string(),
                    "/proc/timer_list".to_string(),
                    "/proc/timer_stats".to_string(),
                    "/sys/firmware".to_string(),
                ],
                readonly_paths: vec![
                    "/proc/bus".to_string(),
                    "/proc/fs".to_string(),
                    "/proc/irq".to_string(),
                    "/proc/sys".to_string(),
                    "/proc/sysrq-trigger".to_string(),
                ],
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

    /// Add environment variables to the OCI process config.
    pub fn with_env(mut self, vars: &[(String, String)]) -> Self {
        for (key, value) in vars {
            self.process.env.push(format!("{}={}", key, value));
        }
        self
    }

    /// Add sd_notify socket passthrough.
    pub fn with_sd_notify(mut self) -> Self {
        if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
            self.process
                .env
                .push(format!("NOTIFY_SOCKET={}", notify_socket));
        }
        self
    }

    /// Add bind mounts for secrets.
    pub fn with_secret_mounts(mut self, secrets: &[crate::container::SecretMount]) -> Self {
        for secret in secrets {
            self.mounts.push(OciMount {
                destination: secret.dest.to_string_lossy().to_string(),
                source: secret.source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "noexec".to_string(),
                ],
            });
        }
        self
    }

    /// Add a read-only bind mount of an in-memory secret staging directory at
    /// `/run/secrets`, plus compatibility bind mounts for each staged secret to
    /// its requested container destination.
    pub fn with_inmemory_secret_mounts(
        mut self,
        stage_dir: &Path,
        secrets: &[crate::container::SecretMount],
    ) -> Result<Self> {
        self.mounts.push(OciMount {
            destination: "/run/secrets".to_string(),
            source: stage_dir.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options: vec![
                "bind".to_string(),
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
                "noexec".to_string(),
            ],
        });

        for secret in secrets {
            let dest = normalize_container_destination(&secret.dest)?;
            if !secret.source.starts_with(stage_dir) {
                return Err(NucleusError::ConfigError(format!(
                    "Staged secret source {:?} must live under {:?}",
                    secret.source, stage_dir
                )));
            }
            self.mounts.push(OciMount {
                destination: dest.to_string_lossy().to_string(),
                source: secret.source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                    "noexec".to_string(),
                ],
            });
        }

        Ok(self)
    }

    /// Bind mount the host context directory into the container.
    ///
    /// The gVisor integration path expects `/context` to be writable so test
    /// workloads can write results back to the host.
    pub fn with_context_bind(mut self, context_dir: &std::path::Path) -> Self {
        self.mounts.push(OciMount {
            destination: "/context".to_string(),
            source: context_dir.to_string_lossy().to_string(),
            mount_type: "bind".to_string(),
            options: vec![
                "bind".to_string(),
                "ro".to_string(),
                "nosuid".to_string(),
                "nodev".to_string(),
            ],
        });
        self
    }

    /// Add rootfs bind mounts from a pre-built rootfs path.
    pub fn with_rootfs_binds(mut self, rootfs_path: &std::path::Path) -> Self {
        let subdirs = ["bin", "sbin", "lib", "lib64", "usr", "etc", "nix"];
        for subdir in &subdirs {
            let source = rootfs_path.join(subdir);
            if source.exists() {
                self.mounts.push(OciMount {
                    destination: format!("/{}", subdir),
                    source: source.to_string_lossy().to_string(),
                    mount_type: "bind".to_string(),
                    options: vec![
                        "bind".to_string(),
                        "ro".to_string(),
                        "nosuid".to_string(),
                        "nodev".to_string(),
                    ],
                });
            }
        }
        self
    }

    /// Replace the default namespace list with an explicit configuration.
    pub fn with_namespace_config(mut self, config: &NamespaceConfig) -> Self {
        let mut namespaces = Vec::new();

        if config.pid {
            namespaces.push(OciNamespace {
                namespace_type: "pid".to_string(),
            });
        }
        if config.net {
            namespaces.push(OciNamespace {
                namespace_type: "network".to_string(),
            });
        }
        if config.ipc {
            namespaces.push(OciNamespace {
                namespace_type: "ipc".to_string(),
            });
        }
        if config.uts {
            namespaces.push(OciNamespace {
                namespace_type: "uts".to_string(),
            });
        }
        if config.mnt {
            namespaces.push(OciNamespace {
                namespace_type: "mount".to_string(),
            });
        }
        if config.cgroup {
            namespaces.push(OciNamespace {
                namespace_type: "cgroup".to_string(),
            });
        }
        if config.time {
            namespaces.push(OciNamespace {
                namespace_type: "time".to_string(),
            });
        }
        if config.user {
            namespaces.push(OciNamespace {
                namespace_type: "user".to_string(),
            });
        }

        if let Some(linux) = &mut self.linux {
            linux.namespaces = Some(namespaces);
        }

        self
    }

    /// Add read-only bind mounts for host runtime paths.
    ///
    /// This mirrors the native fallback path for non-production containers so
    /// common executables such as `/bin/sh` remain available inside the OCI
    /// rootfs when no explicit rootfs is configured.
    pub fn with_host_runtime_binds(mut self) -> Self {
        // Use a fixed set of standard FHS paths only. Do NOT scan host $PATH,
        // which would expose arbitrary host directories inside the container.
        let host_paths: BTreeSet<String> = [
            "/bin",
            "/sbin",
            "/usr",
            "/lib",
            "/lib64",
            "/nix/store",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        for host_path in host_paths {
            let source = Path::new(&host_path);
            if !source.exists() {
                continue;
            }

            self.mounts.push(OciMount {
                destination: host_path.clone(),
                source: source.to_string_lossy().to_string(),
                mount_type: "bind".to_string(),
                options: vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "nodev".to_string(),
                ],
            });
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

    /// Configure gVisor's true rootless OCI path.
    ///
    /// gVisor expects UID/GID mappings in the OCI spec for this mode, and its
    /// rootless OCI implementation does not currently support a network
    /// namespace entry in the spec. We still control networking through
    /// runsc's top-level `--network` flag.
    pub fn with_rootless_user_namespace(mut self, config: &UserNamespaceConfig) -> Self {
        if let Some(linux) = &mut self.linux {
            if let Some(namespaces) = &mut linux.namespaces {
                namespaces.retain(|ns| ns.namespace_type != "network");
                if !namespaces.iter().any(|ns| ns.namespace_type == "user") {
                    namespaces.push(OciNamespace {
                        namespace_type: "user".to_string(),
                    });
                }
            }
            linux.uid_mappings = config.uid_mappings.iter().map(OciIdMapping::from).collect();
            linux.gid_mappings = config.gid_mappings.iter().map(OciIdMapping::from).collect();
        }
        self
    }
}

impl From<&IdMapping> for OciIdMapping {
    fn from(mapping: &IdMapping) -> Self {
        Self {
            container_id: mapping.container_id,
            host_id: mapping.host_id,
            size: mapping.count,
        }
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
        fs::set_permissions(&self.bundle_path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to secure bundle directory permissions {:?}: {}",
                self.bundle_path, e
            ))
        })?;

        // Create rootfs directory
        let rootfs = self.bundle_path.join("rootfs");
        fs::create_dir_all(&rootfs).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to create rootfs directory: {}", e))
        })?;
        fs::set_permissions(&rootfs, fs::Permissions::from_mode(0o700)).map_err(|e| {
            NucleusError::GVisorError(format!(
                "Failed to secure rootfs directory permissions {:?}: {}",
                rootfs, e
            ))
        })?;

        // Write config.json
        let config_path = self.bundle_path.join("config.json");
        let config_json = serde_json::to_string_pretty(&self.config).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to serialize OCI config: {}", e))
        })?;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&config_path)
            .map_err(|e| NucleusError::GVisorError(format!("Failed to open config.json: {}", e)))?;
        file.write_all(config_json.as_bytes()).map_err(|e| {
            NucleusError::GVisorError(format!("Failed to write config.json: {}", e))
        })?;
        file.sync_all()
            .map_err(|e| NucleusError::GVisorError(format!("Failed to sync config.json: {}", e)))?;

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

    #[test]
    fn test_host_runtime_binds_uses_fixed_paths_not_host_path() {
        // with_host_runtime_binds must NOT scan the host $PATH. Only standard
        // FHS paths should be bind-mounted to prevent leaking arbitrary host
        // directories into the container.
        let source = include_str!("oci.rs");
        // Check that with_host_runtime_binds does not call env::var("PATH")
        // We look for non-comment lines that reference env::var and PATH
        let fn_start = source.find("fn with_host_runtime_binds").unwrap();
        let fn_body = &source[fn_start..fn_start + 800];
        assert!(
            !fn_body.contains("env::var"),
            "with_host_runtime_binds must not read host $PATH"
        );
    }

    #[test]
    fn test_oci_config_uses_hardcoded_path_not_host() {
        // C-3: PATH must be a hardcoded minimal value, never the host's PATH.
        // This prevents leaking host filesystem layout into the container.
        std::env::set_var("PATH", "/nix/store/secret-hash/bin:/home/user/.local/bin");
        let config = OciConfig::new(vec!["/bin/sh".to_string()], None);
        let path_env = config
            .process
            .env
            .iter()
            .find(|e| e.starts_with("PATH="))
            .expect("PATH env must be set");
        assert_eq!(
            path_env,
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "OCI config must not leak host PATH"
        );
        assert!(
            !path_env.contains("/nix/store/secret"),
            "Host PATH must not leak into container"
        );
    }
}
