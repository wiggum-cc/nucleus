use crate::error::{NucleusError, Result};
use crate::filesystem::{
    resolve_container_destination, snapshot_context_dir, verify_context_manifest,
    verify_rootfs_attestation, ContextPopulator, create_dev_nodes, create_minimal_fs,
};
use crate::network::{BridgeNetwork, NetworkMode};
use crate::security::{GVisorNetworkMode, GVisorRuntime, OciBundle, OciConfig, OciMount};
use tracing::info;

use super::runtime::Container;
use super::ServiceMode;

impl Container {
    /// Set up container with gVisor and exec.
    pub(super) fn setup_and_exec_gvisor(&self) -> Result<()> {
        info!("Using gVisor runtime");

        let gvisor = if let Some(ref path) = self.runsc_path {
            GVisorRuntime::with_path(path.clone())
        } else {
            GVisorRuntime::new().map_err(|e| {
                NucleusError::GVisorError(format!("Failed to initialize gVisor runtime: {}", e))
            })?
        };

        self.setup_and_exec_gvisor_oci(&gvisor)
    }

    /// Set up container with gVisor using OCI bundle format.
    fn setup_and_exec_gvisor_oci(&self, gvisor: &GVisorRuntime) -> Result<()> {
        info!("Using gVisor with OCI bundle format");

        let mut oci_config =
            OciConfig::new(self.config.command.clone(), self.config.hostname.clone());
        let context_manifest = if self.config.verify_context_integrity {
            self.config
                .context_dir
                .as_ref()
                .map(|dir| snapshot_context_dir(dir))
                .transpose()?
        } else {
            None
        };

        oci_config = oci_config.with_resources(&self.config.limits);
        oci_config = oci_config.with_namespace_config(&self.config.namespaces);

        // Inject user-configured environment variables
        if !self.config.environment.is_empty() {
            oci_config = oci_config.with_env(&self.config.environment);
        }

        // Pass through sd_notify socket
        if self.config.sd_notify {
            oci_config = oci_config.with_sd_notify();
        }

        // Mount pre-built rootfs if provided
        if let Some(ref rootfs_path) = self.config.rootfs_path {
            if self.config.verify_rootfs_attestation {
                verify_rootfs_attestation(rootfs_path)?;
            }
            oci_config = oci_config.with_rootfs_binds(rootfs_path);
        } else {
            oci_config = oci_config.with_host_runtime_binds();
        }

        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::BindMount
            ) {
                ContextPopulator::new(context_dir, "/context").validate_source_tree()?;
                oci_config = oci_config.with_context_bind(context_dir);
            }
        }

        if !self.config.secrets.is_empty() && self.config.service_mode == ServiceMode::Production {
            let secret_stage_dir = Self::gvisor_secret_stage_dir(&self.config.id);
            Self::mount_gvisor_secret_stage_tmpfs(&secret_stage_dir)?;
            let staged_secrets =
                Self::stage_gvisor_secret_files(&secret_stage_dir, &self.config.secrets)?;
            oci_config =
                oci_config.with_inmemory_secret_mounts(&secret_stage_dir, &staged_secrets)?;
        } else if !self.config.secrets.is_empty() {
            oci_config = oci_config.with_secret_mounts(&self.config.secrets);
        }

        if let Some(user_ns_config) = &self.config.user_ns_config {
            oci_config = oci_config.with_rootless_user_namespace(user_ns_config);
        }

        // Pass OCI hooks into the gVisor config.json so gVisor executes them
        if let Some(ref hooks) = self.config.hooks {
            oci_config = oci_config.with_hooks(hooks.clone());
        }

        let artifact_dir = Self::gvisor_artifact_dir(&self.config.id);
        std::fs::create_dir_all(&artifact_dir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create gVisor artifact dir {:?}: {}",
                artifact_dir, e
            ))
        })?;
        // Use --bundle path if provided, otherwise default
        let bundle_path = self
            .config
            .bundle_dir
            .clone()
            .unwrap_or_else(|| Self::gvisor_bundle_path(&self.config.id));
        let oci_mounts = oci_config.mounts.clone();
        let bundle = OciBundle::new(bundle_path, oci_config);
        bundle.create()?;

        let rootfs = bundle.rootfs_path();
        create_minimal_fs(&rootfs)?;
        Self::prepare_oci_mountpoints(&rootfs, &oci_mounts)?;
        if let Some(context_dir) = &self.config.context_dir {
            if matches!(
                self.config.context_mode,
                crate::filesystem::ContextMode::Copy
            ) {
                let context_dest = rootfs.join("context");
                ContextPopulator::new(context_dir, &context_dest).populate()?;
                if let Some(expected) = &context_manifest {
                    verify_context_manifest(expected, &context_dest)?;
                }
            }
        }

        let dev_path = rootfs.join("dev");
        create_dev_nodes(&dev_path, false)?;

        // Write resolv.conf for bridge networking into the OCI rootfs
        if let NetworkMode::Bridge(ref bridge_config) = self.config.network {
            BridgeNetwork::write_resolv_conf(&rootfs, &bridge_config.dns)?;
        }

        // Select gVisor network mode based on container network config
        let gvisor_net = match &self.config.network {
            NetworkMode::None => GVisorNetworkMode::None,
            NetworkMode::Host => GVisorNetworkMode::Host,
            NetworkMode::Bridge(_) => GVisorNetworkMode::Sandbox,
        };

        let rootless_oci = self.config.user_ns_config.is_some();
        gvisor.exec_with_oci_bundle_network(
            &self.config.id,
            &bundle,
            gvisor_net,
            rootless_oci,
            self.config.gvisor_platform,
        )?;

        Ok(())
    }

    pub(super) fn prepare_oci_mountpoints(
        rootfs: &std::path::Path,
        mounts: &[OciMount],
    ) -> Result<()> {
        for mount in mounts {
            let normalized = crate::filesystem::normalize_container_destination(
                std::path::Path::new(&mount.destination),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Invalid OCI mount destination {:?}: {}",
                    mount.destination, e
                ))
            })?;
            let relative = normalized.strip_prefix("/").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to convert OCI mount destination {:?} into a rootfs-relative path: {}",
                    normalized, e
                ))
            })?;
            let target = rootfs.join(relative);
            if mount.mount_type == "bind" && std::path::Path::new(&mount.source).is_file() {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount parent {:?}: {}",
                            parent, e
                        ))
                    })?;
                }
                if !target.exists() {
                    std::fs::File::create(&target).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create OCI mount target {:?}: {}",
                            target, e
                        ))
                    })?;
                }
            } else {
                std::fs::create_dir_all(&target).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create OCI mount target {:?}: {}",
                        target, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    pub(super) fn gvisor_artifact_dir(container_id: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join("nucleus-gvisor")
            .join(container_id)
    }

    pub(super) fn gvisor_bundle_path(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("bundle")
    }

    fn gvisor_secret_stage_dir(container_id: &str) -> std::path::PathBuf {
        Self::gvisor_artifact_dir(container_id).join("secrets-stage")
    }

    fn mount_gvisor_secret_stage_tmpfs(stage_dir: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(stage_dir).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create gVisor secret stage dir {:?}: {}",
                stage_dir, e
            ))
        })?;

        nix::mount::mount(
            Some("tmpfs"),
            stage_dir,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC,
            Some("size=16m,mode=0700"),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to mount gVisor secret stage tmpfs at {:?}: {}",
                stage_dir, e
            ))
        })
    }

    pub(super) fn stage_gvisor_secret_files(
        stage_dir: &std::path::Path,
        secrets: &[crate::container::SecretMount],
    ) -> Result<Vec<crate::container::SecretMount>> {
        let mut staged = Vec::with_capacity(secrets.len());

        for secret in secrets {
            if !secret.source.exists() {
                return Err(NucleusError::FilesystemError(format!(
                    "Secret source does not exist: {:?}",
                    secret.source
                )));
            }

            let staged_source = resolve_container_destination(stage_dir, &secret.dest)?;
            if let Some(parent) = staged_source.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create gVisor secret parent {:?}: {}",
                        parent, e
                    ))
                })?;
            }

            let mut content = std::fs::read(&secret.source).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to read secret {:?}: {}",
                    secret.source, e
                ))
            })?;
            std::fs::write(&staged_source, &content).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to write staged secret {:?}: {}",
                    staged_source, e
                ))
            })?;

            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &staged_source,
                    std::fs::Permissions::from_mode(secret.mode),
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to set permissions on staged secret {:?}: {}",
                        staged_source, e
                    ))
                })?;
            }

            zeroize::Zeroize::zeroize(&mut content);

            staged.push(crate::container::SecretMount {
                source: staged_source,
                dest: secret.dest.clone(),
                mode: secret.mode,
            });
        }

        Ok(staged)
    }

    pub(super) fn cleanup_gvisor_artifacts(container_id: &str) -> Result<()> {
        let artifact_dir = Self::gvisor_artifact_dir(container_id);
        let secret_stage_dir = Self::gvisor_secret_stage_dir(container_id);

        if secret_stage_dir.exists() {
            match nix::mount::umount2(&secret_stage_dir, nix::mount::MntFlags::MNT_DETACH) {
                Ok(()) => {}
                Err(nix::errno::Errno::EINVAL) | Err(nix::errno::Errno::ENOENT) => {}
                Err(e) => {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to unmount gVisor secret stage {:?}: {}",
                        secret_stage_dir, e
                    )));
                }
            }
        }

        if artifact_dir.exists() {
            std::fs::remove_dir_all(&artifact_dir).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to remove gVisor artifact dir {:?}: {}",
                    artifact_dir, e
                ))
            })?;
        }

        Ok(())
    }
}
