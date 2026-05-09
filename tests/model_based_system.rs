use proptest::prelude::*;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Nonexistent,
    Created,
    Running,
    Stopping,
    Stopped,
    Removed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceState {
    Uninitialized,
    Entered,
    Cleaned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemState {
    Unmounted,
    Pivoted,
    UnmountedFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceState {
    Nonexistent,
    Attached,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityState {
    Privileged,
    CapsDropped,
    SeccompApplied,
    LandlockApplied,
    Locked,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkMode {
    None,
    Host,
    Bridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustLevel {
    Trusted,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpResult {
    Granted,
    Denied,
}

#[derive(Debug)]
struct ContainerModel {
    owner: String,
    lifecycle: Lifecycle,
    ns: NamespaceState,
    fs: FilesystemState,
    res: ResourceState,
    sec: SecurityState,
    network_mode: NetworkMode,
    network_ready: bool,
    trust_level: TrustLevel,
    gvisor_available: bool,
    use_gvisor: bool,
    allow_degraded: bool,
    allow_host_network: bool,
    caps_dropped: bool,
    seccomp_on: bool,
    landlock_on: bool,
    mounted_paths: Vec<String>,
    start_requested: bool,
    stop_requested: bool,
    seccomp_supported: bool,
    landlock_supported: bool,
    pid_known: u64,
    pid_actual: u64,
}

impl Default for ContainerModel {
    fn default() -> Self {
        Self {
            owner: "root".to_string(),
            lifecycle: Lifecycle::Nonexistent,
            ns: NamespaceState::Uninitialized,
            fs: FilesystemState::Unmounted,
            res: ResourceState::Nonexistent,
            sec: SecurityState::Privileged,
            network_mode: NetworkMode::None,
            network_ready: false,
            trust_level: TrustLevel::Untrusted,
            gvisor_available: false,
            use_gvisor: false,
            allow_degraded: false,
            allow_host_network: false,
            caps_dropped: false,
            seccomp_on: false,
            landlock_on: false,
            mounted_paths: Vec::new(),
            start_requested: false,
            stop_requested: false,
            seccomp_supported: true,
            landlock_supported: true,
            pid_known: 0,
            pid_actual: 0,
        }
    }
}

#[derive(Debug)]
struct SystemModel {
    caller: String,
    allowed_mounts: Vec<String>,
    containers: HashMap<String, ContainerModel>,
}

impl SystemModel {
    fn new(ids: &[&str]) -> Self {
        let mut containers = HashMap::new();
        for id in ids {
            containers.insert((*id).to_string(), ContainerModel::default());
        }
        Self {
            caller: "root".to_string(),
            allowed_mounts: vec![
                "/bin".into(),
                "/usr".into(),
                "/lib".into(),
                "/lib64".into(),
                "/context".into(),
                "/tmp".into(),
                "/etc".into(),
                "/proc".into(),
                "/dev".into(),
            ],
            containers,
        }
    }

    fn c_mut(&mut self, id: &str) -> &mut ContainerModel {
        self.containers.get_mut(id).unwrap()
    }

    fn c(&self, id: &str) -> &ContainerModel {
        self.containers.get(id).unwrap()
    }

    fn switch_caller(&mut self, caller: &str) {
        self.caller = caller.to_string();
    }

    fn create(&mut self, id: &str) {
        let caller = self.caller.clone();
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Nonexistent);
        c.lifecycle = Lifecycle::Created;
        c.owner = caller;
    }

    fn set_network_mode(&mut self, id: &str, mode: NetworkMode) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.network_mode = mode;
    }

    fn setup_network(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.network_ready = true;
    }

    fn bind_mount(&mut self, id: &str, path: &str) {
        assert!(self.allowed_mounts.iter().any(|p| p == path));
        let c = self.c_mut(id);
        c.mounted_paths.push(path.to_string());
    }

    fn setup_namespaces(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.ns = NamespaceState::Entered;
    }

    fn setup_rootfs(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.fs = FilesystemState::Pivoted;
    }

    fn setup_resources(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.res = ResourceState::Attached;
    }

    fn enable_degraded(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.allow_degraded = true;
    }

    fn enable_gvisor_runtime(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.use_gvisor = true;
    }

    fn enable_host_network_opt_in(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        c.allow_host_network = true;
    }

    fn drop_capabilities(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.sec, SecurityState::Privileged);
        c.sec = SecurityState::CapsDropped;
        c.caps_dropped = true;
    }

    fn apply_seccomp(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.sec, SecurityState::CapsDropped);
        if c.seccomp_supported {
            c.sec = SecurityState::SeccompApplied;
            c.seccomp_on = true;
        } else if c.allow_degraded {
            c.sec = SecurityState::Degraded;
        } else {
            c.lifecycle = Lifecycle::Failed;
        }
    }

    fn apply_landlock(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.sec, SecurityState::SeccompApplied);
        if c.landlock_supported {
            c.sec = SecurityState::LandlockApplied;
            c.landlock_on = true;
        } else if c.allow_degraded {
            c.sec = SecurityState::Degraded;
        } else {
            c.lifecycle = Lifecycle::Failed;
        }
    }

    fn finalize_security(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.sec, SecurityState::LandlockApplied);
        c.sec = SecurityState::Locked;
    }

    fn exec_workload(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Created);
        assert_eq!(c.ns, NamespaceState::Entered);
        assert_eq!(c.fs, FilesystemState::Pivoted);
        assert_eq!(c.res, ResourceState::Attached);
        if c.network_mode == NetworkMode::Bridge {
            assert!(c.network_ready);
        }
        assert!(
            c.sec == SecurityState::Locked
                || (c.sec == SecurityState::Degraded && c.allow_degraded)
        );

        c.start_requested = true;
        c.lifecycle = Lifecycle::Running;
        c.pid_actual += 1;
        c.pid_known = c.pid_actual;
    }

    fn can_access(&self, id: &str) -> bool {
        let c = self.c(id);
        self.caller == "root" || self.caller == c.owner
    }

    fn pid_fresh(&self, id: &str) -> bool {
        let c = self.c(id);
        c.pid_known == c.pid_actual
    }

    fn stop(&mut self, id: &str) -> OpResult {
        let allowed = self.can_access(id) && self.pid_fresh(id);
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Running);
        if allowed {
            c.lifecycle = Lifecycle::Stopping;
            c.stop_requested = true;
            OpResult::Granted
        } else {
            OpResult::Denied
        }
    }

    fn kill(&mut self, id: &str) -> OpResult {
        let allowed = self.can_access(id) && self.pid_fresh(id);
        let c = self.c_mut(id);
        assert!(matches!(
            c.lifecycle,
            Lifecycle::Running | Lifecycle::Stopping
        ));
        if allowed {
            c.lifecycle = Lifecycle::Stopped;
            c.stop_requested = true;
            OpResult::Granted
        } else {
            OpResult::Denied
        }
    }

    fn attach(&mut self, id: &str) -> OpResult {
        let allowed = self.can_access(id) && self.pid_fresh(id);
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Running);
        if allowed {
            OpResult::Granted
        } else {
            OpResult::Denied
        }
    }

    fn complete_stop(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Stopping);
        c.lifecycle = Lifecycle::Stopped;
    }

    fn remove(&mut self, id: &str) -> OpResult {
        let allowed = self.can_access(id);
        let c = self.c_mut(id);
        assert!(matches!(
            c.lifecycle,
            Lifecycle::Stopped | Lifecycle::Failed
        ));
        if allowed {
            c.lifecycle = Lifecycle::Removed;
            c.ns = NamespaceState::Cleaned;
            c.fs = FilesystemState::UnmountedFinal;
            c.res = ResourceState::Removed;
            OpResult::Granted
        } else {
            OpResult::Denied
        }
    }

    fn set_trust_level(&mut self, id: &str, level: TrustLevel) {
        let c = self.c_mut(id);
        c.trust_level = level;
    }

    fn set_gvisor_available(&mut self, id: &str, available: bool) {
        let c = self.c_mut(id);
        c.gvisor_available = available;
    }

    /// Model the runtime trust-level guard logic.
    /// Returns Ok(()) if the container may proceed, Err with reason otherwise.
    fn apply_trust_level_policy(&mut self, id: &str) -> std::result::Result<(), &'static str> {
        let c = self.c_mut(id);
        match c.trust_level {
            TrustLevel::Trusted => Ok(()),
            TrustLevel::Untrusted => {
                if c.network_mode == NetworkMode::Host && !(c.use_gvisor && c.allow_host_network) {
                    return Err("untrusted workloads cannot use host network");
                }
                if !c.use_gvisor {
                    if c.gvisor_available {
                        c.use_gvisor = true;
                        Ok(())
                    } else if c.allow_degraded {
                        Ok(())
                    } else {
                        Err("untrusted workloads require gVisor")
                    }
                } else {
                    Ok(())
                }
            }
        }
    }

    fn syscall_failure(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert!(matches!(
            c.lifecycle,
            Lifecycle::Created | Lifecycle::Running | Lifecycle::Stopping
        ));
        c.lifecycle = Lifecycle::Failed;
    }

    fn set_seccomp_unsupported(&mut self, id: &str) {
        let c = self.c_mut(id);
        c.seccomp_supported = false;
    }

    fn set_landlock_unsupported(&mut self, id: &str) {
        let c = self.c_mut(id);
        c.landlock_supported = false;
    }

    fn pid_reuse_race(&mut self, id: &str) {
        let c = self.c_mut(id);
        assert_eq!(c.lifecycle, Lifecycle::Running);
        c.pid_actual += 1;
    }

    fn refresh_pid(&mut self, id: &str) {
        let c = self.c_mut(id);
        c.pid_known = c.pid_actual;
    }
}

#[test]
fn test_security_chain_locked_implies_controls() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");

    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");

    let c = m.c("c1");
    assert_eq!(c.sec, SecurityState::Locked);
    assert!(c.caps_dropped);
    assert!(c.seccomp_on);
    assert!(c.landlock_on);
}

#[test]
fn test_fail_closed_when_seccomp_unsupported_without_degraded() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.drop_capabilities("c1");
    m.set_seccomp_unsupported("c1");
    m.apply_seccomp("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Failed);
}

#[test]
fn test_degraded_allowed_when_seccomp_unsupported() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.enable_degraded("c1");
    m.drop_capabilities("c1");
    m.set_seccomp_unsupported("c1");
    m.apply_seccomp("c1");
    assert_eq!(m.c("c1").sec, SecurityState::Degraded);
}

#[test]
fn test_fail_closed_when_landlock_unsupported_without_degraded() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.set_landlock_unsupported("c1");
    m.apply_landlock("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Failed);
}

#[test]
fn test_bridge_network_requires_setup_before_exec() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_network_mode("c1", NetworkMode::Bridge);
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");

    // Now satisfy bridge network prerequisite and run.
    m.setup_network("c1");
    m.exec_workload("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Running);
}

#[test]
fn test_host_network_exec_path() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_network_mode("c1", NetworkMode::Host);
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Running);
}

#[test]
fn test_mount_restriction_only_allowed_paths() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.bind_mount("c1", "/bin");
    m.bind_mount("c1", "/context");

    let c = m.c("c1");
    for p in &c.mounted_paths {
        assert!(m.allowed_mounts.iter().any(|ap| ap == p));
    }
}

#[test]
fn test_authorization_owner_or_root_for_control_ops() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    m.switch_caller("bob");
    assert_eq!(m.attach("c1"), OpResult::Denied);
    assert_eq!(m.stop("c1"), OpResult::Denied);

    m.switch_caller("root");
    assert_eq!(m.kill("c1"), OpResult::Granted);
}

#[test]
fn test_pid_reuse_race_blocks_control_until_refresh() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    m.pid_reuse_race("c1");
    assert_eq!(m.stop("c1"), OpResult::Denied);

    m.refresh_pid("c1");
    assert_eq!(m.stop("c1"), OpResult::Granted);
}

#[test]
fn test_stop_eventually_stops_and_cleanup_removes() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    assert_eq!(m.stop("c1"), OpResult::Granted);
    m.complete_stop("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Stopped);

    assert_eq!(m.remove("c1"), OpResult::Granted);
    let c = m.c("c1");
    assert_eq!(c.lifecycle, Lifecycle::Removed);
    assert_eq!(c.ns, NamespaceState::Cleaned);
    assert_eq!(c.fs, FilesystemState::UnmountedFinal);
    assert_eq!(c.res, ResourceState::Removed);
}

#[test]
fn test_partial_setup_failure_path() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.setup_namespaces("c1");
    m.syscall_failure("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Failed);

    assert_eq!(m.remove("c1"), OpResult::Granted);
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Removed);
}

#[test]
fn test_adversarial_bridge_exec_without_network_setup_panics() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_network_mode("c1", NetworkMode::Bridge);
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");

    let result = catch_unwind(AssertUnwindSafe(|| m.exec_workload("c1")));
    assert!(result.is_err());
}

#[test]
fn test_adversarial_finalize_from_degraded_state_panics() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.enable_degraded("c1");
    m.drop_capabilities("c1");
    m.set_seccomp_unsupported("c1");
    m.apply_seccomp("c1");
    assert_eq!(m.c("c1").sec, SecurityState::Degraded);

    let result = catch_unwind(AssertUnwindSafe(|| m.finalize_security("c1")));
    assert!(result.is_err());
}

#[test]
fn test_adversarial_non_owner_cannot_kill_even_with_fresh_pid() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    m.switch_caller("bob");
    assert_eq!(m.kill("c1"), OpResult::Denied);
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Running);
}

#[test]
fn test_adversarial_attach_denied_on_stale_pid_until_refresh() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    m.pid_reuse_race("c1");
    assert_eq!(m.attach("c1"), OpResult::Denied);

    m.refresh_pid("c1");
    assert_eq!(m.attach("c1"), OpResult::Granted);
}

#[test]
fn test_adversarial_mount_escape_path_panics() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");

    let result = catch_unwind(AssertUnwindSafe(|| m.bind_mount("c1", "/etc/../../root")));
    assert!(result.is_err());
}

#[test]
fn test_adversarial_fail_closed_prevents_exec_after_seccomp_failure() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.drop_capabilities("c1");
    m.set_seccomp_unsupported("c1");
    m.apply_seccomp("c1");
    assert_eq!(m.c("c1").lifecycle, Lifecycle::Failed);

    let result = catch_unwind(AssertUnwindSafe(|| m.exec_workload("c1")));
    assert!(result.is_err());
}

#[test]
fn test_complex_attach_multi_container_authorization_matrix() {
    let mut m = SystemModel::new(&["c1", "c2"]);

    // c1 owned by alice
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    // c2 owned by bob
    m.switch_caller("bob");
    m.create("c2");
    m.setup_namespaces("c2");
    m.setup_rootfs("c2");
    m.setup_resources("c2");
    m.setup_network("c2");
    m.drop_capabilities("c2");
    m.apply_seccomp("c2");
    m.apply_landlock("c2");
    m.finalize_security("c2");
    m.exec_workload("c2");

    // alice can attach only to c1
    m.switch_caller("alice");
    assert_eq!(m.attach("c1"), OpResult::Granted);
    assert_eq!(m.attach("c2"), OpResult::Denied);

    // bob can attach only to c2
    m.switch_caller("bob");
    assert_eq!(m.attach("c1"), OpResult::Denied);
    assert_eq!(m.attach("c2"), OpResult::Granted);

    // root can attach to both
    m.switch_caller("root");
    assert_eq!(m.attach("c1"), OpResult::Granted);
    assert_eq!(m.attach("c2"), OpResult::Granted);
}

#[test]
fn test_complex_attach_denied_during_stopping_transition() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    assert_eq!(m.stop("c1"), OpResult::Granted);
    let result = catch_unwind(AssertUnwindSafe(|| m.attach("c1")));
    assert!(result.is_err());
}

#[test]
fn test_complex_attach_denied_after_kill_and_remove() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    assert_eq!(m.kill("c1"), OpResult::Granted);
    let stopped_attach = catch_unwind(AssertUnwindSafe(|| m.attach("c1")));
    assert!(stopped_attach.is_err());

    assert_eq!(m.remove("c1"), OpResult::Granted);
    let removed_attach = catch_unwind(AssertUnwindSafe(|| m.attach("c1")));
    assert!(removed_attach.is_err());
}

#[test]
fn test_complex_attach_pid_reuse_multiple_cycles() {
    let mut m = SystemModel::new(&["c1"]);
    m.switch_caller("alice");
    m.create("c1");
    m.setup_namespaces("c1");
    m.setup_rootfs("c1");
    m.setup_resources("c1");
    m.setup_network("c1");
    m.drop_capabilities("c1");
    m.apply_seccomp("c1");
    m.apply_landlock("c1");
    m.finalize_security("c1");
    m.exec_workload("c1");

    // Multiple PID reuse events keep attach denied until refreshed.
    m.pid_reuse_race("c1");
    m.pid_reuse_race("c1");
    assert_eq!(m.attach("c1"), OpResult::Denied);

    m.refresh_pid("c1");
    assert_eq!(m.attach("c1"), OpResult::Granted);

    // Another reuse invalidates authorization again.
    m.pid_reuse_race("c1");
    assert_eq!(m.attach("c1"), OpResult::Denied);
    m.refresh_pid("c1");
    assert_eq!(m.attach("c1"), OpResult::Granted);
}

proptest! {
    #[test]
    fn prop_security_chain_invariance(
        seccomp_supported in any::<bool>(),
        landlock_supported in any::<bool>(),
        allow_degraded in any::<bool>(),
    ) {
        let mut m = SystemModel::new(&["c1"]);
        m.create("c1");
        if allow_degraded {
            m.enable_degraded("c1");
        }
        m.drop_capabilities("c1");

        if !seccomp_supported {
            m.set_seccomp_unsupported("c1");
        }
        m.apply_seccomp("c1");

        let c_after_seccomp = m.c("c1");
        if !seccomp_supported && !allow_degraded {
            prop_assert_eq!(c_after_seccomp.lifecycle, Lifecycle::Failed);
            prop_assert!(!c_after_seccomp.seccomp_on);
            return Ok(());
        }
        if !seccomp_supported && allow_degraded {
            prop_assert_eq!(c_after_seccomp.sec, SecurityState::Degraded);
            prop_assert_eq!(c_after_seccomp.lifecycle, Lifecycle::Created);
            prop_assert!(!c_after_seccomp.seccomp_on);
            return Ok(());
        }

        prop_assert_eq!(c_after_seccomp.sec, SecurityState::SeccompApplied);
        prop_assert!(c_after_seccomp.seccomp_on);

        if !landlock_supported {
            m.set_landlock_unsupported("c1");
        }
        m.apply_landlock("c1");

        let c_after_landlock = m.c("c1");
        if !landlock_supported && !allow_degraded {
            prop_assert_eq!(c_after_landlock.lifecycle, Lifecycle::Failed);
            prop_assert!(!c_after_landlock.landlock_on);
            return Ok(());
        }
        if !landlock_supported && allow_degraded {
            prop_assert_eq!(c_after_landlock.sec, SecurityState::Degraded);
            prop_assert_eq!(c_after_landlock.lifecycle, Lifecycle::Created);
            prop_assert!(!c_after_landlock.landlock_on);
            return Ok(());
        }

        m.finalize_security("c1");
        let c_final = m.c("c1");
        prop_assert_eq!(c_final.sec, SecurityState::Locked);
        prop_assert!(c_final.caps_dropped);
        prop_assert!(c_final.seccomp_on);
        prop_assert!(c_final.landlock_on);
    }

    #[test]
    fn prop_control_ops_require_auth_and_fresh_pid(
        op in 0u8..3,
        caller_is_root in any::<bool>(),
        caller_is_owner in any::<bool>(),
        stale_pid in any::<bool>(),
    ) {
        let mut m = SystemModel::new(&["c1"]);
        m.switch_caller("alice");
        m.create("c1");
        m.setup_namespaces("c1");
        m.setup_rootfs("c1");
        m.setup_resources("c1");
        m.setup_network("c1");
        m.drop_capabilities("c1");
        m.apply_seccomp("c1");
        m.apply_landlock("c1");
        m.finalize_security("c1");
        m.exec_workload("c1");

        let caller = if caller_is_root {
            "root"
        } else if caller_is_owner {
            "alice"
        } else {
            "bob"
        };
        m.switch_caller(caller);

        if stale_pid {
            m.pid_reuse_race("c1");
        }

        let should_grant = (caller == "root" || caller == "alice") && !stale_pid;
        let before = m.c("c1").lifecycle;
        let result = match op {
            0 => m.stop("c1"),
            1 => m.kill("c1"),
            _ => m.attach("c1"),
        };

        if should_grant {
            prop_assert_eq!(result, OpResult::Granted);
            match op {
                0 => prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Stopping),
                1 => prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Stopped),
                _ => prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Running),
            }
        } else {
            prop_assert_eq!(result, OpResult::Denied);
            prop_assert_eq!(before, Lifecycle::Running);
            prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Running);
        }
    }

    #[test]
    fn prop_remove_requires_authorization(
        caller_is_root in any::<bool>(),
        caller_is_owner in any::<bool>(),
        failed_path in any::<bool>(),
    ) {
        let mut m = SystemModel::new(&["c1"]);
        m.switch_caller("alice");
        m.create("c1");

        if failed_path {
            m.syscall_failure("c1");
            prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Failed);
        } else {
            m.setup_namespaces("c1");
            m.setup_rootfs("c1");
            m.setup_resources("c1");
            m.setup_network("c1");
            m.drop_capabilities("c1");
            m.apply_seccomp("c1");
            m.apply_landlock("c1");
            m.finalize_security("c1");
            m.exec_workload("c1");
            prop_assert_eq!(m.stop("c1"), OpResult::Granted);
            m.complete_stop("c1");
            prop_assert_eq!(m.c("c1").lifecycle, Lifecycle::Stopped);
        }

        let caller = if caller_is_root {
            "root"
        } else if caller_is_owner {
            "alice"
        } else {
            "bob"
        };
        m.switch_caller(caller);

        let result = m.remove("c1");
        let should_grant = caller == "root" || caller == "alice";
        if should_grant {
            prop_assert_eq!(result, OpResult::Granted);
            let c = m.c("c1");
            prop_assert_eq!(c.lifecycle, Lifecycle::Removed);
            prop_assert_eq!(c.ns, NamespaceState::Cleaned);
            prop_assert_eq!(c.fs, FilesystemState::UnmountedFinal);
            prop_assert_eq!(c.res, ResourceState::Removed);
        } else {
            prop_assert_eq!(result, OpResult::Denied);
            prop_assert!(matches!(m.c("c1").lifecycle, Lifecycle::Stopped | Lifecycle::Failed));
        }
    }

    #[test]
    fn prop_trust_level_policy_invariants(
        trust_trusted in any::<bool>(),
        host_network in any::<bool>(),
        explicit_gvisor in any::<bool>(),
        allow_host_network in any::<bool>(),
        gvisor_available in any::<bool>(),
        allow_degraded in any::<bool>(),
    ) {
        let mut m = SystemModel::new(&["c1"]);
        m.create("c1");

        if trust_trusted {
            m.set_trust_level("c1", TrustLevel::Trusted);
        }
        if host_network {
            m.set_network_mode("c1", NetworkMode::Host);
        }
        if explicit_gvisor {
            m.enable_gvisor_runtime("c1");
        }
        if allow_host_network {
            m.enable_host_network_opt_in("c1");
        }
        m.set_gvisor_available("c1", gvisor_available);
        if allow_degraded {
            m.enable_degraded("c1");
        }

        let result = m.apply_trust_level_policy("c1");

        if trust_trusted {
            // Trusted always succeeds
            prop_assert!(result.is_ok());
        } else {
            // Untrusted
            if host_network && !(explicit_gvisor && allow_host_network) {
                // Denied unless gVisor remains the runtime boundary and host
                // networking was explicitly requested.
                prop_assert!(result.is_err());
            } else if explicit_gvisor || gvisor_available {
                // Explicit gVisor or auto-enabled gVisor satisfies the trust policy.
                prop_assert!(result.is_ok());
                prop_assert!(m.c("c1").use_gvisor);
            } else if allow_degraded {
                // Degraded → Ok but no gVisor
                prop_assert!(result.is_ok());
                prop_assert!(!m.c("c1").use_gvisor);
            } else {
                // No gVisor, no degraded → denied
                prop_assert!(result.is_err());
            }
        }
    }
}

// --- Trust-level deterministic model tests ---

#[test]
fn test_untrusted_host_network_denied_without_explicit_gvisor_boundary() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Untrusted);
    m.set_network_mode("c1", NetworkMode::Host);
    m.set_gvisor_available("c1", true);
    m.enable_degraded("c1");

    let result = m.apply_trust_level_policy("c1");
    assert!(
        result.is_err(),
        "Untrusted + host network must be denied without explicit gVisor runtime"
    );
}

#[test]
fn test_untrusted_host_network_allowed_with_explicit_gvisor_boundary() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Untrusted);
    m.set_network_mode("c1", NetworkMode::Host);
    m.enable_gvisor_runtime("c1");
    m.enable_host_network_opt_in("c1");

    let result = m.apply_trust_level_policy("c1");
    assert!(
        result.is_ok(),
        "Untrusted + host network should pass trust policy when gVisor remains the runtime boundary"
    );
}

#[test]
fn test_untrusted_no_gvisor_no_degraded_fails() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Untrusted);
    m.set_gvisor_available("c1", false);
    // allow_degraded defaults to false

    let result = m.apply_trust_level_policy("c1");
    assert!(
        result.is_err(),
        "Untrusted without gVisor or degraded must fail"
    );
}

#[test]
fn test_untrusted_gvisor_available_auto_enables() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Untrusted);
    m.set_gvisor_available("c1", true);

    let result = m.apply_trust_level_policy("c1");
    assert!(result.is_ok(), "Should succeed with gVisor available");
    assert!(
        m.c("c1").use_gvisor,
        "gVisor should be auto-enabled for untrusted workloads"
    );
}

#[test]
fn test_untrusted_no_gvisor_degraded_continues() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Untrusted);
    m.set_gvisor_available("c1", false);
    m.enable_degraded("c1");

    let result = m.apply_trust_level_policy("c1");
    assert!(
        result.is_ok(),
        "Should succeed in degraded mode without gVisor"
    );
    assert!(
        !m.c("c1").use_gvisor,
        "gVisor should not be enabled when unavailable"
    );
}

#[test]
fn test_trusted_does_not_enforce_gvisor() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Trusted);
    m.set_gvisor_available("c1", false);

    let result = m.apply_trust_level_policy("c1");
    assert!(result.is_ok(), "Trusted workloads should always pass");
    assert!(!m.c("c1").use_gvisor, "Trusted should not force gVisor on");
}

#[test]
fn test_trusted_host_network_not_denied_by_trust_policy() {
    let mut m = SystemModel::new(&["c1"]);
    m.create("c1");
    m.set_trust_level("c1", TrustLevel::Trusted);
    m.set_network_mode("c1", NetworkMode::Host);

    let result = m.apply_trust_level_policy("c1");
    assert!(
        result.is_ok(),
        "Trusted + host network should not be denied by trust policy"
    );
}
