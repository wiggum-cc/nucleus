use std::collections::HashMap;

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
    allow_degraded: bool,
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
            allow_degraded: false,
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
            c.sec == SecurityState::Locked || (c.sec == SecurityState::Degraded && c.allow_degraded)
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
        assert!(matches!(c.lifecycle, Lifecycle::Running | Lifecycle::Stopping));
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
        assert!(matches!(c.lifecycle, Lifecycle::Stopped | Lifecycle::Failed));
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
