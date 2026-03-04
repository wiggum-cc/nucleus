--------------------------------------------- MODULE Nucleus_System ---------------------------------------------
EXTENDS Naturals, Sequences, TLC

\* Integrated system model for Nucleus.
\* Subsystem modules are instantiated to keep the composed model tied to existing specs.
INSTANCE Nucleus_Isolation_NamespaceLifecycle AS Iso
INSTANCE Nucleus_Filesystem_FilesystemLifecycle AS Fs
INSTANCE Nucleus_Resources_CgroupLifecycle AS Res
INSTANCE Nucleus_Security_SecurityEnforcement AS Sec

CONSTANTS Containers, Users, Paths, Signals, AllowedMountPaths

RootUser == "root"
NoContainer == "__none__"

ASSUME /\ Containers # {}
       /\ Users # {}
       /\ RootUser \in Users
       /\ NoContainer \notin Containers
       /\ Paths # {}
       /\ AllowedMountPaths \subseteq Paths
       /\ Signals # {}

\* Lifecycle states
LC_nonexistent == "nonexistent"
LC_created == "created"
LC_running == "running"
LC_stopping == "stopping"
LC_stopped == "stopped"
LC_removed == "removed"
LC_failed == "failed"
LifecycleStates == {LC_nonexistent, LC_created, LC_running, LC_stopping, LC_stopped, LC_removed, LC_failed}

\* Namespace states
NS_uninitialized == "uninitialized"
NS_entered == "entered"
NS_cleaned == "cleaned"
NamespaceStates == {NS_uninitialized, NS_entered, NS_cleaned}

\* Filesystem states
FS_unmounted == "unmounted"
FS_pivoted == "pivoted"
FS_unmounted_final == "unmounted_final"
FilesystemStates == {FS_unmounted, FS_pivoted, FS_unmounted_final}

\* Resource states
RS_nonexistent == "nonexistent"
RS_attached == "attached"
RS_removed == "removed"
ResourceStates == {RS_nonexistent, RS_attached, RS_removed}

\* Security chain states
SS_privileged == "privileged"
SS_caps_dropped == "caps_dropped"
SS_seccomp_applied == "seccomp_applied"
SS_landlock_applied == "landlock_applied"
SS_locked == "locked"
SS_degraded == "degraded"
SecurityStates == {SS_privileged, SS_caps_dropped, SS_seccomp_applied, SS_landlock_applied, SS_locked, SS_degraded}

\* Networking
NM_none == "none"
NM_host == "host"
NM_bridge == "bridge"
NetworkModes == {NM_none, NM_host, NM_bridge}

OperationNames == {
  "init", "switch_caller", "create", "set_network_mode", "bind_mount",
  "setup_namespaces", "setup_rootfs", "setup_resources", "setup_network",
  "enable_degraded", "drop_capabilities", "apply_seccomp", "apply_landlock", "finalize_security",
  "exec_workload", "stop", "kill", "attach", "remove", "complete_stop", "cleanup",
  "syscall_failure", "seccomp_unsupported", "landlock_unsupported", "pid_reuse_race", "refresh_pid"
}

ActionResults == {"ok", "granted", "denied"}
ControlOps == {"attach", "stop", "kill", "remove"}

ContainerInitRecord == [
  exists |-> FALSE,
  owner |-> RootUser,
  lifecycle |-> LC_nonexistent,
  ns_state |-> NS_uninitialized,
  fs_state |-> FS_unmounted,
  res_state |-> RS_nonexistent,
  sec_state |-> SS_privileged,
  network_mode |-> NM_none,
  network_ready |-> FALSE,
  allow_degraded |-> FALSE,
  caps_dropped |-> FALSE,
  seccomp_on |-> FALSE,
  landlock_on |-> FALSE,
  mounted_paths |-> {},
  start_requested |-> FALSE,
  stop_requested |-> FALSE,
  seccomp_supported |-> TRUE,
  landlock_supported |-> TRUE,
  pid_known |-> 0,
  pid_actual |-> 0
]

VARIABLES
    containers,   \* [Containers -> Record]
    caller,       \* active control-plane user
    now,          \* logical clock tick
    events        \* audit trail: Seq(Record(op, actor, target, result, t))

vars == <<containers, caller, now, events>>

AccessAllowed(u, c) == (u = RootUser) \/ (containers[c].owner = u)
PidFresh(c) == containers[c].pid_known = containers[c].pid_actual
NetworkReadyForExec(c) == IF containers[c].network_mode = NM_bridge THEN containers[c].network_ready ELSE TRUE

AppendEvent(op, target, result) ==
    Append(events, [op |-> op, actor |-> caller, target |-> target, result |-> result, t |-> now + 1])

Init ==
    /\ containers = [c \in Containers |-> ContainerInitRecord]
    /\ caller = RootUser
    /\ now = 0
    /\ events = << [op |-> "init", actor |-> RootUser, target |-> NoContainer, result |-> "ok", t |-> 0] >>

\* Code mapping: src/container/config.rs + src/container/runtime.rs (Container::run)
CreateContainer(c) ==
    /\ c \in Containers
    /\ ~containers[c].exists
    /\ containers' = [containers EXCEPT
          ![c].exists = TRUE,
          ![c].owner = caller,
          ![c].lifecycle = LC_created,
          ![c].ns_state = NS_uninitialized,
          ![c].fs_state = FS_unmounted,
          ![c].res_state = RS_nonexistent,
          ![c].sec_state = SS_privileged,
          ![c].network_mode = NM_none,
          ![c].network_ready = FALSE,
          ![c].allow_degraded = FALSE,
          ![c].caps_dropped = FALSE,
          ![c].seccomp_on = FALSE,
          ![c].landlock_on = FALSE,
          ![c].mounted_paths = {},
          ![c].start_requested = FALSE,
          ![c].stop_requested = FALSE,
          ![c].seccomp_supported = TRUE,
          ![c].landlock_supported = TRUE,
          ![c].pid_known = 0,
          ![c].pid_actual = 0
       ]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("create", c, "ok")

\* Code mapping: src/main.rs (--network)
SetNetworkMode(c, m) ==
    /\ c \in Containers
    /\ m \in NetworkModes
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers' = [containers EXCEPT ![c].network_mode = m]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("set_network_mode", c, "ok")

\* Code mapping: src/filesystem/mount.rs (bind mounts)
BindMountPath(c, p) ==
    /\ c \in Containers
    /\ p \in AllowedMountPaths
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers' = [containers EXCEPT ![c].mounted_paths = @ \cup {p}]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("bind_mount", c, "ok")

\* Code mapping: src/isolation/namespaces.rs + src/container/runtime.rs
SetupNamespaces(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].ns_state = NS_uninitialized
    /\ containers' = [containers EXCEPT ![c].ns_state = NS_entered]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("setup_namespaces", c, "ok")

\* Code mapping: src/filesystem/tmpfs.rs + src/filesystem/mount.rs::switch_root
SetupRootfs(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].fs_state = FS_unmounted
    /\ containers' = [containers EXCEPT ![c].fs_state = FS_pivoted]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("setup_rootfs", c, "ok")

\* Code mapping: src/resources/cgroup.rs + src/container/runtime.rs
SetupResources(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].res_state = RS_nonexistent
    /\ containers' = [containers EXCEPT ![c].res_state = RS_attached]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("setup_resources", c, "ok")

\* Code mapping: src/network/bridge.rs + runtime network branch
SetupNetwork(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].network_mode \in NetworkModes
    /\ containers' = [containers EXCEPT ![c].network_ready = TRUE]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("setup_network", c, "ok")

\* Code mapping: runtime env NUCLEUS_ALLOW_DEGRADED_SECURITY
EnableDegraded(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].sec_state = SS_privileged
    /\ containers' = [containers EXCEPT ![c].allow_degraded = TRUE]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("enable_degraded", c, "ok")

\* Code mapping: src/security/capabilities.rs
DropCapabilities(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].sec_state = SS_privileged
    /\ containers' = [containers EXCEPT
          ![c].sec_state = SS_caps_dropped,
          ![c].caps_dropped = TRUE
       ]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("drop_capabilities", c, "ok")

\* Code mapping: src/security/seccomp.rs + runtime fail-closed/degraded behavior
ApplySeccomp(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].sec_state = SS_caps_dropped
    /\ IF containers[c].seccomp_supported THEN
          containers' = [containers EXCEPT
             ![c].sec_state = SS_seccomp_applied,
             ![c].seccomp_on = TRUE
          ]
       ELSE IF containers[c].allow_degraded THEN
          containers' = [containers EXCEPT ![c].sec_state = SS_degraded]
       ELSE
          containers' = [containers EXCEPT ![c].lifecycle = LC_failed]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("apply_seccomp", c, "ok")

\* Code mapping: src/security/landlock.rs + runtime fail-closed/degraded behavior
ApplyLandlock(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].sec_state = SS_seccomp_applied
    /\ IF containers[c].landlock_supported THEN
          containers' = [containers EXCEPT
             ![c].sec_state = SS_landlock_applied,
             ![c].landlock_on = TRUE
          ]
       ELSE IF containers[c].allow_degraded THEN
          containers' = [containers EXCEPT ![c].sec_state = SS_degraded]
       ELSE
          containers' = [containers EXCEPT ![c].lifecycle = LC_failed]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("apply_landlock", c, "ok")

\* Code mapping: src/container/runtime.rs (security state lock)
FinalizeSecurity(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].sec_state = SS_landlock_applied
    /\ containers' = [containers EXCEPT ![c].sec_state = SS_locked]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("finalize_security", c, "ok")

\* Code mapping: src/container/runtime.rs (execve)
ExecWorkload(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers[c].ns_state = NS_entered
    /\ containers[c].fs_state = FS_pivoted
    /\ containers[c].res_state = RS_attached
    /\ NetworkReadyForExec(c)
    /\ containers[c].sec_state \in {SS_locked, SS_degraded}
    /\ IF containers[c].sec_state = SS_degraded THEN containers[c].allow_degraded ELSE TRUE
    /\ containers' = [containers EXCEPT
          ![c].lifecycle = LC_running,
          ![c].start_requested = TRUE,
          ![c].pid_actual = @ + 1,
          ![c].pid_known = @ + 1
       ]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("exec_workload", c, "ok")

\* Code mapping: src/container/runtime.rs waitpid/stop flow
CompleteStop(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_stopping
    /\ containers' = [containers EXCEPT ![c].lifecycle = LC_stopped]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("complete_stop", c, "ok")

\* Code mapping: src/container/lifecycle.rs stop/kill ownership + PID freshness
StopOrKillOrAttach(c, op, sig) ==
    /\ c \in Containers
    /\ op \in {"stop", "kill", "attach"}
    /\ sig \in Signals
    /\ containers[c].exists
    /\ containers[c].lifecycle \in {LC_running, LC_stopping}
    /\ IF op = "attach" THEN containers[c].lifecycle = LC_running ELSE TRUE
    /\ IF AccessAllowed(caller, c) /\ PidFresh(c) THEN
          /\ IF op = "stop" THEN
                containers' = [containers EXCEPT ![c].lifecycle = LC_stopping, ![c].stop_requested = TRUE]
             ELSE IF op = "kill" THEN
                containers' = [containers EXCEPT ![c].lifecycle = LC_stopped, ![c].stop_requested = TRUE]
             ELSE
                containers' = containers
          /\ now' = now + 1
          /\ events' = AppendEvent(op, c, "granted")
       ELSE
          /\ containers' = containers
          /\ now' = now + 1
          /\ events' = AppendEvent(op, c, "denied")
    /\ UNCHANGED caller

\* Code mapping: src/container/lifecycle.rs remove + cleanup
RemoveOrCleanup(c, op) ==
    /\ c \in Containers
    /\ op \in {"remove", "cleanup"}
    /\ containers[c].exists
    /\ containers[c].lifecycle \in {LC_stopped, LC_failed}
    /\ IF op = "cleanup" \/ AccessAllowed(caller, c) THEN
          /\ containers' = [containers EXCEPT
                ![c].lifecycle = LC_removed,
                ![c].ns_state = NS_cleaned,
                ![c].fs_state = FS_unmounted_final,
                ![c].res_state = RS_removed
             ]
          /\ now' = now + 1
          /\ events' = AppendEvent(op, c, "granted")
       ELSE
          /\ containers' = containers
          /\ now' = now + 1
          /\ events' = AppendEvent(op, c, "denied")
    /\ UNCHANGED caller

\* Adversarial environment: kernel capability changes
SeccompUnsupported(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers' = [containers EXCEPT ![c].seccomp_supported = FALSE]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("seccomp_unsupported", c, "ok")

LandlockUnsupported(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_created
    /\ containers' = [containers EXCEPT ![c].landlock_supported = FALSE]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("landlock_unsupported", c, "ok")

\* Adversarial environment: setup/runtime syscall failures
SyscallFailure(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle \in {LC_created, LC_running, LC_stopping}
    /\ containers' = [containers EXCEPT ![c].lifecycle = LC_failed]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("syscall_failure", c, "ok")

\* Adversarial environment: PID reuse race and refresh
PidReuseRace(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle = LC_running
    /\ containers' = [containers EXCEPT ![c].pid_actual = @ + 1]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("pid_reuse_race", c, "ok")

RefreshPid(c) ==
    /\ c \in Containers
    /\ containers[c].exists
    /\ containers[c].lifecycle \in {LC_running, LC_stopping}
    /\ containers' = [containers EXCEPT ![c].pid_known = @.pid_actual]
    /\ UNCHANGED caller
    /\ now' = now + 1
    /\ events' = AppendEvent("refresh_pid", c, "ok")

SwitchCaller(u) ==
    /\ u \in Users
    /\ caller' = u
    /\ UNCHANGED containers
    /\ now' = now + 1
    /\ events' = AppendEvent("switch_caller", NoContainer, "ok")

Next ==
    \/ \E u \in Users : SwitchCaller(u)
    \/ \E c \in Containers : CreateContainer(c)
    \/ \E c \in Containers : SetNetworkMode(c, NM_none)
    \/ \E c \in Containers : SetNetworkMode(c, NM_host)
    \/ \E c \in Containers : SetNetworkMode(c, NM_bridge)
    \/ \E c \in Containers : SetupNamespaces(c)
    \/ \E c \in Containers : SetupRootfs(c)
    \/ \E c \in Containers : SetupResources(c)
    \/ \E c \in Containers : SetupNetwork(c)
    \/ \E c \in Containers : EnableDegraded(c)
    \/ \E c \in Containers : DropCapabilities(c)
    \/ \E c \in Containers : ApplySeccomp(c)
    \/ \E c \in Containers : ApplyLandlock(c)
    \/ \E c \in Containers : FinalizeSecurity(c)
    \/ \E c \in Containers : ExecWorkload(c)
    \/ \E c \in Containers : CompleteStop(c)
    \/ \E c \in Containers : RemoveOrCleanup(c, "remove")
    \/ \E c \in Containers : RemoveOrCleanup(c, "cleanup")
    \/ \E c \in Containers, p \in AllowedMountPaths : BindMountPath(c, p)
    \/ \E c \in Containers, s \in Signals : StopOrKillOrAttach(c, "stop", s)
    \/ \E c \in Containers, s \in Signals : StopOrKillOrAttach(c, "kill", s)
    \/ \E c \in Containers, s \in Signals : StopOrKillOrAttach(c, "attach", s)
    \/ \E c \in Containers : SeccompUnsupported(c)
    \/ \E c \in Containers : LandlockUnsupported(c)
    \/ \E c \in Containers : SyscallFailure(c)
    \/ \E c \in Containers : PidReuseRace(c)
    \/ \E c \in Containers : RefreshPid(c)
    \/ UNCHANGED vars

Fairness ==
    /\ \A c \in Containers : WF_vars(SetupNamespaces(c))
    /\ \A c \in Containers : WF_vars(SetupRootfs(c))
    /\ \A c \in Containers : WF_vars(SetupResources(c))
    /\ \A c \in Containers : WF_vars(DropCapabilities(c))
    /\ \A c \in Containers : WF_vars(ApplySeccomp(c))
    /\ \A c \in Containers : WF_vars(ApplyLandlock(c))
    /\ \A c \in Containers : WF_vars(FinalizeSecurity(c))
    /\ \A c \in Containers : WF_vars(ExecWorkload(c))
    /\ \A c \in Containers : WF_vars(CompleteStop(c))
    /\ \A c \in Containers : WF_vars(RemoveOrCleanup(c, "cleanup"))

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ Fairness

LifecycleRank(s) ==
    IF s = LC_nonexistent THEN 0
    ELSE IF s = LC_created THEN 1
    ELSE IF s = LC_running THEN 2
    ELSE IF s = LC_stopping THEN 3
    ELSE IF s = LC_stopped THEN 4
    ELSE IF s = LC_failed THEN 5
    ELSE 6

SecurityRank(s) ==
    IF s = SS_privileged THEN 0
    ELSE IF s = SS_caps_dropped THEN 1
    ELSE IF s = SS_seccomp_applied THEN 2
    ELSE IF s = SS_landlock_applied THEN 3
    ELSE 4

TypeOK ==
    /\ caller \in Users
    /\ now \in Nat
    /\ containers \in [Containers -> [
         exists : BOOLEAN,
         owner : Users,
         lifecycle : LifecycleStates,
         ns_state : NamespaceStates,
         fs_state : FilesystemStates,
         res_state : ResourceStates,
         sec_state : SecurityStates,
         network_mode : NetworkModes,
         network_ready : BOOLEAN,
         allow_degraded : BOOLEAN,
         caps_dropped : BOOLEAN,
         seccomp_on : BOOLEAN,
         landlock_on : BOOLEAN,
         mounted_paths : SUBSET Paths,
         start_requested : BOOLEAN,
         stop_requested : BOOLEAN,
         seccomp_supported : BOOLEAN,
         landlock_supported : BOOLEAN,
         pid_known : Nat,
         pid_actual : Nat
       ]]
    /\ \A i \in 1..Len(events) :
         /\ events[i].op \in OperationNames
         /\ events[i].actor \in Users
         /\ events[i].target \in (Containers \cup {NoContainer})
         /\ events[i].result \in ActionResults
         /\ events[i].t \in Nat

RunningRequiresIsolation ==
    \A c \in Containers :
      containers[c].lifecycle = LC_running =>
        /\ containers[c].ns_state = NS_entered
        /\ containers[c].fs_state = FS_pivoted
        /\ containers[c].res_state = RS_attached
        /\ NetworkReadyForExec(c)

RunningRequiresSecurity ==
    \A c \in Containers :
      containers[c].lifecycle = LC_running =>
        (containers[c].sec_state = SS_locked \/ (containers[c].sec_state = SS_degraded /\ containers[c].allow_degraded))

LockedImpliesAllControls ==
    \A c \in Containers :
      containers[c].sec_state = SS_locked =>
        /\ containers[c].caps_dropped
        /\ containers[c].seccomp_on
        /\ containers[c].landlock_on

RemovedRequiresCleanup ==
    \A c \in Containers :
      containers[c].lifecycle = LC_removed =>
        /\ containers[c].ns_state = NS_cleaned
        /\ containers[c].fs_state = FS_unmounted_final
        /\ containers[c].res_state = RS_removed

MountedPathsRestricted ==
    \A c \in Containers : containers[c].mounted_paths \subseteq AllowedMountPaths

AuthorizationGrantedOnlyForOwnerOrRoot ==
    (events[Len(events)].op \in ControlOps /\ events[Len(events)].result = "granted") =>
        (events[Len(events)].target = NoContainer \/ AccessAllowed(events[Len(events)].actor, events[Len(events)].target))

AuthorizationDeniedOnlyForUnauthorized ==
    (events[Len(events)].op \in ControlOps /\ events[Len(events)].result = "denied") =>
        (events[Len(events)].target # NoContainer /\ ~AccessAllowed(events[Len(events)].actor, events[Len(events)].target))

NoBackwardLifecycle ==
    []\A c \in Containers : LifecycleRank(containers'[c].lifecycle) >= LifecycleRank(containers[c].lifecycle)

NoBackwardSecurity ==
    []\A c \in Containers : SecurityRank(containers'[c].sec_state) >= SecurityRank(containers[c].sec_state)

NoExecWithoutFreshPid ==
    \A c \in Containers : containers[c].lifecycle = LC_running => PidFresh(c)

StartedEventuallyRunningOrFailed(c) ==
    []((containers[c].start_requested /\ containers[c].lifecycle = LC_created) => <>(containers[c].lifecycle \in {LC_running, LC_failed}))

StopEventuallyStopped(c) ==
    []((containers[c].stop_requested /\ containers[c].lifecycle = LC_stopping) => <>(containers[c].lifecycle \in {LC_stopped, LC_removed}))

CleanupEventuallyRemoves(c) ==
    []((containers[c].lifecycle \in {LC_stopped, LC_failed}) => <>(containers[c].lifecycle = LC_removed))

AllStartsEventuallySettle == \A c \in Containers : StartedEventuallyRunningOrFailed(c)
AllStopsEventuallySettle == \A c \in Containers : StopEventuallyStopped(c)
AllCleanupEventuallyRemoves == \A c \in Containers : CleanupEventuallyRemoves(c)

NotTerminated ==
    \E c \in Containers : containers[c].lifecycle \notin {LC_removed, LC_failed}

=================================================================================================
