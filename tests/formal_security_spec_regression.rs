use std::fs;
use std::path::PathBuf;

fn fixture(path: &str) -> String {
    let mut full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full_path.push(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {}", full_path.display(), err))
}

fn assert_contains_all(path: &str, required: &[&str]) {
    let text = fixture(path);
    for needle in required {
        assert!(
            text.contains(needle),
            "{} must retain concrete security assertion {:?}",
            path,
            needle
        );
    }
}

#[test]
fn security_intent_retains_concrete_container_controls() {
    assert_contains_all(
        "intent/security.intent",
        &[
            "can_see_host_pids",
            "can_access_host_fs",
            "has_network_access",
            "can_access_host_ipc",
            "can_call(\"ptrace\")",
            "can_call(\"kexec_load\")",
            "can_call(\"bpf\")",
            "can_call(\"userfaultfd\")",
            "has_memory_limit",
            "memory_usage <= memory_limit",
            "pid_count <= pid_limit",
            "cpu_usage <= cpu_limit",
            "container.security_complete | !container.running",
            "count(allowed_syscalls) <= 150",
            "file.has_setuid_bit",
        ],
    );
}

#[test]
fn generated_tla_retains_concrete_security_state() {
    assert_contains_all(
        "formal/tla/NucleusSecurity_Namespaces_NamespaceIsolation.tla",
        &[
            "can_see_host_pids",
            "can_access_host_fs",
            "has_network_access",
            "can_access_host_ipc",
            "Prop_pid_isolation",
        ],
    );
    assert_contains_all(
        "formal/tla/NucleusSecurity_Seccomp_SeccompEnforcement.tla",
        &[
            "DangerousSyscalls",
            "allowed_syscalls",
            "Prop_no_dangerous_syscalls",
            "Prop_whitelist_default_deny",
        ],
    );
    assert_contains_all(
        "formal/tla/NucleusSecurity_Cgroups_ResourceLimiting.tla",
        &[
            "has_memory_limit",
            "has_pids_limit",
            "has_cpu_limit",
            "memory_usage",
            "Prop_memory_bounded",
        ],
    );
}

#[test]
fn system_and_verification_intents_retain_concrete_gates() {
    assert_contains_all(
        "intent/system.intent",
        &[
            "count(processes_in_cgroup) == 0",
            "context_populated",
            "count(persisted_files) == 0",
            "capabilities_are_dropped",
            "container.security_applied | !container.running",
            "func.returns_result",
            "unsafe_block.in_module(\"ffi\")",
        ],
    );
    assert_contains_all(
        "intent/verification.intent",
        &[
            "has_unit_test(func)",
            "has_test_case(error_variant)",
            "test.verifies_pid_isolation",
            "apalache_verified(spec)",
            "cargo_audit_clean()",
            "all_integration_tests_pass(pr)",
        ],
    );
}
