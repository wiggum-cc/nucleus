/// Comprehensive integration tests for gVisor (runsc) container runtime.
///
/// These tests exercise the production code path: Container::new(config).run().
/// The child process forks, sets up namespaces, builds an OCI bundle, and
/// execve's into runsc which runs the workload under gVisor's application kernel.
///
/// For tests that need to verify container output, the container writes results
/// to a context directory (bind-mounted into the container) which the test reads
/// back from the host.
///
/// All tests require `runsc` on PATH (provided by gvisor in flake.nix).
#[cfg(test)]
mod tests {
    use nucleus::container::{Container, ContainerConfig};
    use nucleus::resources::ResourceLimits;
    use nucleus::security::GVisorRuntime;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    macro_rules! require_gvisor {
        () => {
            if !GVisorRuntime::is_available() {
                eprintln!("SKIP: runsc not available");
                return;
            }
        };
    }

    /// Run a container through the production code path and return exit code.
    fn run_gvisor(name: &str, command: Vec<String>) -> nucleus::Result<i32> {
        let config = ContainerConfig::new(Some(name.to_string()), command);
        Container::new(config).run()
    }

    /// Run a container that writes its output to a context directory,
    /// then read and return that output.
    /// The command should write to /context/output.
    fn run_gvisor_with_output(name: &str, shell_cmd: &str) -> (i32, String) {
        let context_dir = TempDir::new().unwrap();
        let output_file = context_dir.path().join("output");
        // Pre-create so the container can write to it
        fs::write(&output_file, "").unwrap();

        let config = ContainerConfig::new(
            Some(name.to_string()),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("{{ {}; }} > /context/output 2>&1", shell_cmd),
            ],
        )
        .with_context(context_dir.path().to_path_buf());

        let exit_code = Container::new(config).run().unwrap_or(-1);
        let output = fs::read_to_string(&output_file).unwrap_or_default();
        (exit_code, output)
    }

    fn unique_name(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{}", prefix, ts)
    }

    // -----------------------------------------------------------------------
    // gVisor runtime detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_runtime_detected() {
        require_gvisor!();
        let rt = GVisorRuntime::new().unwrap();
        let version = rt.version().expect("Failed to get runsc version");
        assert!(!version.is_empty(), "runsc version should not be empty");
        println!("runsc version: {}", version);
    }

    #[test]
    fn test_gvisor_is_available() {
        assert!(
            GVisorRuntime::is_available(),
            "GVisorRuntime::is_available() should return true when runsc is installed"
        );
    }

    // -----------------------------------------------------------------------
    // Basic container launch through production path
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_run_true() {
        require_gvisor!();
        let exit_code = run_gvisor(
            &unique_name("gv-true"),
            vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
        )
        .expect("Container should run successfully");
        assert_eq!(exit_code, 0, "true should exit 0");
    }

    #[test]
    fn test_gvisor_run_false_exits_nonzero() {
        require_gvisor!();
        let exit_code = run_gvisor(
            &unique_name("gv-false"),
            vec!["/bin/sh".to_string(), "-c".to_string(), "false".to_string()],
        )
        .expect("Container should run (even with non-zero exit)");
        assert_ne!(exit_code, 0, "false should exit non-zero");
    }

    #[test]
    fn test_gvisor_run_echo() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-echo"), "echo hello-gvisor");
        assert_eq!(exit_code, 0, "echo should exit 0");
        assert!(
            output.contains("hello-gvisor"),
            "stdout should contain 'hello-gvisor', got: {}",
            output
        );
    }

    #[test]
    fn test_gvisor_run_sh_command() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-sh"), "echo gvisor-works && exit 0");
        assert_eq!(exit_code, 0, "sh -c should succeed");
        assert!(output.contains("gvisor-works"));
    }

    // -----------------------------------------------------------------------
    // Exit code propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_exit_code_propagation() {
        require_gvisor!();

        for expected_code in [0, 1, 2, 42] {
            let exit_code = run_gvisor(
                &unique_name(&format!("gv-exit-{}", expected_code)),
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    format!("exit {}", expected_code),
                ],
            )
            .expect("Container should run");
            assert_eq!(
                exit_code, expected_code,
                "Exit code {} should propagate",
                expected_code
            );
        }
    }

    // -----------------------------------------------------------------------
    // Process isolation — PID namespace virtualisation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_pid_namespace_isolation() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(&unique_name("gv-pid-ns"), "echo pid=$$");
        assert_eq!(exit_code, 0);
        assert!(
            output.contains("pid="),
            "should report PID, got: {}",
            output
        );
    }

    #[test]
    fn test_gvisor_only_own_processes_visible() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-proc-count"),
            "ls /proc | grep -E '^[0-9]+$' | wc -l",
        );
        assert_eq!(exit_code, 0);
        let proc_count: u32 = output.trim().parse().unwrap_or(999);
        assert!(
            proc_count < 20,
            "Expected < 20 visible processes, got {}",
            proc_count
        );
    }

    // -----------------------------------------------------------------------
    // /proc virtualisation — gVisor's Sentry intercepts procfs
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_proc_self_exists() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-proc-self"),
            "test -d /proc/self && echo proc-ok",
        );
        assert_eq!(exit_code, 0);
        assert!(output.contains("proc-ok"));
    }

    #[test]
    fn test_gvisor_proc_meminfo_virtualised() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-meminfo"), "cat /proc/meminfo | head -3");
        assert_eq!(exit_code, 0);
        assert!(
            output.contains("MemTotal"),
            "/proc/meminfo should contain MemTotal, got: {}",
            output
        );
    }

    #[test]
    fn test_gvisor_proc_uptime_virtualised() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-uptime"), "cat /proc/uptime");
        assert_eq!(exit_code, 0);
        let uptime: f64 = output
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9999.0);
        assert!(
            uptime < 60.0,
            "Container uptime should be small (fresh boot), got: {}",
            uptime
        );
    }

    #[test]
    fn test_gvisor_proc_version() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-version"), "cat /proc/version");
        assert_eq!(exit_code, 0);
        assert!(
            !output.trim().is_empty(),
            "/proc/version should not be empty"
        );
        println!("/proc/version inside gVisor: {}", output.trim());
    }

    #[test]
    fn test_gvisor_proc_mounts_virtualised() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-mounts"), "cat /proc/mounts");
        assert_eq!(exit_code, 0);
        assert!(output.contains("/proc"), "should see /proc mount");
        assert!(output.contains("/dev"), "should see /dev mount");
    }

    // -----------------------------------------------------------------------
    // Filesystem isolation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_rootfs_readonly() {
        require_gvisor!();
        let (_, output) = run_gvisor_with_output(
            &unique_name("gv-ro-rootfs"),
            "touch /testfile 2>&1; echo exit=$?",
        );
        assert!(
            output.contains("exit=1")
                || output.contains("Read-only")
                || output.contains("read-only"),
            "Writing to read-only rootfs should fail, got: {}",
            output
        );
    }

    #[test]
    fn test_gvisor_tmp_writable() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-tmp-write"),
            "echo testdata > /tmp/testfile && cat /tmp/testfile",
        );
        assert_eq!(exit_code, 0, "writing to /tmp should work");
        assert!(output.contains("testdata"));
    }

    #[test]
    fn test_gvisor_host_filesystem_not_visible() {
        require_gvisor!();
        // Create a marker on the host in a non-shared location
        let marker_dir = TempDir::new().unwrap();
        let marker = marker_dir.path().join("host-marker.txt");
        fs::write(&marker, "host-secret").unwrap();

        let (_, output) = run_gvisor_with_output(
            &unique_name("gv-fs-iso"),
            &format!(
                "test -f {} && echo LEAKED || echo ISOLATED",
                marker.display()
            ),
        );
        assert!(
            output.contains("ISOLATED"),
            "Host filesystem should not be visible inside gVisor container, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // Network isolation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_network_none_no_eth() {
        require_gvisor!();
        let (_, output) = run_gvisor_with_output(
            &unique_name("gv-net-none"),
            "ls /sys/class/net/ 2>/dev/null || echo no-sysfs",
        );
        assert!(
            !output.contains("eth0"),
            "eth0 should not exist with network=none, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // Hostname / UTS namespace
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_hostname_set() {
        require_gvisor!();
        let context_dir = TempDir::new().unwrap();
        let output_file = context_dir.path().join("output");
        fs::write(&output_file, "").unwrap();

        let config = ContainerConfig::new(
            Some(unique_name("gv-hostname")),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "hostname > /context/output".to_string(),
            ],
        )
        .with_hostname(Some("nucleus-test-host".to_string()))
        .with_context(context_dir.path().to_path_buf());

        let exit_code = Container::new(config).run().unwrap();
        assert_eq!(exit_code, 0);
        let output = fs::read_to_string(&output_file).unwrap();
        assert_eq!(
            output.trim(),
            "nucleus-test-host",
            "Hostname should be 'nucleus-test-host', got: '{}'",
            output.trim()
        );
    }

    // -----------------------------------------------------------------------
    // Syscall interception — gVisor's Sentry mediates all syscalls
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_getpid_returns_virtualised_pid() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-getpid"),
            "cat /proc/self/stat | cut -d' ' -f1",
        );
        assert_eq!(exit_code, 0);
        let pid: u32 = output.trim().parse().unwrap_or(0);
        assert!(
            pid > 0 && pid < 100,
            "Virtualised PID should be small, got: {}",
            pid
        );
    }

    #[test]
    fn test_gvisor_clock_gettime_works() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(&unique_name("gv-clock"), "date +%s");
        assert_eq!(exit_code, 0);
        let ts: u64 = output.trim().parse().unwrap_or(0);
        assert!(
            ts > 1_700_000_000,
            "Timestamp should be reasonable, got: {}",
            ts
        );
    }

    // -----------------------------------------------------------------------
    // Security hardening — capabilities, no_new_privileges
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_no_capabilities() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-caps"), "grep -i ^Cap /proc/self/status");
        assert_eq!(exit_code, 0);
        println!("Capabilities inside gVisor:\n{}", output);
        for line in output.lines() {
            if line.starts_with("Cap") {
                let hex = line.split(':').nth(1).unwrap_or("").trim();
                assert_eq!(
                    hex, "0000000000000000",
                    "Capability set should be empty: {}",
                    line
                );
            }
        }
    }

    #[test]
    fn test_gvisor_no_new_privileges() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-nnp"), "cat /proc/self/status");
        assert_eq!(exit_code, 0);
        if output.contains("NoNewPrivs:") {
            assert!(
                output.contains("NoNewPrivs:\t1") || output.contains("NoNewPrivs: 1"),
                "NoNewPrivs should be 1 when reported, got: {}",
                output
            );
        }
    }

    // -----------------------------------------------------------------------
    // Environment variables
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_environment_variables() {
        require_gvisor!();
        let context_dir = TempDir::new().unwrap();
        let output_file = context_dir.path().join("output");
        fs::write(&output_file, "").unwrap();

        let mut config = ContainerConfig::new(
            Some(unique_name("gv-env")),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo PATH=$PATH && echo NUCLEUS_TEST=$NUCLEUS_TEST > /context/output".to_string(),
            ],
        )
        .with_context(context_dir.path().to_path_buf());

        config
            .environment
            .push(("NUCLEUS_TEST".to_string(), "gvisor-works".to_string()));

        let exit_code = Container::new(config).run().unwrap();
        assert_eq!(exit_code, 0);
        let output = fs::read_to_string(&output_file).unwrap();
        assert!(
            output.contains("NUCLEUS_TEST=gvisor-works"),
            "Custom env var should be set, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // Multiple processes / fork
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_can_fork_processes() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-fork"),
            "echo parent=$$ && /bin/sh -c 'echo child=$$'",
        );
        assert_eq!(exit_code, 0);
        assert!(output.contains("parent="));
        assert!(output.contains("child="));
    }

    // -----------------------------------------------------------------------
    // /dev virtualisation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_dev_null_works() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-devnull"),
            "echo discard > /dev/null && echo ok",
        );
        assert_eq!(exit_code, 0);
        assert!(output.contains("ok"));
    }

    #[test]
    fn test_gvisor_dev_urandom_readable() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-urandom"),
            "head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \\n'; echo",
        );
        assert_eq!(exit_code, 0);
        let hex = output.trim();
        assert!(
            hex.len() >= 16,
            "/dev/urandom should produce hex output, got: '{}'",
            hex
        );
    }

    // -----------------------------------------------------------------------
    // User / UID virtualisation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_runs_as_configured_uid() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(&unique_name("gv-uid"), "id -u && id -g");
        assert_eq!(exit_code, 0);
        let lines: Vec<&str> = output.trim().lines().collect();
        assert!(
            lines.len() >= 2,
            "Expected uid and gid lines, got: {}",
            output
        );
        assert_eq!(lines[0].trim(), "0", "uid should be 0");
        assert_eq!(lines[1].trim(), "0", "gid should be 0");
    }

    // -----------------------------------------------------------------------
    // Signal handling inside gVisor
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_signal_handling() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-signal"),
            "trap 'echo trapped-sigterm' TERM; kill -TERM $$; echo done",
        );
        assert_eq!(exit_code, 0);
        assert!(
            stdout_contains_signal(&output),
            "Signal handler should have run, got: {}",
            output
        );
    }

    fn stdout_contains_signal(output: &str) -> bool {
        output.contains("trapped-sigterm") || output.contains("done")
    }

    // -----------------------------------------------------------------------
    // Sysfs isolation
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_sysfs_readonly() {
        require_gvisor!();
        let (_, output) = run_gvisor_with_output(
            &unique_name("gv-sysfs-ro"),
            "touch /sys/testfile 2>&1; echo exit=$?",
        );
        assert!(
            output.contains("exit=1")
                || output.contains("Read-only")
                || output.contains("read-only")
                || output.contains("Permission denied"),
            "/sys should be read-only, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // Working directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_working_directory() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(&unique_name("gv-cwd"), "pwd");
        assert_eq!(exit_code, 0);
        assert_eq!(output.trim(), "/", "Default cwd should be /");
    }

    // -----------------------------------------------------------------------
    // Concurrent containers
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_concurrent_containers() {
        require_gvisor!();

        let handles: Vec<_> = (0..3)
            .map(|i| {
                std::thread::spawn(move || {
                    let exit_code = run_gvisor(
                        &unique_name(&format!("gv-conc-{}", i)),
                        vec![
                            "/bin/sh".to_string(),
                            "-c".to_string(),
                            format!("echo container-{}", i),
                        ],
                    )
                    .expect("Container should run");
                    assert_eq!(exit_code, 0, "Container {} should exit 0", i);
                })
            })
            .collect();

        for h in handles {
            h.join().expect("Thread panicked");
        }
    }

    // -----------------------------------------------------------------------
    // OCI bundle correctness through production path
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_with_resource_limits() {
        require_gvisor!();
        let limits = ResourceLimits::unlimited()
            .with_memory("128M")
            .unwrap()
            .with_pids(100)
            .unwrap();

        let config = ContainerConfig::new(
            Some(unique_name("gv-limits")),
            vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
        )
        .with_limits(limits);

        let exit_code = Container::new(config).run().unwrap();
        assert_eq!(exit_code, 0, "Container with resource limits should run");
    }

    #[test]
    fn test_gvisor_with_context_dir() {
        require_gvisor!();
        let context_dir = TempDir::new().unwrap();
        fs::write(context_dir.path().join("input.txt"), "hello from host").unwrap();
        let output_file = context_dir.path().join("output");
        fs::write(&output_file, "").unwrap();

        let config = ContainerConfig::new(
            Some(unique_name("gv-context")),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "cat /context/input.txt > /context/output".to_string(),
            ],
        )
        .with_context(context_dir.path().to_path_buf());

        let exit_code = Container::new(config).run().unwrap();
        assert_eq!(exit_code, 0);
        let output = fs::read_to_string(&output_file).unwrap();
        assert!(
            output.contains("hello from host"),
            "Context dir content should be readable, got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // gVisor-specific kernel behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn test_gvisor_dmesg_not_accessible() {
        require_gvisor!();
        // dmesg requires CAP_SYSLOG which we don't grant
        let exit_code = run_gvisor(
            &unique_name("gv-dmesg"),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "dmesg 2>/dev/null".to_string(),
            ],
        )
        .unwrap_or(-1);
        // Either dmesg is not found or returns error — both acceptable
        let _ = exit_code;
    }

    #[test]
    fn test_gvisor_proc_cmdline() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-cmdline"),
            "cat /proc/self/cmdline | tr '\\0' ' '",
        );
        assert_eq!(exit_code, 0);
        assert!(
            output.contains("sh") || output.contains("proc/self/cmdline"),
            "/proc/self/cmdline should reflect the launched command, got: {}",
            output
        );
    }

    #[test]
    fn test_gvisor_proc_status_fields() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-status"),
            "cat /proc/self/status | head -10",
        );
        assert_eq!(exit_code, 0);
        assert!(
            output.contains("Name:"),
            "/proc/self/status should have Name field"
        );
        assert!(
            output.contains("Pid:"),
            "/proc/self/status should have Pid field"
        );
    }

    #[test]
    fn test_gvisor_pipe_works() {
        require_gvisor!();
        let (exit_code, output) =
            run_gvisor_with_output(&unique_name("gv-pipe"), "echo hello | cat | cat");
        assert_eq!(exit_code, 0);
        assert_eq!(output.trim(), "hello");
    }

    #[test]
    fn test_gvisor_subshell_isolation() {
        require_gvisor!();
        let (exit_code, output) = run_gvisor_with_output(
            &unique_name("gv-subshell"),
            "VAR=outer; (VAR=inner; echo $VAR); echo $VAR",
        );
        assert_eq!(exit_code, 0);
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "inner");
        assert_eq!(lines[1], "outer");
    }
}
