{ config, lib, pkgs, ... }:

let
  cfg = config.services.nucleus;
  inherit (lib) mkEnableOption mkOption types mkIf mapAttrs' nameValuePair
    concatStringsSep optional optionalString;

  containerOpts = { name, ... }: {
    options = {
      enable = mkEnableOption "this Nucleus container";

      command = mkOption {
        type = types.listOf types.str;
        description = "Command and arguments to run inside the container.";
      };

      rootfs = mkOption {
        type = types.package;
        description = ''
          Nix-built rootfs derivation (e.g. pkgs.buildEnv).
          Mounted read-only as the container filesystem instead of host bind mounts.
        '';
      };

      memory = mkOption {
        type = types.str;
        example = "512M";
        description = "Memory limit (e.g. 512M, 1G).";
      };

      cpus = mkOption {
        type = types.nullOr types.float;
        default = null;
        description = "CPU core limit.";
      };

      pids = mkOption {
        type = types.int;
        default = 512;
        description = "Maximum number of PIDs.";
      };

      network = mkOption {
        type = types.enum [ "none" "bridge" ];
        default = "bridge";
        description = "Network mode. Production mode forbids 'host'.";
      };

      dns = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "DNS servers for the container. Must be set explicitly for production.";
      };

      egressAllow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "10.0.0.0/8" "192.168.1.0/24" ];
        description = "Allowed egress CIDRs. Empty means deny-all outbound.";
      };

      egressTcpPorts = mkOption {
        type = types.listOf types.port;
        default = [ ];
        description = "Allowed egress TCP destination ports.";
      };

      egressUdpPorts = mkOption {
        type = types.listOf types.port;
        default = [ ];
        description = "Allowed egress UDP destination ports.";
      };

      portForwards = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "8080:80" "5353:53/udp" ];
        description = "Port forwarding rules (HOST:CONTAINER[/PROTOCOL]).";
      };

      trustLevel = mkOption {
        type = types.enum [ "trusted" "untrusted" ];
        default = "trusted";
        description = "Workload trust level. 'untrusted' requires gVisor.";
      };

      runtime = mkOption {
        type = types.enum [ "native" "gvisor" ];
        default = "native";
        description = "Container runtime.";
      };

      healthCheck = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "curl -sf http://localhost:8080/health";
        description = "Health check command to run inside the container.";
      };

      healthInterval = mkOption {
        type = types.int;
        default = 30;
        description = "Health check interval in seconds.";
      };

      healthRetries = mkOption {
        type = types.int;
        default = 3;
        description = "Health check failure retries before unhealthy.";
      };

      healthStartPeriod = mkOption {
        type = types.int;
        default = 5;
        description = "Seconds to wait before starting health checks.";
      };

      secrets = mkOption {
        type = types.listOf (types.submodule {
          options = {
            source = mkOption {
              type = types.path;
              description = "Source path (host or Nix store) for the secret.";
            };
            dest = mkOption {
              type = types.str;
              description = "Destination path inside the container.";
            };
          };
        });
        default = [ ];
        description = "Secret files to mount read-only into the container.";
      };

      environment = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "Environment variables to set in the container.";
      };

      sdNotify = mkOption {
        type = types.bool;
        default = true;
        description = "Enable sd_notify integration for systemd readiness.";
      };

      context = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Context directory to pre-populate in the container.";
      };

      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra arguments to pass to the nucleus run command.";
      };
    };
  };

  mkContainerService = name: containerCfg:
    let
      nucleusArgs = lib.concatStringsSep " " (
        [
          "--service-mode production"
          "--trust-level ${containerCfg.trustLevel}"
          "--memory ${containerCfg.memory}"
          "--pids ${toString containerCfg.pids}"
          "--network ${containerCfg.network}"
          "--rootfs ${containerCfg.rootfs}"
          "--name ${name}"
        ]
        ++ optional (containerCfg.cpus != null) "--cpus ${toString containerCfg.cpus}"
        ++ optional (containerCfg.runtime == "gvisor") "--runtime gvisor"
        ++ optional containerCfg.sdNotify "--sd-notify"
        ++ (map (d: "--dns ${d}") containerCfg.dns)
        ++ (map (c: "--egress-allow ${c}") containerCfg.egressAllow)
        ++ (map (p: "--egress-tcp-port ${toString p}") containerCfg.egressTcpPorts)
        ++ (map (p: "--egress-udp-port ${toString p}") containerCfg.egressUdpPorts)
        ++ (map (p: "-p ${p}") containerCfg.portForwards)
        ++ (map (s: "--secret ${s.source}:${s.dest}") containerCfg.secrets)
        ++ (lib.mapAttrsToList (k: v: "-e ${k}=${v}") containerCfg.environment)
        ++ optional (containerCfg.healthCheck != null)
          "--health-cmd '${containerCfg.healthCheck}'"
        ++ optional (containerCfg.healthCheck != null)
          "--health-interval ${toString containerCfg.healthInterval}"
        ++ optional (containerCfg.healthCheck != null)
          "--health-retries ${toString containerCfg.healthRetries}"
        ++ optional (containerCfg.healthCheck != null)
          "--health-start-period ${toString containerCfg.healthStartPeriod}"
        ++ optional (containerCfg.context != null) "--context ${containerCfg.context}"
        ++ containerCfg.extraArgs
      );
      commandStr = lib.concatStringsSep " " (map lib.escapeShellArg containerCfg.command);
    in
    nameValuePair "nucleus-${name}" {
      description = "Nucleus container: ${name}";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = if containerCfg.sdNotify then "notify" else "simple";
        ExecStart = "${cfg.package}/bin/nucleus run ${nucleusArgs} -- ${commandStr}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Journald integration: nucleus already uses tracing, which outputs
        # structured log lines. systemd captures stdout/stderr to journald.
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "nucleus-${name}";

        # Hardening at the systemd level (defense-in-depth)
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = false; # nucleus needs to set up namespaces
        LimitNOFILE = 65536;
      };
    };

in
{
  options.services.nucleus = {
    enable = mkEnableOption "Nucleus container runtime for production services";

    package = mkOption {
      type = types.package;
      description = "The nucleus package to use.";
    };

    containers = mkOption {
      type = types.attrsOf (types.submodule containerOpts);
      default = { };
      description = "Declarative Nucleus containers to run as systemd services.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services = lib.mapAttrs' mkContainerService
      (lib.filterAttrs (_: c: c.enable) cfg.containers);
  };
}
