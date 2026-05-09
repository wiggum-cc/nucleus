{
  description = "Nucleus - Extremely lightweight Docker alternative for agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane.url = "github:ipetkov/crane";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay, advisory-db, ... }:
    {
      # NixOS module for declarative Nucleus service management
      nixosModules.default = import ./nix/module.nix;
      nixosModules.nucleus = self.nixosModules.default;

      # Helper: build a minimal rootfs for a Nucleus production container.
      # Usage in a flake:
      #   nucleus.lib.mkRootfs { pkgs = import nixpkgs { system = "x86_64-linux"; };
      #     packages = [ pkgs.coreutils pkgs.curl pkgs.cacert ]; }
      lib.mkRootfs = { pkgs, packages ? [ ], name ? "nucleus-rootfs" }:
        let
          baseRootfs = pkgs.buildEnv {
            inherit name;
            paths = [ pkgs.coreutils pkgs.bashInteractive ] ++ packages;
            pathsToLink = [ "/bin" "/sbin" "/lib" "/lib64" "/usr" "/etc" ];
          };
          closure = pkgs.closureInfo {
            rootPaths = [ baseRootfs ];
          };
        in
        pkgs.runCommand name {
          nativeBuildInputs = [ pkgs.coreutils pkgs.findutils ];
        } ''
          mkdir -p "$out"
          for path in bin sbin lib lib64 usr etc; do
            if [ -e "${baseRootfs}/$path" ]; then
              mkdir -p "$out/$path"
              cp -a -P --no-preserve=mode,ownership "${baseRootfs}/$path/." "$out/$path/"
            fi
          done
          mkdir -p "$out/etc"
          rm -f "$out/etc/resolv.conf"
          : > "$out/etc/resolv.conf"

          mkdir -p "$out/nix/store"
          store_paths="$out/.nucleus-rootfs-store-paths"
          : > "$store_paths"
          while IFS= read -r store_path; do
            case "$store_path" in
              /nix/store/*)
                basename="$(basename "$store_path")"
                mkdir -p "$out/nix/store/$basename"
                printf '%s\n' "$store_path" >> "$store_paths"
                ;;
            esac
          done < "${closure}/store-paths"
          sort -u -o "$store_paths" "$store_paths"

          manifest="$out/.nucleus-rootfs-sha256"
          find -L "$out" -type f ! -name ".nucleus-rootfs-sha256" -printf '%P\0' \
            | sort -z \
            | while IFS= read -r -d "" rel; do
                digest="$(sha256sum "$out/$rel" | cut -d' ' -f1)"
                printf '%s\t%s\n' "$digest" "$rel"
              done > "$manifest"
        '';
    } //
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        inherit (pkgs) lib;

        gvisor = pkgs.gvisor.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ [
            ./nix/patches/gvisor-runsc-real-exe-path.patch
          ];
        });
        gvisorRuntimePkgs = lib.optionals pkgs.stdenv.isLinux [ gvisor ];
        networkRuntimePkgs = lib.optionals pkgs.stdenv.isLinux [ pkgs.iptables pkgs.slirp4netns ];
        runtimePath = lib.makeBinPath (gvisorRuntimePkgs ++ networkRuntimePkgs);

        rustToolchain = pkgs.rust-bin.stable.latest.default;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Check if Cargo.lock exists
        cargoLockExists = builtins.pathExists ./Cargo.lock;

        srcRoot = ./.;
        src =
          if cargoLockExists then
            lib.cleanSourceWith {
              src = srcRoot;
              filter =
                path: type:
                let
                  pathString = toString path;
                  rootString = toString srcRoot;
                  relativePath = lib.removePrefix "${rootString}/" pathString;
                in
                craneLib.filterCargoSources path type
                || relativePath == "formal"
                || lib.hasPrefix "formal/" relativePath
                || relativePath == "intent"
                || lib.hasPrefix "intent/" relativePath
                || relativePath == "nix/patches/gvisor-runsc-real-exe-path.patch";
            }
          else
            srcRoot;

        # Common arguments
        commonArgs = {
          inherit src;
          pname = "nucleus";
          version = "0.3.7";
          strictDeps = true;

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          buildInputs = [
            pkgs.openssl
          ] ++ lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];
        };

        # Build dependencies only (for caching)
        cargoArtifacts = if cargoLockExists then craneLib.buildDepsOnly commonArgs else null;

        # Build the actual crate
        my-crate = if cargoLockExists then craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          nativeCheckInputs = gvisorRuntimePkgs;
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.makeWrapper ];
          postFixup = lib.optionalString pkgs.stdenv.isLinux ''
            wrapProgram $out/bin/nucleus --prefix PATH : "${runtimePath}"
          '';
        }) else null;

        # Apalache - TLA+ model checker
        apalacheVersion = "0.52.2";
        apalache = pkgs.stdenv.mkDerivation {
          pname = "apalache";
          version = apalacheVersion;

          src = pkgs.fetchurl {
            url = "https://github.com/apalache-mc/apalache/releases/download/v${apalacheVersion}/apalache-${apalacheVersion}.tgz";
            sha256 = "e0ebea7e45c8f99df8d92f2755101dda84ab71df06d1ec3a21955d3b53a886e2";
          };

          nativeBuildInputs = [ pkgs.makeWrapper ];
          buildInputs = [ pkgs.jdk17_headless ];

          dontConfigure = true;
          dontBuild = true;

          unpackPhase = ''
            mkdir -p src
            tar xzf $src -C src --strip-components=1
          '';

          installPhase = ''
            mkdir -p $out/share/apalache $out/bin
            cp -r src/lib $out/share/apalache/
            cp -r src/bin $out/share/apalache/

            makeWrapper $out/share/apalache/bin/apalache-mc $out/bin/apalache-mc \
              --set JAVA_HOME "${pkgs.jdk17_headless}" \
              --prefix PATH : "${pkgs.jdk17_headless}/bin"
          '';
        };

      in
      {
        checks = lib.optionalAttrs cargoLockExists {
          inherit my-crate;

          my-crate-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          my-crate-doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
          });

          my-crate-fmt = craneLib.cargoFmt {
            inherit src;
            pname = "nucleus";
            version = "0.3.7";
          };

          my-crate-audit = craneLib.cargoAudit {
            inherit src advisory-db;
            pname = "nucleus";
            version = "0.3.7";
          };

          my-crate-deny = craneLib.cargoDeny {
            inherit src;
            pname = "nucleus";
            version = "0.3.7";
          };

          my-crate-nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            nativeCheckInputs = gvisorRuntimePkgs;
            partitions = 1;
            partitionType = "count";
          });
        };

        packages = lib.optionalAttrs cargoLockExists {
          default = my-crate;
        };

        apps = lib.optionalAttrs cargoLockExists {
          default = flake-utils.lib.mkApp {
            drv = my-crate;
          };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";

          shellHook = ''
            if [ "''${NUCLEUS_ENABLE_SCCACHE:-0}" = "1" ]; then
              export RUSTC_WRAPPER="${pkgs.sccache}/bin/sccache"
              export SCCACHE_CACHE_SIZE="5G"
            else
              unset RUSTC_WRAPPER
            fi
          '';

          packages = with pkgs; [
            # Build tools
            pkg-config
            openssl
            openssl.dev

            # Rust tooling
            rust-analyzer
            cargo-watch
            cargo-nextest
            sccache
            just

            # Container runtime
            gvisor
            iptables
            slirp4netns

            # Formal verification tools
            z3
            apalache
          ];
        };
      });
}
