{
  description = "Fluent RSP client — reproducible AWS Nitro EIF via monzo/aws-nitro-util";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    crane.url = "github:ipetkov/crane";

    # nitro-util's buildGoModule usage predates nixpkgs 25.05's structured-env
    # change (CGO_ENABLED must now live in `env`, not derivation args).
    # Let it pull its own vendored nixpkgs to avoid the attribute conflict.
    nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, nitro-util }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        nitro = nitro-util.lib.${system};

        # Rust toolchain with x86_64-linux-musl target for static enclave binary.
        rustToolchain = pkgs.rust-bin.stable."1.94.1".default.override {
          targets = [ "x86_64-unknown-linux-musl" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Pre-fetched genesis blobs for crates/primitives/build.rs.
        # build.rs iterates all three networks regardless of feature, so all
        # three must be present or the build fails trying to hit the network.
        genesisMainnet = pkgs.fetchurl {
          url = "https://github.com/fluentlabs-xyz/fluentbase/releases/download/v1.0.0/genesis-mainnet-v1.0.0.json.gz";
          sha256 = "72cb4b3b7b15de952bd1094281a1f2430cb711bc473a0520f92aa3e2b1bdb643";
        };
        genesisTestnet = pkgs.fetchurl {
          url = "https://github.com/fluentlabs-xyz/fluentbase/releases/download/v0.3.4-dev/genesis-v0.3.4-dev.json.gz";
          sha256 = "8cd30358c5664375e6739bc48302445e7ee10fd0158bedb788505e5c590983bd";
        };
        genesisDevnet = pkgs.fetchurl {
          url = "https://github.com/fluentlabs-xyz/fluentbase/releases/download/v0.5.7/genesis-v0.5.7.json.gz";
          sha256 = "91b9a427805d45dd14e46a0cd517bcc85f350fe7dfc38fa96f6ff0ebf5e864da";
        };

        # Crane vendors git deps per-commit (not per-name), so duplicate-name
        # crates like ecdsa-0.16.9 (appearing as both registry + git in the
        # same Cargo.lock) don't collide. However, when crane fetches a crate
        # from a git workspace, it vendors ONLY the crate's subdir — stripping
        # the workspace root's Cargo.toml. This breaks `readme.workspace =
        # true` inheritance (as used by op-revm). We patch the vendored
        # op-revm Cargo.toml to inline a concrete readme value.
        rawCargoVendor = craneLib.vendorCargoDeps {
          cargoLock = ./bin/client/Cargo.lock;
        };
        cargoVendorDir = pkgs.runCommand "rsp-client-vendor-patched" { } ''
          cp -rL --no-preserve=mode,ownership ${rawCargoVendor} $out
          # config.toml has absolute paths pointing back to the source derivation;
          # rewrite them to point at our patched copy at $out.
          sed -i "s|${rawCargoVendor}|$out|g" $out/config.toml
          # Several revm-rwasm crates (op-revm, revm-bytecode, ...) use
          # `readme.workspace = true`, but the workspace root doesn't define
          # workspace.package.readme at all — cargo tolerates this at
          # workspace level but fails when only the crate is vendored.
          # Rewrite every offending line to a concrete readme value.
          find $out -name Cargo.toml -print0 | xargs -0 \
            sed -i 's|^readme\.workspace = true|readme = "README.md"|'
        '';

        # Build rsp-client for one network feature → static musl ELF via crane.
        # Using crane (not buildRustPackage) because the latter's
        # replace-workspace-values postPatch script crashes on op-revm's
        # `readme.workspace = true` with KeyError: 'readme'.
        mkRspClient = network:
          craneLib.buildPackage {
            pname = "rsp-client-${network}";
            version = "0.1.0";

            # bin/client is a standalone crate but path-depends on ../../crates/*,
            # so the source must include both. sourceRoot cd's into bin/client
            # for cargo; the sibling crates/ stays reachable via relative paths.
            #
            # The filter is scoped to bin/client + crates/ only — unrelated
            # subtrees (bin/aws-nitro-validator, bin/proxy, bin/witness-*)
            # must NOT influence the source hash, otherwise mutating their
            # files (e.g. scripts/update_expected_pcr0.py rewriting
            # EXPECTED_PCR0 in aws-nitro-validator/src/lib.rs after each
            # build) would cascade into a different PCR0 on every rebuild.
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                let
                  root = toString ./.;
                  rel = pkgs.lib.removePrefix (root + "/") (toString path);
                  inWanted =
                    rel == "bin/client" || pkgs.lib.hasPrefix "bin/client/" rel
                    || rel == "crates"   || pkgs.lib.hasPrefix "crates/" rel
                    || rel == "Cargo.toml" || rel == "Cargo.lock";
                  isAncestor = rel == "" || rel == "bin";
                in
                  (inWanted || isAncestor)
                  && (type == "directory"
                      || craneLib.filterCargoSources path type
                      || builtins.match ".*/bin/client/trusted_setup\\.txt$" path != null);
            };
            sourceRoot = "source/bin/client";

            cargoToml = ./bin/client/Cargo.toml;
            cargoLock = ./bin/client/Cargo.lock;
            inherit cargoVendorDir;

            cargoExtraArgs = "--locked --no-default-features --features nitro,${network}";

            nativeBuildInputs = [ rustToolchain ];

            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/${pkgs.pkgsStatic.stdenv.cc.targetPrefix}cc";

            # Pre-populate genesis cache so build.rs skips network download.
            # directories::ProjectDirs::from(_, _, "fluent").cache_dir()
            # resolves to $HOME/.cache/fluent on Linux.
            preBuild = ''
              export HOME="$TMPDIR/home"
              mkdir -p "$HOME/.cache/fluent/genesis"
              install -m 0644 ${genesisMainnet} "$HOME/.cache/fluent/genesis/genesis-mainnet-v1.0.0.json.gz"
              install -m 0644 ${genesisTestnet} "$HOME/.cache/fluent/genesis/genesis-v0.3.4-dev.json.gz"
              install -m 0644 ${genesisDevnet}  "$HOME/.cache/fluent/genesis/genesis-v0.5.7.json.gz"
              # crates/primitives/build.rs writes generated code under
              # crates/primitives/src/fluent_genesis_bin/, so the source must
              # be writable. Crane unpacks with mode 555 (read-only).
              chmod -R u+w ../../crates
            '';

            doCheck = false;

            installPhaseCommand = ''
              mkdir -p $out/bin
              install -m 0755 \
                target/x86_64-unknown-linux-musl/release/rsp-client \
                $out/bin/rsp-client
            '';
          };

        mkEnclave = network:
          let
            client = mkRspClient network;
          in
          nitro.buildEif {
            name = "rsp-client-enclave-${network}";
            arch = "x86_64";

            kernel = nitro.blobs.x86_64.kernel;
            kernelConfig = nitro.blobs.x86_64.kernelConfig;
            nsmKo = nitro.blobs.x86_64.nsmKo;
            cmdline = builtins.readFile nitro.blobs.x86_64.cmdLine;

            copyToRoot = pkgs.buildEnv {
              name = "rsp-enclave-root";
              paths = [ client ];
              pathsToLink = [ "/bin" ];
            };

            entrypoint = "/bin/rsp-client";
            env = "";
          };
      in
      {
        packages = {
          rsp-client-mainnet = mkRspClient "mainnet";
          rsp-client-testnet = mkRspClient "testnet";
          rsp-client-devnet  = mkRspClient "devnet";

          enclave-mainnet = mkEnclave "mainnet";
          enclave-testnet = mkEnclave "testnet";
          enclave-devnet  = mkEnclave "devnet";

          default = mkEnclave "mainnet";
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.pkgsStatic.stdenv.cc
          ];
        };
      });
}
