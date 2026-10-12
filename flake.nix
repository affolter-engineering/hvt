{
  description = "hvt - HTTP Verb Tampering";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
      in {
        # `nix develop` - drop into dev shell
        devShells.default = pkgs.mkShell {
          # rustls is pure Rust - no OpenSSL or pkg-config needed
          buildInputs = with pkgs; [
            rustToolchain
            gcc
          ];
          RUST_BACKTRACE = "1";
        };

        # `nix build` - produce the binary
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "hvt";
          version = "0.2.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = with pkgs; [ gcc ];
          meta = with pkgs.lib; {
            description = "HTTP Verb Tampering - security testing tool";
            license = licenses.mit;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        # `nix flake check` - build and run cargo test
        checks.default = pkgs.rustPlatform.buildRustPackage {
          pname = "hvt";
          version = "0.2.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = with pkgs; [ gcc ];
          doCheck = true;
        };

        # `nix run` - run directly
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };
      });
}
