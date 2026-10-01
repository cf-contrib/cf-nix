{
  description = "cf-nix-cache - Cloudflare-native Nix binary cache using Workers, R2, and Rust.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "cf-nix-cache";
          packages = [
            pkgs.nodejs_24
            pkgs.opentofu
            pkgs.pkg-config
            pkgs.wrangler
            pkgs.worker-build
            rust-toolchain
          ];
        };
      }
    );
}
