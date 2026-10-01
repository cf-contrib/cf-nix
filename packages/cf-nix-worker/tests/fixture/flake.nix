{
  description = "Fixture flake for cf-nix R2 narinfo/nar testing";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        packages.default = pkgs.writeTextFile {
          name = "cf-nix-r2-fixture";
          text = ''
            This is a deterministic fixture output for cf-nix integration testing.
            Build this flake, then upload the generated .narinfo and .nar to R2.
          '';
        };
      }
    );
}
