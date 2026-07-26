{
  description = "A safety-first terminal UI for firewalld";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # Run `nix flake lock` once to pin nixpkgs in a committed flake.lock.
  outputs = { self, nixpkgs }:
    let
      # firewalld is Linux-only, so only Linux systems are supported.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "fwdeck";
          version = "0.2.1"; # x-release-please-version
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          # firewalld / firewall-cmd is a runtime dependency, resolved on PATH
          # of the host, not a build input.
          meta = {
            description = "A safety-first terminal UI for firewalld";
            homepage = "https://github.com/madebydaniz/fwdeck";
            license = nixpkgs.lib.licenses.mit;
            mainProgram = "fwdeck";
          };
        };
      });

      apps = forAll (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.default}/bin/fwdeck";
        };
      });
    };
}
