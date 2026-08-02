{
  description = "Impulse Server - secure ephemeral messenger over WebTransport (QUIC)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "impulse-server";
            version = "2.5.1";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = with pkgs; [ cmake perl ];
          };
        });
    };
}
