{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    utils,
    ...
  }:
    utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };

        clang-ebpf = pkgs.writeShellScriptBin "clang" ''
        exec ${pkgs.llvmPackages_latest.clang-unwrapped}/bin/clang \
          -I${pkgs.linuxHeaders}/include \
          -I${pkgs.libbpf}/include \
          "$@"
        '';
      in rec {
        devShells.default = pkgs.mkShell {
          name = "cordon";
          packages = with pkgs; [
            go
            gopls
            go-tools
            clang-ebpf
            clang-tools
            libllvm
            libbpf
            linuxHeaders
            bpftools
          ];
        };
      }
    );
}
