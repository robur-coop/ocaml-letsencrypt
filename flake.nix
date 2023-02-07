{
  description = "An implementation of the ACME protocol (RFC 8555) for OCaml";

  nixConfig = {
    extra-substituters = "https://anmonteiro.nix-cache.workers.dev";
    extra-trusted-public-keys = "ocaml.nix-cache.com-1:/xI2h2+56rwFfKyyFVbkJSeGqSIYMC/Je+7XXqGKDIY=";
  };

  inputs = {
    nixpkgs.url = "github:nix-ocaml/nix-overlays";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    nix-filter.url = "github:numtide/nix-filter";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
      ];
      systems = [ "x86_64-linux" "aarch64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {
        treefmt = {
          projectRootFile = "flake.nix";
          programs = {
            alejandra.enable = true;
          };
        };

        packages = pkgs.ocamlPackages.callPackage ./nix { inherit (inputs) nix-filter; };

        devShells.default = pkgs.mkShell {
          inputsFrom = with self'.packages; [
            letsencrypt
            letsencrypt-dns
            letsencrypt-app
          ];

          packages = with pkgs.ocamlPackages; [
            ocaml
            dune

            ocaml-lsp
          ];
        };
      };
      flake = {
        # The usual flake attributes can be defined here, including system-
        # agnostic ones like nixosModule and system-enumerating ones, although
        # those are more easily expressed in perSystem.

      };
    };
}
