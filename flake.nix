
{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = { self, nixpkgs, utils, naersk, flake-compat }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in
      {
        defaultPackage = naersk-lib.buildPackage { 
          src = ./.; 
        };
        devShell = with pkgs; mkShell {
          buildInputs = [ cargo rustc pre-commit rustPackages.clippy rust-analyzer cargo-expand rustfmt rust-bindgen-unwrapped cargo-deny sqlite openssl cmake ninja];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}


