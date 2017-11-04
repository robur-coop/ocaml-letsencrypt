#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let opams =
  let lint_deps_excluding =
    Some ["ounit"; "oUnit"; "dispatch"] (* acme_server is disabled below *)
  in
  [Pkg.opam_file ~lint_deps_excluding "opam"]

let () =
  Pkg.describe ~opams "letsencrypt" @@ fun c ->
  Ok [
    Pkg.mllib ~api:["Letsencrypt"] "src/letsencrypt.mllib";
    Pkg.bin "bin/oacmel";
    (* Pkg.bin "bin/acme_server"; *)
    Pkg.test "test/tests";
  ]
