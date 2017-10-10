#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "letsencrypt" @@ fun c ->
  Ok [
    Pkg.mllib ~api:["Letsencrypt"] "src/letsencrypt.mllib";
    Pkg.bin "bin/oacmel";
    Pkg.bin "bin/acme_server";
    Pkg.test "test/tests";
  ]
