#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "acme" @@ fun c ->
  Ok [
    Pkg.mllib ~api:["Acme"] "src/acme.mllib";
    Pkg.mllib ~api:["Acme_client"] "src/acme_client.mllib";
    Pkg.bin ~dst:"oacmel" "src/oacmel";
    Pkg.test "src/tests";
  ]
