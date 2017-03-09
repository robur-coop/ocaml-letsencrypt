#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "letsencrypt" @@ fun c ->
  Ok [
    Pkg.mllib ~api:["Letsencrypt"] "src/letsencrypt.mllib";
    Pkg.mllib ~api:["Acme_client"] "src/acme_client.mllib";
    Pkg.bin ~dst:"oacmel" "src/oacmel";
    Pkg.test "src/tests";
  ]
