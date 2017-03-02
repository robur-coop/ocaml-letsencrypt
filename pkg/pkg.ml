#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "acme" @@ fun c ->
  Ok [
    Pkg.bin ~dst:"oacmel" "src/acme_client";
    Pkg.test "src/tests";
  ]
