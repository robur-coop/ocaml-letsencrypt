open Cohttp
open Cohttp_lwt_unix
open Dispatch
open Lwt
open Nocrypto

module Json = Yojson.Basic

open Dispatch

let ca = "http://localhost:8080/"
let path_directory = "directory"

type directory_t = {
    directory   : string;
    root        : string;
    new_authz   : string;
    new_reg     : string;
    new_cert    : string;
    revoke_cert : string;
  }

type t = {
    port : int;
    dir  : directory_t;
  }

let new_server root port =
  let dir = {
    root        = root;
    directory   = "/directory";
    new_authz   = "/acme/new-authz";
    new_reg     = "/acme/new-reg";
    new_cert    = "/acme/new-cert";
    revoke_cert = "/acme/revoke-cert";
    } in
  let s = {
      dir     = dir;
      port    = port;
    } in
  s

let index_handler keys rest s request =
  let body = "Hello!\n" in
  Server.respond_string ~status:`OK ~body ()

let directory_handler keys rest s request =
  let p = (^) s.dir.root in
  let body = Printf.sprintf
               {|{"new-authz": "%s", "new-cert": "%s", "new-reg": "%s", "revoke-cert": "%s"}|}
               (p s.dir.new_authz)
               (p s.dir.new_cert)
               (p s.dir.new_reg)
               (p s.dir.revoke_cert)
  in
  Server.respond_string ~status:`OK ~body ()

let new_reg_handler keys rest s request =
  let body = "" in
  Server.respond_string ~status:`OK ~body ()

let notfound_handler uri =
  let body = "404: Not found." in
  Server.respond_string ~status:`Not_found ~body ()

let serve s request =
  let path = Request.uri request |> Uri.path in
  let table = [
      "/"            , index_handler
    ; s.dir.directory    , directory_handler
    ; s.dir.new_reg      , new_reg_handler
    ]
  in
  match DSL.dispatch table path with
  | Result.Ok handler -> handler s request
  | Result.Error _    -> notfound_handler path


let start_server s =
  let callback conn_id request body = serve s request in
  let port = `Port s.port in
  Server.create ~mode:(`TCP port) (Server.make ~callback ())

let () =
  let host = "localhost" in
  let port = 8000 in
  let root = Printf.sprintf "http://%s:%d" host port in
  let s = new_server root port in
  Printf.printf "Starting server on %s" root;
  start_server s |> Lwt_main.run |> ignore
