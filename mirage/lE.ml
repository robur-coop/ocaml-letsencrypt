type configuration = {
  email : Emile.mailbox option;
  certificate_seed : string option;
  certificate_key_type : X509.Key_type.t;
  certificate_key_bits : int option;
  hostname : [ `host ] Domain_name.t;
  account_seed : string option;
  account_key_type : X509.Key_type.t;
  account_key_bits : int option;
}

module C : Letsencrypt.Client.C
  with type 'a t = 'a Lwt.t
   and type ctx = Http_mirage_client.t
= struct
  type 'a t = 'a Lwt.t
  type ctx = Http_mirage_client.t
  type error = Mimic.error
  type meth = [ `HEAD | `GET | `POST ]

  type response =
    { headers : (string * string) list
    ; status : int }

  open Lwt.Infix

  let get_or_fail msg = function
    | Some ctx -> ctx
    | None -> failwith msg

  let request ?ctx ?meth ?headers ?body uri =
    let ctx = get_or_fail "http-mirage-client context is required" ctx in
    let meth = match meth with
      | Some `HEAD -> `HEAD | Some `GET -> `GET | Some `POST -> `POST
      | None -> `GET in
    Http_mirage_client.request ctx ~meth ?headers ?body uri
      (fun _response buf str -> Buffer.add_string buf str; Lwt.return buf)
      (Buffer.create 0x100) >>= function
    | Ok (resp, buf) ->
      let status = Http_mirage_client.Status.to_code resp.Http_mirage_client.status in
      let headers = Http_mirage_client.Headers.to_list resp.Http_mirage_client.headers in
      let headers = List.map (fun (k, v) -> String.lowercase_ascii k, v) headers in
      Lwt.return_ok ({ headers; status }, Buffer.contents buf)
    | Error err -> Lwt.return_error err
end

module Log = (val let src = Logs.Src.create "letsencrypt.mirage" in
              Logs.src_log src : Logs.LOG)

module Make (Stack : Tcpip.Stack.V4V6) = struct
  type nonrec configuration = configuration = {
    email : Emile.mailbox option;
    certificate_seed : string option;
    certificate_key_type : X509.Key_type.t;
    certificate_key_bits : int option;
    hostname : [ `host ] Domain_name.t;
    account_seed : string option;
    account_key_type : X509.Key_type.t;
    account_key_bits : int option;
  }

  module Acme = Letsencrypt.Client.Make (Lwt) (C)
  module Solver = Letsencrypt.Client.Solver (Lwt)

  let gen_key ?seed ?bits key_type =
    X509.Private_key.generate ?seed ?bits key_type

  let csr key host =
    let host = Domain_name.to_string host in
    let cn =
      X509.
        [ Distinguished_name.(Relative_distinguished_name.singleton (CN host)) ]
    in
    X509.Signing_request.create cn key

  let prefix = (".well-known", "acme-challenge")
  let tokens = Hashtbl.create 1

  let solver _host ~prefix:_ ~token ~content =
    Hashtbl.replace tokens token content ;
    Lwt.return (Ok ())

  let request_handler (ipaddr, port) reqd =
    let req = H1.Reqd.request reqd in
    Log.debug (fun m ->
        m "Let's encrypt request handler for %a:%d (%s)" Ipaddr.pp ipaddr port
          req.H1.Request.target) ;
    match String.split_on_char '/' req.H1.Request.target with
    | [ ""; p1; p2; token ]
      when String.equal p1 (fst prefix) && String.equal p2 (snd prefix) -> (
        match Hashtbl.find_opt tokens token with
        | Some data ->
            Log.debug (fun m -> m "Be able to respond to let's encrypt!") ;
            let headers =
              H1.Headers.of_list
                [
                  ("content-type", "application/octet-stream");
                  ("content-length", string_of_int (String.length data));
                ] in
            let resp = H1.Response.create ~headers `OK in
            H1.Reqd.respond_with_string reqd resp data
        | None ->
            Log.warn (fun m -> m "Token %S not found!" token) ;
            let headers = H1.Headers.of_list [ ("connection", "close") ] in
            let resp = H1.Response.create ~headers `Not_found in
            H1.Reqd.respond_with_string reqd resp "")
    | _ ->
        let headers = H1.Headers.of_list [ ("connection", "close") ] in
        let resp = H1.Response.create ~headers `Not_found in
        H1.Reqd.respond_with_string reqd resp ""

  let provision_certificate ?(tries = 10) ?(production = false) cfg ctx =
    let open Lwt.Infix in
    let ( >>? ) = Lwt_result.bind in
    let endpoint =
      if production
      then Letsencrypt.letsencrypt_production_url
      else Letsencrypt.letsencrypt_staging_url in
    let priv =
      gen_key ?seed:cfg.certificate_seed ?bits:cfg.certificate_key_bits
        cfg.certificate_key_type in
    match csr priv cfg.hostname with
    | Error _ as err -> Lwt.return err
    | Ok csr ->
        let account_key =
          gen_key ?seed:cfg.account_seed ?bits:cfg.account_key_bits
            cfg.account_key_type in
        Acme.initialise ~ctx ~endpoint
          ?email:(Option.map Emile.to_string cfg.email)
          account_key
        >>? fun le ->
        Log.debug (fun m -> m "Let's encrypt state initialized.") ;
        let sleep sec = Mirage_sleep.ns (Duration.of_sec sec) in
        let solver : Acme.solver = Solver.http_solver solver in
        let rec go tries =
          Acme.sign_certificate ~ctx solver le sleep csr >>= function
          | Ok certs -> Lwt.return_ok (`Single (certs, priv))
          | Error (`Msg err) when tries > 0 ->
              Log.warn (fun m ->
                  m
                    "Got an error when we tried to get a certificate: %s \
                     (tries: %d)"
                    err tries) ;
              go (pred tries)
          | Error (`Msg err) ->
              Log.err (fun m ->
                  m "Got an error when we tried to get a certificate: %s" err) ;
              Lwt.return (Error (`Msg err))
          | Error (`HTTP _err) ->
              Lwt.return (Error (`Msg "HTTP error during certificate provisioning")) in
        go tries

  let initialise ~ctx ~endpoint ?email key = Acme.initialise ~ctx ~endpoint:(Uri.to_string endpoint) ?email key
  let sign_certificate ~ctx solver le sleep csr = Acme.sign_certificate ~ctx solver le sleep csr
end
