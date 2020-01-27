open Lwt.Infix

open Acme_common

type t = {
  account_key : Nocrypto.Rsa.priv ;
  mutable next_nonce : string ;
  d : directory_t ;
}

type challenge_t = {
  url : Uri.t ;
  token : string ;
}

type solver_t = {
  name : string ;
  get_challenge : Json.t -> (challenge_t, [ `Msg of string ]) result ;
  solve_challenge : (unit -> unit Lwt.t) -> t -> challenge_t ->
    [`host] Domain_name.t -> (unit, [ `Msg of string ]) result Lwt.t ;
}

let error_in endpoint code body =
  let body = String.escaped body in
  Error (`Msg (Printf.sprintf "Error at %s: code %d - body: %s" endpoint code body))

let bad_nonce body =
  match Json.of_string body with
  | Error _ -> false
  | Ok json -> match Json.string_member "type" json with
    | Error _ -> false
    | Ok x -> String.equal x "urn:acme:error:badNonce"

let extract_nonce headers =
  match Cohttp.Header.get headers "Replay-Nonce" with
  | Some nonce -> Ok nonce
  | None -> Error (`Msg "Error: I could not fetch a new nonce.")

(*
   XXX. probably the structure of challenges different from http-01 and
   dns-01 is different, but for the two and only supported ones it's
   probably fine.
 *)
(* TODO what about the tail of the challenge list? *)
let get_challenge challenge_filter authorization =
  let open Rresult.R.Infix in
  Json.list_member "challenges" authorization >>= fun challenges ->
  match List.filter challenge_filter challenges with
  | [] -> Error (`Msg "No supported challenges found.")
  | challenge :: cs ->
    Logs.debug (fun m -> m "got %d challenges, using the head"
                   (succ (List.length cs))) ;
    Json.string_member "token" challenge >>= fun token ->
    Json.string_member "uri" challenge >>= fun url ->
    Ok { token ; url = Uri.of_string url }

let http_solver writef =
  let name = "http-01" in
  let get_http01_challenge =
    let is_http01 c = match Json.string_member "type" c with
      | Ok x when x = "http-01" -> true
      | _ -> false
    in
    get_challenge is_http01
  in
  let solve_http01_challenge _ cli challenge domain =
    let token = challenge.token in
    let pk = Primitives.pub_of_priv cli.account_key in
    let thumbprint = Jwk.thumbprint (`Rsa pk) in
    let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
    writef domain token key_authorization;
    Lwt.return_ok ()
  in
  {
    name = name ;
    get_challenge = get_http01_challenge ;
    solve_challenge = solve_http01_challenge
  }

let default_http_solver =
  let default_writef domain file content =
    Logs.info (fun f -> f "Domain %a wants file %s content %s\n"
                  Domain_name.pp domain file content);
    ignore (read_line ())
  in
  http_solver default_writef

let dns_solver writef =
  let name = "dns-01" in
  let get_dns01_challenge =
    let is_dns01 c = match Json.string_member "type" c with
      | Ok x when x = "dns-01" -> true
      | _ -> false
    in
    get_challenge is_dns01
  in
  let solve_dns01_challenge sleep cli challenge domain =
    let token = challenge.token in
    let pk = Primitives.pub_of_priv cli.account_key in
    let thumbprint = Jwk.thumbprint (`Rsa pk) in
    let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
    let solution = Primitives.sha256 key_authorization |> B64u.urlencode in
    writef domain solution >>= function
    | Ok () -> sleep () >|= fun () -> Ok ()
    | Error e -> Lwt.return (Error e)
  in
  {
    name = name ;
    get_challenge = get_dns01_challenge ;
    solve_challenge = solve_dns01_challenge
  }

let default_dns_solver ?proto id now out ?recv ~keyname key ~zone =
  let open Dns in
  let nsupdate host record =
    let name = Domain_name.prepend_label_exn host "_acme-challenge" in
    let zone = Packet.Question.create zone Rr_map.Soa
    and update =
      let up =
        Domain_name.Map.singleton name
          [
            Packet.Update.Remove (Rr_map.K Txt) ;
            Packet.Update.Add Rr_map.(B (Txt, (3600l, Txt_set.singleton record)))
      ]
      in
      (Domain_name.Map.empty, up)
    and header = (id, Packet.Flags.empty)
    in
    let packet = Packet.create header zone (`Update update) in
    match Dns_tsig.encode_and_sign ?proto packet now key keyname with
    | Error s -> Lwt.return_error (`Msg (Fmt.to_to_string Dns_tsig.pp_s s))
    | Ok (data, mac) ->
      out data >>= function
      | Error err -> Lwt.return_error err
      | Ok () ->
        match recv with
        | None -> Lwt.return_ok ()
        | Some recv -> recv () >|= function
          | Error e -> Error e
          | Ok data ->
            match Dns_tsig.decode_and_verify now key keyname ~mac data with
            | Error e -> Error (`Msg (Fmt.strf "decode and verify error %a" Dns_tsig.pp_e e))
            | Ok (res, _, _) ->
              match Packet.reply_matches_request ~request:packet res with
              | Ok _ -> Ok ()
              | Error mismatch ->
                Error (`Msg (Fmt.strf "error %a expected reply to %a, got %a"
                               Packet.pp_mismatch mismatch
                               Packet.pp packet Packet.pp res))
  in
  dns_solver nsupdate

module Make (Client : Cohttp_lwt.S.Client) = struct

let http_get ?ctx url =
  Client.get ?ctx url >>= fun (resp, body) ->
  let code = resp |> Cohttp.Response.status |> Cohttp.Code.code_of_status in
  let headers = resp |> Cohttp.Response.headers in
  body |> Cohttp_lwt.Body.to_string >>= fun body ->
  Logs.debug (fun m -> m "HTTP get: %a" Uri.pp_hum url);
  Logs.debug (fun m -> m "Got code: %d" code);
  Logs.debug (fun m -> m "headers \"%s\"" (Cohttp.Header.to_string headers));
  Logs.debug (fun m -> m "body \"%s\"" (String.escaped body));
  Lwt.return (code, headers, body)

let discover ?ctx directory =
  http_get ?ctx directory >|= fun (_code, headers, body) ->
  let open Rresult.R.Infix in
  extract_nonce headers >>= fun nonce ->
  Json.of_string body >>= fun edir ->
  let p m = Json.string_member m edir in
  p "new-authz" >>= fun new_authz ->
  p "new-reg" >>= fun new_reg ->
  p "new-cert" >>= fun new_cert ->
  p "revoke-cert" >>= fun revoke_cert ->
  let u = Uri.of_string in
  let directory_t = {
    directory = directory;
    new_authz = u new_authz;
    new_reg = u new_reg;
    new_cert = u new_cert;
    revoke_cert = u revoke_cert }
  in
  Ok (nonce, directory_t)

let rec http_post_jws ?ctx cli data url =
  let prepare_post key nonce data =
    let body = Jws.encode key data nonce in
    let body_len = string_of_int (String.length body) in
    let header = Cohttp.Header.init () in
    let header = Cohttp.Header.add header "Content-Length" body_len in
    (header, body)
  in
  let headers, body = prepare_post cli.account_key cli.next_nonce data in
  Logs.debug (fun m -> m "HTTP post %a (data %s body %s)"
                 Uri.pp_hum url data (String.escaped body));
  let body = Cohttp_lwt.Body.of_string body in
  Client.post ?ctx ~body ~headers url >>= fun (resp, body) ->
  let code = resp |> Cohttp.Response.status |> Cohttp.Code.code_of_status in
  let headers = resp |> Cohttp.Response.headers in
  body |> Cohttp_lwt.Body.to_string >>= fun body ->
  Logs.debug (fun m -> m "Got code: %d" code);
  Logs.debug (fun m -> m "headers \"%s\"" (Cohttp.Header.to_string headers));
  Logs.debug (fun m -> m "body \"%s\"" (String.escaped body));
  match extract_nonce headers with
  | Error e -> Lwt.return_error e
  | Ok next_nonce ->
    (* XXX: is this like cheating? *)
    cli.next_nonce <- next_nonce;
    match code with
    | 400 when bad_nonce body ->
      Logs.warn (fun m -> m "received bad nonce (and a fresh nonce), retrying same request");
      http_post_jws ?ctx cli data url
    | _ -> Lwt.return_ok (code, headers, body)

let get_terms_of_service links =
  try Some (List.find
              (fun (link : Cohttp.Link.t) ->
                 link.Cohttp.Link.arc.Cohttp.Link.Arc.relation =
                 [Cohttp.Link.Rel.extension (Uri.of_string "terms-of-service")])
              links)
  with Not_found -> None

let new_reg ?ctx cli =
  let url = cli.d.new_reg in
  let body = {|{"resource": "new-reg"}|} in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (code, headers, body) ->
    match code with
    | 201 ->
      begin match Cohttp.Header.get_location headers with
        | Some accept_url ->
          begin match Cohttp.Header.get_links headers |> get_terms_of_service with
            | Some terms ->
              Logs.info (fun m -> m "Must accept terms.");
              Ok (Some (terms, accept_url))
            | None -> Error (`Msg "Accept url without terms-of-service")
          end
        | None ->
          Logs.info (fun m -> m "Account created.");
          Ok None
      end
    | 409 ->
      Logs.info (fun m -> m "Already registered.");
      Ok None
    | _ -> error_in "new-reg" code body

let accept_terms ?ctx cli ~url ~terms =
  let body =
    Json.to_string (`Assoc [
        ("resource", `String "reg");
        ("agreement", `String (Uri.to_string terms));
      ])
  in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (code, _headers, body) ->
    match code with
    | 202 -> Logs.info (fun m -> m "Terms accepted."); Ok ()
    | 409 -> Logs.info (fun m -> m "Already registered."); Ok ()
    | _ -> error_in "accept_terms" code body

let new_authz ?ctx cli domain get_challenge =
  let url = cli.d.new_authz in
  let body = Printf.sprintf
      {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
      (Domain_name.to_string domain)
  in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (code, _headers, body) ->
    let open Rresult.R.Infix in
    match code with
    | 201 ->
      Json.of_string body >>= fun authorization ->
      get_challenge authorization
    (* XXX. any other codes to handle? *)
    | _ -> error_in "new-authz" code body

let challenge_met ?ctx cli ct challenge =
  let token = challenge.token in
  let pub = Primitives.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint (`Rsa pub) in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  (*
   XXX. that's weird: the standard (page 40, rev. 5) specifies only a "type" and
   a "keyAuthorization" key in order to inform the CA of the accomplished
   challenge.
   However, following that I got

   "urn:acme:error:malformed",
   "detail": "Request payload does not specify a resource",
   "status": 400

   while specifying "challenge": type I am able to proceed.
   **)
  let data = Printf.sprintf
      {|{"resource": "challenge", "type": "%s", "keyAuthorization": "%s"}|}
      ct key_authorization
  in
  http_post_jws ?ctx cli data challenge.url >>= fun _ ->
  (* XXX. here we should deal with the resulting codes, at least. *)
  Lwt.return_ok ()


let poll_challenge_status ?ctx cli challenge =
  http_get ?ctx challenge.url >|= fun (code, headers, body) ->
  (match extract_nonce headers with
   | Error _ -> ()
   | Ok nonce -> cli.next_nonce <- nonce) ;
  let open Rresult.R.Infix in
  Json.of_string body >>= fun challenge_status ->
  match Json.string_member "status" challenge_status with
  | Ok "valid" -> Ok false
  (* «If this field is missing, then the default value is "pending".» *)
  | Ok "pending" | Error _ -> Ok true
  | Ok status -> error_in ("polling " ^ status) code body

let rec poll_until ?ctx sleep cli challenge =
  poll_challenge_status ?ctx cli challenge >>= function
  | Error e  -> Lwt.return_error e
  | Ok false -> Lwt.return_ok ()
  | Ok true  ->
    Logs.info (fun m -> m "Polling...");
    sleep () >>= fun () ->
    poll_until ?ctx sleep cli challenge

let body_to_certificate der =
  let der = Cstruct.of_string der in
  match X509.Certificate.decode_der der with
  | Ok crt -> Ok crt
  | Error (`Msg e) ->
    Error (`Msg ("I got gibberish while trying to decode the new certificate: " ^ e))

let new_cert ?ctx cli csr =
  let url = cli.d.new_cert in
  let der = X509.Signing_request.encode_der csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  http_post_jws ?ctx cli data url >|= function
  | Error e -> Error e
  | Ok (code, _headers, body) ->
    match code with
    | 201 -> body_to_certificate body
    | _ -> error_in "new-cert" code body

let sign_certificate ?ctx ?(solver = default_http_solver) cli sleep csr =
  let open Lwt_result.Infix in
  (* for all domains, ask the ACME server for a certificate *)
  X509.Certificate.Host_set.fold
    (fun (typ, name) r ->
       r >>= fun () ->
       match typ with
       | `Strict ->
         new_authz ?ctx cli name solver.get_challenge >>= fun challenge ->
         solver.solve_challenge sleep cli challenge name >>= fun () ->
         challenge_met ?ctx cli solver.name challenge >>= fun () ->
         poll_until ?ctx sleep cli challenge
       | `Wildcard ->
         Lwt.return (Error (`Msg "wildcard hostnames are not supported")))
    (X509.Signing_request.hostnames csr) (Lwt.return (Ok ())) >>= fun () ->
  new_cert ?ctx cli csr >>= fun pem ->
  Lwt.return_ok pem

let initialise ?ctx ?(directory = letsencrypt_url) account_key =
  let open Lwt_result.Infix in
  (* create a new client *)
  discover ?ctx directory >>= fun (next_nonce, d) ->
  let cli = { next_nonce ; d ; account_key } in

  (* if the client didn't register, then register. Otherwise proceed *)
  new_reg ?ctx cli >>= function
  | Some (terms_link, accept_url) ->
    let terms = terms_link.Cohttp.Link.target in
    Logs.info (fun f -> f "Accepting terms at %s\n" (Uri.to_string terms));
    accept_terms ?ctx cli ~url:accept_url ~terms >>= fun () ->
    Lwt.return_ok cli
  | None ->
    Logs.info (fun f -> f "No ToS.");
    Lwt.return_ok cli
end
