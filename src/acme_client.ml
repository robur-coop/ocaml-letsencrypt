open Lwt.Infix

open Acme_common

module Pem = X509.Encoding.Pem

type t = {
  account_key : Nocrypto.Rsa.priv ;
  csr :  X509.CA.signing_request ;
  mutable next_nonce : string ;
  d : directory_t ;
}

type challenge_t = {
  url : Uri.t ;
  token : string ;
}

type solver_t = {
  name : string ;
  get_challenge : Json.t -> (challenge_t, string) Result.result ;
  solve_challenge : t -> challenge_t -> string -> (unit, string) Result.result Lwt.t ;
}

let error_in endpoint code body =
  let body = String.escaped body in
  Error (Printf.sprintf "Error at %s: code %d - body: %s" endpoint code body)

let extract_nonce headers =
  match Cohttp.Header.get headers "Replay-Nonce" with
  | Some nonce -> Ok nonce
  | None -> Error "Error: I could not fetch a new nonce."

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
  | [] -> Error "No supported challenges found."
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
  let solve_http01_challenge cli challenge domain =
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
    Logs.info (fun f -> f "Domain %s wants file %s content %s\n" domain file content);
    read_line ()
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
  let solve_dns01_challenge cli challenge domain =
    let token = challenge.token in
    let pk = Primitives.pub_of_priv cli.account_key in
    let thumbprint = Jwk.thumbprint (`Rsa pk) in
    let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
    let solution = Primitives.sha256 key_authorization |> B64u.urlencode in
    writef domain solution
  in
  {
    name = name ;
    get_challenge = get_dns01_challenge ;
    solve_challenge = solve_dns01_challenge
  }

let default_dns_solver now out keyname key =
  let nsupdate host record =
    let name = Dns_name.prepend_exn ~hostname:false (Dns_name.of_string_exn host) "_acme-challenge" in
    let nsupdate =
      let q_name =
        let a = Dns_name.to_array keyname in
        Dns_name.of_array (Array.sub a 0 (Array.length a - 2))
      in
      let zone = { Dns_packet.q_name ; q_type = Dns_enum.SOA }
      and update = [
        Dns_packet.Remove (name, Dns_enum.TXT) ;
        Dns_packet.Add ({ Dns_packet.name ; ttl = 3600l ; rdata = Dns_packet.TXT [ record ] })
      ]
      in
      { Dns_packet.zone ; prereq = [] ; update ; addition = [] }
    and header = { Dns_packet.id = 0xDEAD ; query = true ; operation = Dns_enum.Update ;
                   authoritative = false ; truncation = false ; recursion_desired = false ;
                   recursion_available = false ; authentic_data = false ; checking_disabled = false ;
                   rcode = Dns_enum.NoError }
    in
    let b, _ = Dns_packet.encode `Udp (header, `Update nsupdate) in
    match Dns_packet.dnskey_to_tsig_algo key with
    | None -> Lwt.return_error "cannot discover tsig algorithm of key"
    | Some algorithm ->
      match Dns_packet.tsig ~algorithm ~signed:now () with
      | None -> Lwt.return_error "couldn't create tsig"
      | Some tsig ->
        match Dns_tsig.sign keyname ~key tsig b with
        | None -> Lwt.return_error "key is not good"
        | Some (b, _) -> out b
  in
  dns_solver nsupdate

module Make (Client : Cohttp_lwt.S.Client) = struct

let http_get url =
  Client.get url >>= fun (resp, body) ->
  let code = resp |> Cohttp.Response.status |> Cohttp.Code.code_of_status in
  let headers = resp |> Cohttp.Response.headers in
  body |> Cohttp_lwt.Body.to_string >>= fun body ->
  Logs.debug (fun m -> m "HTTP get: %a" Uri.pp_hum url);
  Logs.debug (fun m -> m "Got code: %d" code);
  Logs.debug (fun m -> m "headers \"%s\"" (Cohttp.Header.to_string headers));
  Logs.debug (fun m -> m "body \"%s\"" (String.escaped body));
  Lwt.return (code, headers, body)

let discover directory =
  http_get directory >|= fun (code, headers, body) ->
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

let new_cli directory rsa_pem csr_pem =
  match
    let open Rresult.R.Infix in
    Primitives.priv_of_pem rsa_pem >>= fun account_key ->
    (try Ok (Pem.Certificate_signing_request.of_pem_cstruct1 (Cstruct.of_string csr_pem))
     with Invalid_argument i -> Error i) >>= fun csr ->
    Ok (account_key, csr)
  with
  | Error e -> Lwt.return_error e
  | Ok (account_key, csr) ->
    let open Lwt.Infix in
    discover directory >>= function
    | Error e -> Lwt.return_error e
    | Ok (next_nonce, d)  -> Lwt.return_ok { account_key ; csr ; next_nonce ; d }

let http_post_jws cli data url =
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
  Client.post ~body ~headers url >>= fun (resp, body) ->
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
    Lwt.return_ok (code, headers, body)

let get_terms_of_service links =
  try Some (List.find
              (fun (link : Cohttp.Link.t) ->
                 link.Cohttp.Link.arc.Cohttp.Link.Arc.relation =
                 [Cohttp.Link.Rel.extension (Uri.of_string "terms-of-service")])
              links)
  with Not_found -> None

let new_reg cli =
  let url = cli.d.new_reg in
  let body = {|{"resource": "new-reg"}|} in
  http_post_jws cli body url >|= function
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
            | None -> Error "Accept url without terms-of-service"
          end
        | None ->
          Logs.info (fun m -> m "Account created.");
          Ok None
      end
    | 409 ->
      Logs.info (fun m -> m "Already registered.");
      Ok None
    | _ -> error_in "new-reg" code body

let accept_terms cli ~url ~terms =
  let body =
    Json.to_string (`Assoc [
        ("resource", `String "reg");
        ("agreement", `String (Uri.to_string terms));
      ])
  in
  http_post_jws cli body url >|= function
  | Error e -> Error e
  | Ok (code, headers, body) ->
    match code with
    | 202 -> Logs.info (fun m -> m "Terms accepted."); Ok ()
    | 409 -> Logs.info (fun m -> m "Already registered."); Ok ()
    | _ -> error_in "accept_terms" code body

let new_authz cli domain get_challenge =
  let url = cli.d.new_authz in
  let body = Printf.sprintf
      {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
      domain
  in
  http_post_jws cli body url >|= function
  | Error e -> Error e
  | Ok (code, headers, body) ->
    let open Rresult.R.Infix in
    match code with
    | 201 ->
      Json.of_string body >>= fun authorization ->
      get_challenge authorization
    (* XXX. any other codes to handle? *)
    | _ -> error_in "new-authz" code body

let challenge_met cli ct challenge =
  let token = challenge.token in
  let pub = Primitives.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint (`Rsa pub) in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  (**
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
  http_post_jws cli data challenge.url >>= fun _ ->
  (* XXX. here we should deal with the resulting codes, at least. *)
  Lwt.return_ok ()


let poll_challenge_status cli challenge =
  http_get challenge.url >|= fun (code, headers, body) ->
  let open Rresult.R.Infix in
  Json.of_string body >>= fun challenge_status ->
  match Json.string_member "status" challenge_status with
  | Ok "valid" -> Ok false
  (* «If this field is missing, then the default value is "pending".» *)
  | Ok "pending" | Error _ -> Ok true
  | Ok status -> error_in ("polling " ^ status) code body

let rec poll_until sleep cli challenge =
  poll_challenge_status cli challenge >>= function
  | Error e  -> Lwt.return_error e
  | Ok false -> Lwt.return_ok ()
  | Ok true  ->
    Logs.info (fun m -> m "Polling...");
    sleep () >>= fun () ->
    poll_until sleep cli challenge

let der_to_pem der =
  let der = Cstruct.of_string der in
  match X509.Encoding.parse der with
  | Some crt -> Ok (Pem.Certificate.to_pem_cstruct [crt] |> Cstruct.to_string)
  | None -> Error "I got gibberish while trying to decode the new certificate."

let new_cert cli =
  let url = cli.d.new_cert in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  http_post_jws cli data url >|= function
  | Error e -> Error e
  | Ok (code, headers, body) ->
    match code with
    | 201 -> der_to_pem body
    | _ -> error_in "new-cert" code body

let get_crt ?(directory = letsencrypt_url) ?(solver = default_http_solver) sleep rsa_pem csr_pem =
  let open Lwt_result.Infix in
  (* create a new client *)
  new_cli directory rsa_pem csr_pem >>= fun cli ->

  (* if the client didn't register, then register. Otherwise proceed *)
  new_reg cli >>= (function
      | Some (terms_link, accept_url) ->
        let terms = terms_link.Cohttp.Link.target in
        Logs.info (fun f -> f "Accepting terms at %s\n" (Uri.to_string terms));
        accept_terms cli ~url:accept_url ~terms
      | None ->
        Logs.info (fun f -> f "No ToS.");
        Lwt.return_ok ())
    >>= fun () ->

    (* for all domains, ask the ACME server for a certificate *)
    let csr = Pem.Certificate_signing_request.of_pem_cstruct1 (Cstruct.of_string csr_pem) in
    let domains = domains_of_csr csr in
    Lwt_list.fold_left_s
      (fun r domain ->
         match r with
         | Ok () ->
           new_authz cli domain solver.get_challenge >>= fun challenge ->
           solver.solve_challenge cli challenge domain >>= fun () ->
           challenge_met cli solver.name challenge >>= fun () ->
           poll_until sleep cli challenge
         | Error r -> Lwt.return_error r)
      (Ok ()) domains >>= fun () ->
      new_cert cli >>= fun pem ->
      Lwt.return_ok pem
end
