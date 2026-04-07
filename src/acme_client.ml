open Acme_common

let src = Logs.Src.create "letsencrypt" ~doc:"let's encrypt library"
module Log = (val Logs.src_log src : Logs.LOG)

let ( let* ) = Result.bind

let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let key_authorization key token =
  let pk = X509.Private_key.public key in
  let pk = Jws.Jwk.of_public_key_exn pk in
  Fmt.str "%s.%s" token (Jws.Jwk.signature pk)

type t = {
  account_key : X509.Private_key.t;
  mutable next_nonce : string;
  d : Directory.t;
  account_url : string;
}

type challenge = Challenge.typ = DNS | HTTP | ALPN | Unknown of string

module type S = sig
  type 'a t

  val bind : 'a t -> ('a -> 'b t) -> 'b t
  val return : 'a -> 'a t
end

module type Client = sig
  type 'a t
  type ctx
  type error
  type meth = [ `HEAD | `GET | `POST ]

  type response =
    { headers : (string * string) list
    ; status : int }

  val request : ?ctx:ctx -> ?meth:meth -> ?headers:(string * string) list -> ?body:string -> string -> (response * string, error) result t
end

module Solver (S : S) = struct
type solver = {
  challenge : challenge;
  solve_challenge : token:string -> key_authorization:string ->
    [`host] Domain_name.t -> (unit, [ `Msg of string]) result S.t;
}

let http_solver writef =
  let solve_challenge ~token ~key_authorization domain =
    let prefix = ".well-known/acme-challenge" in
    writef domain ~prefix ~token ~content:key_authorization
  in
  { challenge = HTTP; solve_challenge }

let print_http =
  let solve domain ~prefix ~token ~content =
    Log.warn (fun f -> f "Setup http://%a/%s/%s to serve %s and press enter to continue"
                 Domain_name.pp domain prefix token content);
    ignore (read_line ());
    S.return (Ok ())
  in
  http_solver solve

let alpn_solver ?(key_type = `RSA) ?(bits = 2048) writef =
  (* on the ID-PE arc (from RFC 5280), 31 *)
  let id_pe_acme = Asn.OID.(base 1 3 <| 6 <| 1 <| 5 <| 5 <| 7 <| 1 <| 31)
  and alpn = "acme-tls/1"
  in
  (* extension value is an octet_string of the hash *)
  let encode_val hash =
    let enc = Asn.(encode (codec der S.octet_string)) in
    enc hash
  in
  let solve_challenge ~token:_ ~key_authorization domain =
    let open X509 in
    let priv = Private_key.generate ~bits key_type in
    let solution = Digestif.SHA256.digest_string key_authorization in
    let solution = Digestif.SHA256.to_raw_string solution in
    let name = Domain_name.to_string domain in
    let cn = Distinguished_name.CN name in
    let dn = [ Distinguished_name.Relative_distinguished_name.singleton cn ] in
    let extensions =
      let gn = General_name.(singleton DNS [ name ]) in
      let full = encode_val solution in
      Extension.(add Subject_alt_name (false, gn)
                   (singleton (Unsupported id_pe_acme) (true, full)))
    in
    let valid_from, valid_until = Ptime.epoch, Ptime.epoch in
    match
      let* csr = Signing_request.create dn priv in
      Result.map_error
        (fun e -> `Msg (Fmt.to_to_string X509.Validation.pp_signature_error e))
        (Signing_request.sign csr ~valid_from ~valid_until ~extensions priv dn)
    with
    | Ok cert -> writef domain ~alpn priv cert
    | Error _ as e -> S.return e
  in
  { challenge = ALPN; solve_challenge }

let print_alpn =
  let solve domain ~alpn priv cert =
    Log.warn (fun f -> f "Setup a TLS server for %a (ALPN %s) to use key %s and certificate %s. Press enter to continue"
                 Domain_name.pp domain alpn
                 (X509.Private_key.encode_pem priv)
                 (X509.Certificate.encode_pem cert));
    ignore (read_line ());
    S.return (Ok ())
  in
  alpn_solver solve
end

module Make (S : S) (C : Client with type 'a t = 'a S.t) = struct
include Solver (S)

let ( let* ) x fn =
  S.bind x @@ function
  | Error _ as err -> S.return err
  | Ok v -> fn v

let ( >>= ) = S.bind

let error_msgf fmt = Fmt.kstr (fun msg -> S.return (Error (`Msg msg))) fmt
let ok v = S.return (Ok v)
let guard ~err fn = if fn () then ok () else S.return (Error err)

let location r =
  let fn (k, v) = String.lowercase_ascii k, v in
  let hdrs = List.map fn r.C.headers in
  match List.assoc_opt "location" hdrs with
  | Some url -> ok url
  | None -> error_msgf "Expected a location header, but couldn't find it"

let request ?ctx ?meth ?headers ?body url =
  C.request ?ctx ?meth ?headers ?body url >>= function
  | Ok value -> ok value
  | Error err -> S.return (Error (`HTTP err))

let extract_nonce r =
  let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) r.C.headers in
  match List.assoc_opt "replay-nonce" hdrs with
  | Some nonce -> ok nonce
  | None -> error_msgf "Nonce not found"

let discover ?ctx directory =
  let* resp, body = request ?ctx ~meth:`GET directory in
  match resp.C.status with
  | 200 -> S.return (Directory.decode body)
  | c -> error_msgf
           "Impossible to discover your ACME service: status %u - body: %S"
           c body

let get_nonce ?ctx url =
  let* r, body = request ?ctx ~meth:`HEAD url in
  match r.C.status with
  | 200 -> extract_nonce r
  | c -> error_msgf
           "Invalid response from HEAD request to %s, status: %u - body %S"
           url c body

let rec post ?ctx ?(with_kid = false) cli data url =
  let prepare key nonce =
    let kid = if with_kid then None else Some cli.account_url in
    let extra = Jws.S.singleton "url" (Jsont.Json.string url) in
    let key = Jws.Pk.of_private_key_exn key in
    let data = Jsont_bytesrw.encode_string Jsont.json data |> Result.get_ok in
    let body = Jws.encode ?kid ~extra ~nonce key data in
    let headers =
      [ "Content-Type", "application/jose+json"
      ; "Content-Length", string_of_int (String.length body) ] in
    (headers, body)
  in
  let headers, body = prepare cli.account_key cli.next_nonce in
  Log.debug (fun m -> m "HTTP post %s (data %a body %S)"
                url Jsont.Json.pp data body);
  let* resp, body = request ?ctx ~meth:`POST ~body ~headers url in
  Log.debug (fun m -> m "Got code: %3d" resp.C.status);
  Log.debug (fun m -> m "headers %a" Fmt.(Dump.list (pair string string)) resp.C.headers);
  Log.debug (fun m -> m "body %S" body);
  let* () =
    extract_nonce resp >>= function
    | Ok nonce -> cli.next_nonce <- nonce; ok ()
    | Error (`Msg msg) ->
        Log.err (fun m -> m "Couldn't extract nonce: %s" msg);
        ok () in
  match resp.C.status with
  | 400 ->
      let* err = S.return (Error.decode body) in
      begin match err.Error.error with
      | `Bad_nonce ->
          Log.warn (fun m -> m "received bad nonce %s from server, retrying same request"
                       err.detail);
          post ?ctx cli data url
      | _ -> ok (resp, body) end
  | _ -> ok (resp, body)

let create_account ?ctx ?email cli =
  let url = cli.d.newAccount in
  let contact = match email with
    | None -> []
    | Some email ->
        let open Jsont.Json in
        [ mem (name "contact") (list [string ("mailto:" ^ email)]) ]
  in
  let body =
    let open Jsont.Json in
    object' (mem (name "termsOfServiceAgreed") (bool true) :: contact) in
  let* resp, body = post ?ctx ~with_kid:true cli body url in
  match resp.C.status with
  | 201 ->
    let* account = Account.decode body |> S.return in
    let* () =
      let err = msgf "Account %a does not have status valid" Account.pp account in
      guard ~err @@ fun () -> (account.Account.status = Account.Valid)
    in
    let* account_url = location resp in
    ok { cli with account_url }
  | c -> error_msgf "Invalid response to newAccount, status: %u - body %S"
           c body

let get_account ?ctx cli url =
  let* resp, body = post ?ctx cli Jsont.Json.(null ()) url in
  match resp.C.status with
  | 200 ->
    (* at least staging doesn't include orders *)
    let* acc = S.return (Account.decode body) in
    (* well, here we may encounter some orders which should be processed
       (or cancelled, considering the lack of a csr)! *)
    Log.info (fun m -> m "account %a" Account.pp acc);
    ok ()
  | c -> error_msgf "Invalid response to get_account, status: %u - body %S"
           c body

let find_account_url ?ctx ?email ~nonce key directory =
  let url = directory.Directory.newAccount in
  let body =
    let open Jsont.Json in
    object' [ mem (name "onlyReturnExisting") (bool true) ] in
  let cli =
    { next_nonce = nonce
    ; account_key = key
    ; d= directory
    ; account_url = String.empty } in
  let* resp, body = post ?ctx ~with_kid:false cli body url in
  match resp.C.status with
  | 200 ->
    (* unclear why this is not an account object, as required in 7.3.0/7.3.1 *)
    let* account = S.return (Account.decode body) in
    let* () =
      let err = msgf "Account %a does not have status valid" Account.pp account in
      guard ~err @@ fun () -> account.Account.status = Account.Valid in
    let* account_url = location resp in
    ok { cli with account_url }
  | 400 ->
    let* err = S.return (Error.decode body) in
    if err.Error.error = `Account_does_not_exist then begin
      Log.info (fun m -> m "account does not exist, creating an account");
      create_account ?ctx ?email cli
    end else begin
      Log.err (fun m -> m "error %a in find account url" Error.pp err);
      error_msgf "newAccount: %s" err.Error.detail
    end
  (* according to RFC 8555 7.3.3 there can be a forbidden if ToS were updated,
     and the client should re-approve them *)
  | status -> error_msgf "find_account_url: unexpected status %u - body %S" status body

let challenge_solved ?ctx cli url =
  let body = Jsont.Json.(object' []) in (* not entirely clear why this now is {} and not "" *)
  let* resp, body = post ?ctx cli body url in
  match resp.C.status with
  | 200 ->
    Log.info (fun m -> m "challenge solved POSTed (OK), body %s" body);
    ok ()
  | 201 ->
    Log.info (fun m -> m "challenge solved POSTed (CREATE), body %s" body);
    ok ()
  | status -> error_msgf "challenge solved: status %u - body: %S" status body

let process_challenge ?ctx solver cli sleep host challenge =
  (* overall plan:
     - solve it (including "provisioning" - for now maybe a sleep 5)
     - report back to server that it is now solved
  *)
  (* good news is that we already ensured that the solver and challenge fit *)
  match challenge.Challenge.status with
  | Pending ->
    (* do some work :) solve it! *)
    let token = challenge.token in
    let key_authorization = key_authorization cli.account_key token in
    let* () =
      S.bind (solver.solve_challenge ~token ~key_authorization host) @@ function
      | (Ok _) as r -> S.return r
      | Error (`Msg _) as r -> S.return r in
    challenge_solved ?ctx cli challenge.url
  | Processing -> (* ehm - relax and wait till the server figured something out? *)
    (* but there's as well the notion of "Likewise, client requests for retries do not cause a state change." *)
    (* it looks like in processing after some _client_defined_timeout_, the client may approach to server to re-evaluate *)

    (* from Section 8.2 *)
    (* While the server is
       still trying, the status of the challenge remains "processing"; it is
       only marked "invalid" once the server has given up.

       The server MUST provide information about its retry state to the
       client via the "error" field in the challenge and the Retry-After
       HTTP header field in response to requests to the challenge resource.
       The server MUST add an entry to the "error" field in the challenge
       after each failed validation query.  The server SHOULD set the Retry-
       After header field to a time after the server's next validation
       query, since the status of the challenge will not change until that
       time.

       Clients can explicitly request a retry by re-sending their response
       to a challenge in a new POST request (with a new nonce, etc.).  This
       allows clients to request a retry when the state has changed (e.g.,
       after firewall rules have been updated).  Servers SHOULD retry a
       request immediately on receiving such a POST request.  In order to
       avoid denial-of-service attacks via client-initiated retries, servers
       SHOULD rate-limit such requests.
    *)
    (* so what shall we do? wait? *)
    Log.info (fun m -> m "challenge is processing, let's wait a second");
    sleep 1 >>= fun () -> ok ()
  | Valid -> (* nothing to do from our side *)
    ok ()
  | Invalid -> (* we lost *)
    S.return (Error (`Msg "challenge invalid"))

(* yeah, we could parallelize them... but first not do it. *)

let process_authorization ?ctx solver cli sleep url =
  let body = Jsont.Json.(null ()) in
  let* resp, body = post ?ctx cli body url in
  match resp.C.status with
  | 200 ->
      let* auth = S.return (Authorization.decode body) in
      Log.info (fun m -> m "authorization %a" Authorization.pp auth);
      begin match auth.Authorization.status with
      | Pending -> (* we need to work on some challenge here! *)
        let host = Domain_name.(host_exn @@ of_string_exn @@ auth.identifier) in
        begin match List.filter (fun c -> c.Challenge.typ = solver.challenge) auth.challenges with
          | [] ->
            Log.err (fun m -> m "no challenge found for solver");
            S.return (Error (`Msg "couldn't find a challenge that matches the provided solver"))
          | c::cs ->
            if not (cs = []) then
              Log.err (fun m -> m "multiple (%d) challenges found for solver, taking head"
                          (succ (List.length cs)));
            process_challenge ?ctx solver cli sleep host c
        end
      | Valid -> (* we can ignore it - some challenge made it *)
        Log.info (fun m -> m "authorization is valid");
        ok ()
      | Invalid -> (* no chance this will ever be good again, or is there? *)
        Log.err (fun m -> m "authorization is invalid");
        S.return (Error (`Msg "invalid"))
      | Deactivated -> (* client-side deactivated / retracted *)
        Log.err (fun m -> m "authorization is deactivated");
        S.return (Error (`Msg "deactivated"))
      | Expired -> (* timeout *)
        Log.err (fun m -> m "authorization is expired");
        S.return (Error (`Msg "expired"))
      | Revoked -> (* server-side deactivated *)
        Log.err (fun m -> m "authorization is revoked");
        S.return (Error (`Msg "revoked"))
      end
  | status -> error_msgf "authorization: status %u - body: %S" status body

let finalize ?ctx cli csr url =
  let body =
    let csr_as_b64 =
      X509.Signing_request.encode_der csr |> Jws.Base64u.encode in
    let open Jsont.Json in
    object' [ mem (name "csr") (string csr_as_b64) ] in
  let* resp, body = post ?ctx cli body url in
  match resp.C.status with
  | 200 ->
    let* order = S.return (Order.decode body) in
    ok (resp.C.headers, order)
  | status -> error_msgf "finalize: status %u - body: %S" status body

let dl_certificate ?ctx cli url =
  let body = Jsont.Json.(null ()) in
  let* resp, body = post ?ctx cli body url in
  match resp.C.status with
  | 200 ->
    (* body is a certificate chain (no comments), with end-entity certificate being the first *)
    (* TODO: check order? figure out chain? *)
    S.return (X509.Certificate.decode_pem_multiple body)
  | status -> error_msgf "certificate: status %u - body: %S" status body

let get_order ?ctx cli url =
  let body = Jsont.Json.(null ()) in
  let* resp, body = post ?ctx cli body url in
  match resp.C.status with
  | 200 ->
    let* order = Order.decode body |> S.return in
    ok (resp.C.headers, order)
  | status -> error_msgf "getting order: status %u - body: %S" status body

(* HTTP defines this header as "either seconds" or "absolute HTTP date" *)
let retry_after headers =
  let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) headers in
  match List.assoc_opt "retry-after" hdrs with
  | None -> 1
  | Some x -> try int_of_string x with
      Failure _ ->
      Log.warn (fun m -> m "retry-after header is not an integer, but %s (using 1 second instead)" x);
      1
(* TODO this 'expires' stuff in the order *)
(* state machine is slightly unclear, from section 7.4 (page 47 top):
   "Once the client believes it has fulfilled the server's requirements,
   it should send a POST request to the order resource's finalize URL"
   does this mean e.g. retry-after should as well be done to the finalize URL?
   (rather than the order URL)

   page 48 says:
   "A request to finalize an order will result in error if the order is
   not in the "ready" state.  In such cases, the server MUST return a
   403 (Forbidden) error with a problem document of type
   "orderNotReady".  The client should then send a POST-as-GET request
   to the order resource to obtain its current state."

   and also
   "If a request to finalize an order is successful, the server will
   return a 200 (OK) with an updated order object.  The status of the
   order will indicate what action the client should take"

   so basically the "order" object returned by finalize is only every in
   "processing" or "pending", or do I misunderstand anything?
   if it is in a different state, a 403 would've been issued (not telling
   what is wrong) - with orderNotReady; if the CSR is bad, some unspecified
   HTTP status is returned, with "badCSR" as error code. how convenient.
*)
let rec process_order ?ctx solver cli sleep csr order_url headers order =
  (* as usual, first do the easy stuff ;) *)
  match order.Order.status with
  | Invalid ->
    (* exterminate -- consider the order process abandoned *)
    Log.err (fun m -> m "order %a is invalid, falling apart" Order.pp order);
    S.return (Error (`Msg "attempting to process an invalid order"))
  | Pending ->
    (* there's still some authorization pending, according to the server! *)
    Log.warn (fun m -> m "something is pending here... need to work on this");
    let rec fold = function
      | [] -> ok ()
      | a :: rest ->
        let* () = process_authorization ?ctx solver cli sleep a in
        fold rest in
    let* () = fold order.authorizations in
    let* headers, order = get_order ?ctx cli order_url in
    process_order ?ctx solver cli sleep csr order_url headers order
  | Ready ->
    (* server agrees that requirements are fulfilled, submit a finalization request *)
    let* headers, order = finalize ?ctx cli csr order.finalize in
    process_order ?ctx solver cli sleep csr order_url headers order
  | Processing ->
    (* sleep Retry-After header field time, and re-get order to hopefully get a certificate url *)
    let retry_after = retry_after headers in
    Log.debug (fun m -> m "sleeping for %d seconds" retry_after);
    sleep retry_after >>= fun () ->
    let* headers, order = get_order ?ctx cli order_url in
    process_order ?ctx solver cli sleep csr order_url headers order
  | Valid ->
    (* the server has issued the certificate and provisioned its URL in the certificate field of the order *)
    match order.certificate with
    | None ->
      Log.warn (fun m -> m "received valid order %a without certificate URL, should not happen" Order.pp order);
      S.return (Error (`Msg "valid order without certificate URL"))
    | Some cert ->
      let* certs = dl_certificate ?ctx cli cert in
      Log.info (fun m -> m "retrieved %d certificates" (List.length certs));
      List.iter (fun c ->
          Log.info (fun m -> m "%s" (X509.Certificate.encode_pem c)))
        certs;
      ok certs

let new_order ?ctx solver cli sleep csr =
  let hostnames =
    X509.Host.Set.fold
      (fun (typ, name) acc ->
         let pre = match typ with `Strict -> "" | `Wildcard -> "*." in
         (pre ^ Domain_name.to_string name) :: acc)
      (X509.Signing_request.hostnames csr) []
  in
  let body =
    (* TODO this may contain "notBefore" and "notAfter" as RFC3339 encoded timestamps
       (what the client would like as validity of the certificate) *)
    let open Jsont.Json in
    let ids =
      List.map (fun hostname ->
          object' [ mem (name "type") (string "dns")
                  ; mem (name "value") (string hostname) ])
        hostnames in
    object' [ mem (name "identifiers") (list ids) ] in
  let* resp, body = post ?ctx cli body cli.d.Directory.newOrder in
  match resp.C.status with
  | 201 ->
    let* order = S.return (Order.decode body) in
    (* identifiers (should-be-verified to be the same set as the hostnames above?) *)
    let* order_url = location resp in
    process_order ?ctx solver cli sleep csr order_url resp.C.headers order
  | status -> error_msgf "newOrder: status %u - body: %S" status body

let sign_certificate ?ctx solver cli sleep csr =
  (* send a newOrder request for all the host names in the CSR *)
  (* but as well need to check that we're able to solve authorizations for the names *)
  new_order ?ctx solver cli sleep csr

let supported_key = function
  | `RSA _ | `P256 _ | `P384 _ | `P521 _ -> Ok ()
  | _ -> Error (`Msg "unsupported key type")

let initialise ?ctx ~endpoint ?email account_key =
  (* create a new client *)
  let* () = S.return (supported_key account_key) in
  let* d = discover ?ctx endpoint in
  Log.info (fun m -> m "discovered directory %a" Directory.pp d);
  let* nonce = get_nonce ?ctx d.Directory.newNonce in
  Log.info (fun m -> m "got nonce %s" nonce);
  (* now there are two ways forward
     - register a new account based on account_key
     - retrieve account URL for account_key (if already registered)
     let's first try the latter -- the former is done by find_account_url if account does not exist!
  *)
  find_account_url ?ctx ?email ~nonce account_key d
end
