open Rresult.R.Infix

let letsencrypt_production_url =
  Uri.of_string "https://acme-v02.api.letsencrypt.org/directory"

let letsencrypt_staging_url =
  Uri.of_string "https://acme-staging-v02.api.letsencrypt.org/directory"

let sha256_and_base64 a =
  Primitives.sha256 a |> B64u.urlencode

module J = Yojson.Basic

type json = J.t

(* Serialize a json object without having spaces around. Dammit Yojson. *)
(* XXX. I didn't pay enough attention on escaping.
 * It is possible that this is okay; however, our encodings are nice. *)
(* NOTE: hannes thinks that Json.to_string (`String {|foo"bar|}) looks suspicious *)
let rec json_to_string ?(comma = ",") ?(colon = ":") : J.t -> string = function
  | `Null -> ""
  | `String s -> Printf.sprintf {|"%s"|} (String.escaped s)
  | `Bool b -> if b then "true" else "false"
  | `Float f -> string_of_float f
  | `Int i -> string_of_int i
  | `List l ->
    let s = List.map (json_to_string ~comma ~colon) l in
    "[" ^ (String.concat comma s) ^ "]"
  | `Assoc a ->
    let serialize_pair (key, value) =
      Printf.sprintf {|"%s"%s%s|} key colon (json_to_string ~comma ~colon value)
    in
    let s = List.map serialize_pair a in
    Printf.sprintf {|{%s}|} (String.concat comma s)

let of_string s =
  try Ok (J.from_string s) with
    Yojson.Json_error str -> Error (`Msg str)

let err_msg typ name json =
  Rresult.R.error_msgf "couldn't find %s %s in %s" typ name (J.to_string json)

(* decoders *)
let string_val key json =
  match J.Util.member key json with
  | `String s -> Ok s
  | _ -> err_msg "string" key json

let opt_string_val key json =
  match J.Util.member key json with
  | `String s -> Ok (Some s)
  | `Null -> Ok None
  | _ -> err_msg "opt_string" key json

let json_val member json =
  match J.Util.member member json with
  | `Assoc j -> Ok (`Assoc j)
  | _ -> err_msg "json object" member json

let b64_z_val member json =
  string_val member json >>= fun s ->
  Rresult.R.open_error_msg (B64u.urldecodez s)

let b64_string_val member json =
  string_val member json >>= fun s ->
  Rresult.R.open_error_msg (B64u.urldecode s)

let assoc_val key json =
  match J.Util.member key json with
  | `Assoc _ | `Null as x -> Ok x
  | _ -> err_msg "assoc" key json

let list_val key json =
  match J.Util.member key json with
  | `List l -> Ok l
  | _ -> err_msg "list" key json

let opt_string_list key json =
  match J.Util.member key json with
  | `List l ->
    let xs =
      List.fold_left
        (fun acc -> function `String s -> s :: acc | _ -> acc)
        [] l
    in
    Ok (Some xs)
  | `Null -> Ok None
  | _ -> err_msg "string list" key json

let opt_bool key json =
  match J.Util.member key json with
  | `Bool b -> Ok (Some b)
  | `Null -> Ok None
  | _ -> err_msg "opt bool" key json

let decode_ptime str =
  match Ptime.of_rfc3339 str with
  | Ok (ts, _, _) -> Ok ts
  | Error `RFC3339 (_, err) ->
    Rresult.R.error_msgf "couldn't parse %s as rfc3339 %a"
      str Ptime.pp_rfc3339_error err

let maybe f = function
  | None -> Ok None
  | Some s -> f s >>| fun s' -> Some s'

module Jwk = struct
  type key = X509.Public_key.t

  let encode = function
    | `RSA key ->
      let e, n = Primitives.pub_to_z key in
      `Assoc [
        "e", `String (B64u.urlencodez e);
        "kty", `String "RSA";
        "n", `String (B64u.urlencodez n);
      ]
    | `P256 key ->
      let cs = Mirage_crypto_ec.P256.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 32 in
      `Assoc [
        "crv", `String "P-256";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | `P384 key ->
      let cs = Mirage_crypto_ec.P384.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 48 in
      `Assoc [
        "crv", `String "P-384";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | `P521 key ->
      let cs = Mirage_crypto_ec.P521.Dsa.pub_to_cstruct key in
      let x, y = Cstruct.split cs ~start:1 66 in
      `Assoc [
        "crv", `String "P-521";
        "kty", `String "EC";
        "x", `String (B64u.urlencode (Cstruct.to_string x));
        "y", `String (B64u.urlencode (Cstruct.to_string y));
      ]
    | _ -> assert false

  let decode_json json =
    string_val "kty" json >>= function
    | "RSA" ->
      b64_z_val "e" json >>= fun e ->
      b64_z_val "n" json >>= fun n ->
      Primitives.pub_of_z ~e ~n >>= fun pub ->
      Ok (`RSA pub)
    | "EC" ->
      let four = Cstruct.create 1 in
      Cstruct.set_uint8 four 0 0x04;
      (b64_string_val "x" json >>| Cstruct.of_string) >>= fun x ->
      (b64_string_val "y" json >>| Cstruct.of_string) >>= fun y ->
      begin string_val "crv" json >>= function
        | "P-256" ->
          Rresult.R.error_to_msg ~pp_error:Mirage_crypto_ec.pp_error
            (Mirage_crypto_ec.P256.Dsa.pub_of_cstruct
               (Cstruct.concat [ four ; x ; y ]))
          >>| fun pub ->
          `P256 pub
        | "P-384" ->
          Rresult.R.error_to_msg ~pp_error:Mirage_crypto_ec.pp_error
            (Mirage_crypto_ec.P384.Dsa.pub_of_cstruct
               (Cstruct.concat [ four ; x ; y ]))
          >>| fun pub ->
          `P384 pub
        | "P-521" ->
          Rresult.R.error_to_msg ~pp_error:Mirage_crypto_ec.pp_error
            (Mirage_crypto_ec.P521.Dsa.pub_of_cstruct
               (Cstruct.concat [ four ; x ; y ]))
          >>| fun pub ->
          `P521 pub
        | x -> Rresult.R.error_msgf "unknown EC curve %s" x
      end
    | x -> Rresult.R.error_msgf "unknown key type %s" x

  let decode data =
    of_string data >>= fun json ->
    decode_json json

  let thumbprint pub_key =
    let jwk = json_to_string (encode pub_key) in
    let h = Primitives.sha256 jwk in
    B64u.urlencode h
end

module Jws = struct
  type header = {
    alg : string;
    nonce : string option;
    jwk : Jwk.key option;
  }

  let encode ?(protected = []) ~data ?nonce priv =
    let alg, hash = match priv with
      | `RSA _ -> "RS256", `SHA256
      | `P256 _ -> "ES256", `SHA256
      | `P384 _ -> "ES384", `SHA384
      | `P521 _ -> "ES512", `SHA512
      | _ -> assert false
    in
    let protected =
      let n = match nonce with None -> [] | Some x -> [ "nonce", `String x ] in
      `Assoc (("alg", `String alg) :: protected @ n) |> json_to_string
    in
    let protected = protected |> B64u.urlencode in
    let payload = B64u.urlencode data in
    let signature =
      let m = protected ^ "." ^ payload in
      Primitives.sign hash priv m |> B64u.urlencode
    in
    let json =
      `Assoc [
        "protected", `String protected ;
        "payload", `String payload ;
        "signature", `String signature
      ]
    in
    json_to_string ~comma:", " ~colon:": " json

  let encode_acme ?kid_url ~data ?nonce url priv =
    let kid_or_jwk =
      match kid_url with
      | None -> "jwk", Jwk.encode (X509.Private_key.public priv)
      | Some url -> "kid", `String (Uri.to_string url)
    in
    let url = "url", `String (Uri.to_string url) in
    let protected = [ kid_or_jwk ; url ] in
    encode ~protected ~data ?nonce priv

  let decode_header protected_header =
    of_string protected_header >>= fun protected ->
    (match json_val "jwk" protected with
     | Ok key -> Jwk.decode_json key >>| fun k -> Some k
     | Error _ -> Ok None) >>= fun jwk ->
    string_val "alg" protected >>= fun alg ->
    let nonce = match string_val "nonce" protected with
      | Ok nonce -> Some nonce
      | Error _ -> None
    in
    Ok { alg ; nonce ; jwk }

  let decode ?pub data =
    of_string data >>= fun jws ->
    string_val "protected" jws >>= fun protected64 ->
    string_val "payload" jws >>= fun payload64 ->
    b64_string_val "signature" jws >>= fun signature ->
    Rresult.R.open_error_msg (B64u.urldecode protected64) >>= fun protected ->
    decode_header protected >>= fun header ->
    Rresult.R.open_error_msg (B64u.urldecode payload64) >>= fun payload ->
    (match pub, header.jwk with
     | Some pub, _ -> Ok pub
     | None, Some pub -> Ok pub
     | None, None -> Error (`Msg "no public key found")) >>= fun pub ->
    let verify m s =
      match header.alg with
      | "RS256" -> Primitives.verify `SHA256 pub m s
      | "ES256" -> Primitives.verify `SHA256 pub m s
      | "ES384" -> Primitives.verify `SHA384 pub m s
      | "ES512" -> Primitives.verify `SHA512 pub m s
      | _ -> false
    in
    let m = protected64 ^ "." ^ payload64 in
    if verify m signature then
      Ok (header, payload)
    else
      Rresult.R.error_msgf "signature verification failed"
end

let uri s = Ok (Uri.of_string s)

module Directory = struct
  type meta = {
    terms_of_service : Uri.t option;
    website : Uri.t option;
    caa_identities : string list option;
    (* external_account_required *)
  }

  let pp_meta ppf { terms_of_service ; website ; caa_identities } =
    Fmt.pf ppf "terms of service: %a@,website %a@,caa identities %a"
      Fmt.(option ~none:(any "no tos") Uri.pp_hum) terms_of_service
      Fmt.(option ~none:(any "no website") Uri.pp_hum) website
      Fmt.(option ~none:(any "no CAA") (list ~sep:(any ", ") string))
      caa_identities

  let meta_of_json = function
    | `Assoc _ as json ->
      opt_string_val "termsOfService" json >>= maybe uri >>= fun terms_of_service ->
      opt_string_val "website" json >>= maybe uri >>= fun website ->
      opt_string_list "caaIdentities" json >>| fun caa_identities ->
      Some { terms_of_service ; website ; caa_identities }
    | _ -> Ok None

  type t = {
    new_nonce : Uri.t;
    new_account : Uri.t;
    new_order : Uri.t;
    new_authz : Uri.t option;
    revoke_cert : Uri.t;
    key_change : Uri.t;
    meta : meta option;
  }

  let pp ppf dir =
    Fmt.pf ppf "new nonce %a@,new account %a@,new order %a@,new authz %a@,revoke cert %a@,key change %a@,meta %a"
      Uri.pp_hum dir.new_nonce Uri.pp_hum dir.new_account Uri.pp_hum dir.new_order
      Fmt.(option ~none:(any "no authz") Uri.pp_hum) dir.new_authz
      Uri.pp_hum dir.revoke_cert Uri.pp_hum dir.key_change
      Fmt.(option ~none:(any "no meta") pp_meta) dir.meta

  let decode s =
    of_string s >>= fun json ->
    string_val "newNonce" json >>= uri >>= fun new_nonce ->
    string_val "newAccount" json >>= uri >>= fun new_account ->
    string_val "newOrder" json >>= uri >>= fun new_order ->
    opt_string_val "newAuthz" json >>= maybe uri >>= fun new_authz ->
    string_val "revokeCert" json >>= uri >>= fun revoke_cert ->
    string_val "keyChange" json >>= uri >>= fun key_change ->
    assoc_val "meta" json >>= meta_of_json >>| fun meta ->
    { new_nonce ; new_account ; new_order ; new_authz ; revoke_cert ;
      key_change ; meta }
end

module Account = struct
  type t = {
    account_status : [ `Valid | `Deactivated | `Revoked ];
    contact : string list option;
    terms_of_service_agreed : bool option;
    (* externalAccountBinding *)
    orders : Uri.t option;
    initial_ip : string option;
    created_at : Ptime.t option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Valid -> "valid"
        | `Deactivated -> "deactivated"
        | `Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,contact %a@,terms of service agreed %a@,orders %a@,initial IP %a@,created %a"
      pp_status a.account_status
      Fmt.(option ~none:(any "no contact") (list ~sep:(any ", ") string))
      a.contact
      Fmt.(option ~none:(any "unknown") bool) a.terms_of_service_agreed
      Fmt.(option ~none:(any "unknown") Uri.pp_hum) a.orders
      Fmt.(option ~none:(any "unknown") string) a.initial_ip
      Fmt.(option ~none:(any "unknown") (Ptime.pp_rfc3339 ())) a.created_at

  let status_of_string = function
    | "valid" -> Ok `Valid
    | "deactivated" -> Ok `Deactivated
    | "revoked" -> Ok `Revoked
    | s -> Rresult.R.error_msgf "unknown account status %s" s

  (* "it's fine to not have a 'required' orders array" (in contrast to 8555)
     and seen in the wild when creating an account, or retrieving the account url
     of a key, or even fetching the account url. all with an account that never
     ever did an order... it seems to be a discrepancy from LE servers and
     RFC 8555 *)
  (* https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md
     or https://github.com/letsencrypt/boulder/issues/3335 contains more
     information *)
  let decode str =
    of_string str >>= fun json ->
    string_val "status" json >>= status_of_string >>= fun account_status ->
    opt_string_list "contact" json >>= fun contact ->
    opt_bool "termsOfServiceAgreed" json >>= fun terms_of_service_agreed ->
    opt_string_val "orders" json >>= maybe uri >>= fun orders ->
    opt_string_val "initialIp" json >>= fun initial_ip ->
    opt_string_val "createdAt" json >>= maybe decode_ptime >>| fun created_at ->
    { account_status ; contact ; terms_of_service_agreed ; orders ; initial_ip ; created_at }
end

type id_type = [ `Dns ]

let pp_id_type ppf = function `Dns -> Fmt.string ppf "dns"

let pp_id = Fmt.(pair ~sep:(any " - ") pp_id_type string)

let id_type_of_string = function
  | "dns" -> Ok `Dns
  | s -> Rresult.R.error_msgf "only DNS typ is supported, got %s" s

let decode_id json =
  string_val "type" json >>= id_type_of_string >>= fun typ ->
  string_val "value" json >>| fun id ->
  (typ, id)

let decode_ids ids =
  List.fold_left (fun acc json_id ->
      acc >>= fun acc ->
      decode_id json_id >>| fun id ->
      id :: acc)
    (Ok []) ids

module Order = struct
  type t = {
    order_status : [ `Pending | `Ready | `Processing | `Valid | `Invalid ];
    expires : Ptime.t option; (* required if order_status = pending | valid *)
    identifiers : (id_type * string) list;
    not_before : Ptime.t option;
    not_after : Ptime.t option;
    error : json option; (* "structured as problem document, RFC 7807" *)
    authorizations : Uri.t list;
    finalize : Uri.t;
    certificate : Uri.t option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Ready -> "ready"
        | `Processing -> "processing"
        | `Valid -> "valid"
        | `Invalid -> "invalid")

  let pp ppf o =
    Fmt.pf ppf "status %a@,expires %a@,identifiers %a@,not_before %a@,not_after %a@,error %a@,authorizations %a@,finalize %a@,certificate %a"
      pp_status o.order_status
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.expires
      Fmt.(list ~sep:(any ", ") pp_id) o.identifiers
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.not_before
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.not_after
      Fmt.(option ~none:(any "no error") J.pp) o.error
      Fmt.(list ~sep:(any ", ") Uri.pp_hum) o.authorizations
      Uri.pp_hum o.finalize
      Fmt.(option ~none:(any "no") Uri.pp_hum) o.certificate

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "ready" -> Ok `Ready
    | "processing" -> Ok `Processing
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | s -> Rresult.R.error_msgf "unknown order status %s" s

  let decode str =
    of_string str >>= fun json ->
    string_val "status" json >>= status_of_string >>= fun order_status ->
    opt_string_val "expires" json >>= maybe decode_ptime >>= fun expires ->
    list_val "identifiers" json >>= decode_ids >>= fun identifiers ->
    opt_string_val "notBefore" json >>= maybe decode_ptime >>= fun not_before ->
    opt_string_val "notAfter" json >>= maybe decode_ptime >>= fun not_after ->
    (match J.Util.member "error" json with `Null -> Ok None | x -> Ok (Some x)) >>= fun error ->
    (opt_string_list "authorizations" json >>= function
      | None -> Error (`Msg "no authorizations found in order")
      | Some auths -> Ok (List.map Uri.of_string auths)) >>= fun authorizations ->
    string_val "finalize" json >>= uri >>= fun finalize ->
    opt_string_val "certificate" json >>= maybe uri >>| fun certificate ->
    { order_status ; expires ; identifiers ; not_before ; not_after ; error ;
      authorizations ; finalize ; certificate }
end

module Challenge = struct
  type typ = [ `Dns | `Http | `Alpn ]

  let pp_typ ppf t =
    Fmt.string ppf (match t with `Dns -> "DNS" | `Http -> "HTTP" | `Alpn -> "ALPN")

  let typ_of_string = function
    | "tls-alpn-01" -> Ok `Alpn
    | "http-01" -> Ok `Http
    | "dns-01" -> Ok `Dns
    | s -> Rresult.R.error_msgf "unknown challenge typ %s" s

  (* turns out, the only interesting ones are dns, http, alpn *)
  (* all share the same style *)
  type t = {
    challenge_typ : typ;
    url : Uri.t;
    challenge_status : [ `Pending | `Processing | `Valid | `Invalid ];
    token : string;
    validated : Ptime.t option;
    error : json option;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Processing -> "processing"
        | `Valid -> "valid"
        | `Invalid -> "invalid")

  let pp ppf c =
    Fmt.pf ppf "status %a@,typ %a@,token %s@,url %a@,validated %a@,error %a"
      pp_status c.challenge_status
      pp_typ c.challenge_typ
      c.token
      Uri.pp_hum c.url
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) c.validated
      Fmt.(option ~none:(any "no error") J.pp) c.error

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "processing" -> Ok `Processing
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | s -> Rresult.R.error_msgf "unknown order status %s" s

  let decode json =
    string_val "type" json >>= typ_of_string >>= fun challenge_typ ->
    string_val "status" json >>= status_of_string >>= fun challenge_status ->
    string_val "url" json >>= uri >>= fun url ->
    (* in all three challenges, it's b64 url encoded (but the raw value never used) *)
    (* they MUST >= 128bit entropy, and not have any trailing = *)
    string_val "token" json >>= fun token ->
    opt_string_val "validated" json >>= maybe decode_ptime >>= fun validated ->
    (match J.Util.member "error" json with `Null -> Ok None | x -> Ok (Some x)) >>| fun error ->
    { challenge_typ ; challenge_status ; url ; token ; validated ; error }
end

module Authorization = struct
  type t = {
    identifier : id_type * string;
    authorization_status : [ `Pending | `Valid | `Invalid | `Deactivated | `Expired | `Revoked ];
    expires : Ptime.t option;
    challenges : Challenge.t list;
    wildcard : bool;
  }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | `Pending -> "pending"
        | `Valid -> "valid"
        | `Invalid -> "invalid"
        | `Deactivated -> "deactivated"
        | `Expired -> "expired"
        | `Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,identifier %a@,expires %a@,challenges %a@,wildcard %a"
      pp_status a.authorization_status pp_id a.identifier
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) a.expires
      Fmt.(list ~sep:(any ",") Challenge.pp) a.challenges
      Fmt.bool a.wildcard

  let status_of_string = function
    | "pending" -> Ok `Pending
    | "valid" -> Ok `Valid
    | "invalid" -> Ok `Invalid
    | "deactivated" -> Ok `Deactivated
    | "expired" -> Ok `Expired
    | "revoked" -> Ok `Revoked
    | s -> Rresult.R.error_msgf "unknown order status %s" s

  let decode str =
    of_string str >>= fun json ->
    assoc_val "identifier" json >>= decode_id >>= fun identifier ->
    string_val "status" json >>= status_of_string >>= fun authorization_status ->
    opt_string_val "expires" json >>= maybe decode_ptime >>= fun expires ->
    list_val "challenges" json >>= fun challenges ->
    let challenges =
      (* be modest in what you receive - there may be other challenges in the future *)
      List.fold_left (fun acc json ->
          match Challenge.decode json with
          | Error `Msg err ->
            Logs.warn (fun m -> m "ignoring challenge %a: parse error %s" J.pp json err);
            acc
          | Ok c -> c :: acc) [] challenges
    in
    (* TODO "MUST be present and true for orders containing a DNS identifier with wildcard. for others, it MUST be absent" *)
    (opt_bool "wildcard" json >>| function None -> false | Some v -> v) >>| fun wildcard ->
    { identifier ; authorization_status ; expires ; challenges ; wildcard }
end

module Error = struct
  (* from http://www.iana.org/assignments/acme urn registry *)
  type t = {
    err_typ : [
      | `Account_does_not_exist | `Already_revoked | `Bad_csr | `Bad_nonce
      | `Bad_public_key | `Bad_revocation_reason | `Bad_signature_algorithm
      | `CAA | `Connection | `DNS | `External_account_required
      | `Incorrect_response | `Invalid_contact | `Malformed | `Order_not_ready
      | `Rate_limited | `Rejected_identifier | `Server_internal | `TLS
      | `Unauthorized | `Unsupported_contact | `Unsupported_identifier
      | `User_action_required
    ];
    detail : string
  }

  let err_typ_to_string = function
    | `Account_does_not_exist -> "The request specified an account that does not exist"
    | `Already_revoked -> "The request specified a certificate to be revoked that has already been revoked"
    | `Bad_csr -> "The CSR is unacceptable (e.g., due to a short key)"
    | `Bad_nonce -> "The client sent an unacceptable anti-replay nonce"
    | `Bad_public_key -> "The JWS was signed by a public key the server does not support"
    | `Bad_revocation_reason -> "The revocation reason provided is not allowed by the server"
    | `Bad_signature_algorithm -> "The JWS was signed with an algorithm the server does not support"
    | `CAA -> "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate"
    (*  | `Compound -> "Specific error conditions are indicated in the 'subproblems' array" *)
    | `Connection -> "The server could not connect to validation target"
    | `DNS -> "There was a problem with a DNS query during identifier validation"
    | `External_account_required -> "The request must include a value for the 'externalAccountBinding' field"
    | `Incorrect_response -> "Response received didn't match the challenge's requirements"
    | `Invalid_contact -> "A contact URL for an account was invalid"
    | `Malformed -> "The request message was malformed"
    | `Order_not_ready -> "The request attempted to finalize an order that is not ready to be finalized"
    | `Rate_limited -> "The request exceeds a rate limit"
    | `Rejected_identifier -> "The server will not issue certificates for the identifier"
    | `Server_internal -> "The server experienced an internal error"
    | `TLS -> "The server received a TLS error during validation"
    | `Unauthorized -> "The client lacks sufficient authorization"
    | `Unsupported_contact -> "A contact URL for an account used an unsupported protocol scheme"
    | `Unsupported_identifier -> "An identifier is of an unsupported type"
    | `User_action_required -> "Visit the 'instance' URL and take actions specified there"

  let pp ppf e =
    Fmt.pf ppf "%s, detail: %s" (err_typ_to_string e.err_typ) e.detail

  let err_typ_of_string str =
    let prefix = "urn:ietf:params:acme:error:" in
    let plen = String.length prefix in
    let err =
      if String.length str > plen && String.(equal prefix (sub str 0 plen)) then
        Some (String.sub str plen (String.length str - plen))
      else
        None
    in
    match err with
    | Some err ->
      (* from https://www.iana.org/assignments/acme/acme.xhtml (20200209) *)
      begin match err with
        | "accountDoesNotExist" -> Ok `Account_does_not_exist
        | "alreadyRevoked" -> Ok `Already_revoked
        | "badCSR" -> Ok `Bad_csr
        | "badNonce" -> Ok `Bad_nonce
        | "badPublicKey" -> Ok `Bad_public_key
        | "badRevocationReason" -> Ok `Bad_revocation_reason
        | "badSignatureAlgorithm" -> Ok `Bad_signature_algorithm
        | "caa" -> Ok `CAA
        (* | "compound" -> Ok `Compound see 'subproblems' array *)
        | "connection" -> Ok `Connection
        | "dns" -> Ok `DNS
        | "externalAccountRequired" -> Ok `External_account_required
        | "incorrectResponse" -> Ok `Incorrect_response
        | "invalidContact" -> Ok `Invalid_contact
        | "malformed" -> Ok `Malformed
        | "orderNotReady" -> Ok `Order_not_ready
        | "rateLimited" -> Ok `Rate_limited
        | "rejectedIdentifier" -> Ok `Rejected_identifier
        | "serverInternal" -> Ok `Server_internal
        | "tls" -> Ok `TLS
        | "unauthorized" -> Ok `Unauthorized
        | "unsupportedContact" -> Ok `Unsupported_contact
        | "unsupportedIdentifier" -> Ok `Unsupported_identifier
        | "userActionRequired" -> Ok `User_action_required
        | s -> Rresult.R.error_msgf "unknown acme error typ %s" s
      end
    | None -> Rresult.R.error_msgf "unknown error type %s" str

  let decode str =
    of_string str >>= fun json ->
    string_val "type" json >>= err_typ_of_string >>= fun err_typ ->
    string_val "detail" json >>| fun detail ->
    { err_typ ; detail }
end
