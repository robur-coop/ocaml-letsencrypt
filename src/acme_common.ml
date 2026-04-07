let letsencrypt_production_url =
  "https://acme-v02.api.letsencrypt.org/directory"

let letsencrypt_staging_url =
  "https://acme-staging-v02.api.letsencrypt.org/directory"

let sha256_and_base64 a =
  let open Digestif.SHA256 in
  let a = digest_string a in
  let a = to_raw_string a in
  Jws.Base64u.encode a

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module S = Map.Make (String)

module Directory = struct
  type meta =
    { termsOfService : string option
    ; website : string option
    ; caaIdentities : string list
    ; externalAccountRequired : bool }

  let pp_meta ppf { termsOfService ; website ; caaIdentities ; _ } =
    Fmt.pf ppf "terms of service: %a@,website %a@,caa identities %a"
      Fmt.(option ~none:(any "no tos") string) termsOfService
      Fmt.(option ~none:(any "no website") string) website
      Fmt.(list ~sep:(any ", ") string)
      caaIdentities

  type t =
    { newAccount : string
    ; newNonce : string
    ; newOrder : string
    ; revokeCert : string
    ; keyChange : string
    ; newAuthz : string option
    ; meta : meta option }

  let pp ppf dir =
    Fmt.pf ppf "new nonce %s@,new account %s@,new order %s@,new authz %a@,revoke cert %s@,key change %s@,meta %a"
      dir.newNonce dir.newAccount dir.newOrder
      Fmt.(option ~none:(any "no authz") string) dir.newAuthz
      dir.revokeCert dir.keyChange
      Fmt.(option ~none:(any "no meta") pp_meta) dir.meta

  module Optics = struct
    let termsOfService () =
      Lun.lense
        (fun { termsOfService; _ } -> termsOfService)
        (fun t termsOfService -> { t with termsOfService })

    let website () =
      Lun.lense
        (fun { website; _ } -> website)
        (fun t website -> { t with website })

    let caaIdentities () =
      Lun.lense
        (fun { caaIdentities; _ } -> caaIdentities)
        (fun t caaIdentities -> { t with caaIdentities })

    let externalAccountRequired () =
      Lun.lense
        (fun { externalAccountRequired; _ } -> externalAccountRequired)
        (fun t externalAccountRequired -> { t with externalAccountRequired })

    let newAccount () =
      Lun.lense
        (fun { newAccount; _ } -> newAccount)
        (fun t newAccount -> { t with newAccount })

    let newNonce () =
      Lun.lense
        (fun { newNonce; _ } -> newNonce)
        (fun t newNonce -> { t with newNonce })

    let newOrder () =
      Lun.lense
        (fun { newOrder; _ } -> newOrder)
        (fun t newOrder -> { t with newOrder })

    let revokeCert () =
      Lun.lense
        (fun { revokeCert; _ } -> revokeCert)
        (fun t revokeCert -> { t with revokeCert })

    let keyChange () =
      Lun.lense
        (fun { keyChange; _ } -> keyChange)
        (fun t keyChange -> { t with keyChange })

    let newAuthz () =
      Lun.lense
        (fun { newAuthz; _ } -> newAuthz)
        (fun t newAuthz -> { t with newAuthz })

    let meta () =
      Lun.lense
        (fun { meta; _ } -> meta)
        (fun t meta -> { t with meta })
  end

  let meta =
    let open Jsont in
    let termsOfService =
      let enc = Lun.get Optics.termsOfService in
      Object.opt_mem "termsOfService" ~enc string in
    let website =
      let enc = Lun.get Optics.website in
      Object.opt_mem "website" ~enc string in
    let caaIdentities =
      let enc = Lun.get Optics.caaIdentities in
      let dec_absent = [] in
      let enc_omit = function [] -> true | _ -> false in
      Object.mem "caaIdentities" ~enc ~dec_absent ~enc_omit (list string) in
    let externalAccountRequired =
      let enc = Lun.get Optics.externalAccountRequired in
      let dec_absent = false in
      let enc_omit = Fun.negate Fun.id in
      Object.mem "externalAccountRequired" ~enc ~dec_absent ~enc_omit bool in
    let fn termsOfService website caaIdentities externalAccountRequired =
      { termsOfService; website; caaIdentities; externalAccountRequired } in
    Object.map fn
    |> termsOfService
    |> website
    |> caaIdentities
    |> externalAccountRequired
    |> Object.finish

  let t =
    let open Jsont in
    let newAccount =
      let enc = Lun.get Optics.newAccount in
      Object.mem "newAccount" ~enc string in
    let newNonce =
      let enc = Lun.get Optics.newNonce in
      Object.mem "newNonce" ~enc string in
    let newOrder =
      let enc = Lun.get Optics.newOrder in
      Object.mem "newOrder" ~enc string in
    let revokeCert =
      let enc = Lun.get Optics.revokeCert in
      Object.mem "revokeCert" ~enc string in
    let keyChange =
      let enc = Lun.get Optics.keyChange in
      Object.mem "keyChange" ~enc string in
    let newAuthz =
      let enc = Lun.get Optics.newAuthz in
      Object.opt_mem "newAuthz" ~enc string in
    let meta =
      let enc = Lun.get Optics.meta in
      Object.opt_mem "meta" ~enc meta in
    let fn newAccount newNonce newOrder revokeCert keyChange newAuthz meta =
      { newAccount; newNonce; newOrder; revokeCert; keyChange; newAuthz; meta } in
    Object.map fn
    |> newAccount
    |> newNonce
    |> newOrder
    |> revokeCert
    |> keyChange
    |> newAuthz
    |> meta
    |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid directory object"
end

module Account = struct
  type status =
    | Valid
    | Deactivated
    | Revoked

  let status =
    let valid = "valid", Valid
    and deactived = "deactived", Deactivated
    and revoked = "revoked", Revoked in
    Jsont.enum [ valid; deactived; revoked ]

  type t =
    { status : status
    ; contact : string list
    ; termsOfServiceAgreed : bool
    ; orders : string }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | Valid -> "valid"
        | Deactivated -> "deactivated"
        | Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,contact %a@,terms of service agreed %b@,orders %s"
      pp_status a.status
      Fmt.(list ~sep:(any ", ") string)
      a.contact
      a.termsOfServiceAgreed
      a.orders

  module Optics = struct
    let status () =
      Lun.lense
        (fun { status; _ } -> status)
        (fun t status -> { t with status })

    let contact () =
      Lun.lense
        (fun { contact; _ } -> contact)
        (fun t contact -> { t with contact })

    let termsOfServiceAgreed () =
      Lun.lense
        (fun { termsOfServiceAgreed; _ } -> termsOfServiceAgreed)
        (fun t termsOfServiceAgreed -> { t with termsOfServiceAgreed })

    let orders () =
      Lun.lense
        (fun { orders; _ } -> orders)
        (fun t orders -> { t with orders })
  end

  let t =
    let open Jsont in
    let status =
      let enc = Lun.get Optics.status in
      Object.mem "status" ~enc status in
    let contact =
      let enc = Lun.get Optics.contact in
      let dec_absent = [] in
      let enc_omit = function [] -> true | _ -> false in
      Object.mem "contact" ~enc ~dec_absent ~enc_omit (list string) in
    let termsOfServiceAgreed =
      let enc = Lun.get Optics.termsOfServiceAgreed in
      let dec_absent = false in
      let enc_omit = Fun.negate Fun.id in
      Object.mem "termsOfServiceAgreed" ~enc ~dec_absent ~enc_omit bool in
    let orders =
      let enc = Lun.get Optics.orders in
      let dec_absent = "" in
      let enc_omit = function "" -> true | _ -> false in
      Object.mem "orders" ~enc ~dec_absent ~enc_omit string in
    let fn status contact termsOfServiceAgreed orders =
      { status; contact; termsOfServiceAgreed; orders } in
    Object.map fn
    |> status
    |> contact
    |> termsOfServiceAgreed
    |> orders
    |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid account object"
end

let rfc3339 =
  let dec str = match Ptime.of_rfc3339 str with
    | Ok (t, _, _) -> t
    | Error _ -> failwith "Invalid RFC3339 date" in
  let enc str = Ptime.to_rfc3339 str in
  Jsont.map ~dec ~enc Jsont.string

let pp_id ppf str = Fmt.pf ppf "DNS - %s" str

let pp_json =
  let open Fmt in
  Dump.iter_bindings S.iter (any "mems") string Jsont.pp_json

module Order = struct
  type status =
    | Pending
    | Ready
    | Processing
    | Valid
    | Invalid

  let status =
    let pending = "pending", Pending
    and ready = "ready", Ready
    and processing = "processing", Processing
    and valid = "valid", Valid
    and invalid = "invalid", Invalid in
    Jsont.enum [ pending; ready; processing; valid; invalid ]

  let identifier =
    let open Jsont in
    let t = Object.mem "type" (const string "dns") in
    let identifier = Object.mem "value" string in
    Object.map (fun _ identifier -> identifier)
    |> t |> identifier |> Object.finish

  type t =
    { status : status
    ; expires : Ptime.t option
    ; identifiers : string list
    ; notBefore : Ptime.t option
    ; notAfter : Ptime.t option
    ; error : Jsont.json S.t option
    ; authorizations : string list
    ; finalize : string
    ; certificate : string option }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | Pending -> "pending"
        | Ready -> "ready"
        | Processing -> "processing"
        | Valid -> "valid"
        | Invalid -> "invalid")

  let pp ppf o =
    Fmt.pf ppf "status %a@,expires %a@,identifiers %a@,not_before %a@,not_after %a@,error %a@,authorizations %a@,finalize %s@,certificate %a"
      pp_status o.status
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.expires
      Fmt.(list ~sep:(any ", ") pp_id) o.identifiers
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.notBefore
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) o.notAfter
      Fmt.(option ~none:(any "no error") pp_json) o.error
      Fmt.(list ~sep:(any ", ") string) o.authorizations
      o.finalize
      Fmt.(option ~none:(any "no") string) o.certificate

  module Optics = struct
    let status () =
      Lun.lense
        (fun { status; _ } -> status)
        (fun t status -> { t with status })

    let expires () =
      Lun.lense
        (fun { expires; _ } -> expires)
        (fun t expires -> { t with expires })

    let identifiers () =
      Lun.lense
        (fun { identifiers; _ } -> identifiers)
        (fun t identifiers -> { t with identifiers })

    let notBefore () =
      Lun.lense
        (fun { notBefore; _ } -> notBefore)
        (fun t notBefore -> { t with notBefore })

    let notAfter () =
      Lun.lense
        (fun { notAfter; _ } -> notAfter)
        (fun t notAfter -> { t with notAfter })

    let error () =
      Lun.lense
        (fun { error; _ } -> error)
        (fun t error -> { t with error })

    let authorizations () =
      Lun.lense
        (fun { authorizations; _ } -> authorizations)
        (fun t authorizations -> { t with authorizations })

    let finalize () =
      Lun.lense
        (fun { finalize; _ } -> finalize)
        (fun t finalize -> { t with finalize })

    let certificate () =
      Lun.lense
        (fun { certificate; _ } -> certificate)
        (fun t certificate -> { t with certificate })
  end

  let t =
    let open Jsont in
    let status =
      let enc = Lun.get Optics.status in
      Object.mem "status" ~enc status in
    let expires =
      let enc = Lun.get Optics.expires in
      Object.opt_mem "expires" ~enc rfc3339 in
    let identifiers =
      let enc = Lun.get Optics.identifiers in
      Object.mem "identifiers" ~enc (list identifier) in
    let notBefore =
      let enc = Lun.get Optics.notBefore in
      Object.opt_mem "notBefore" ~enc rfc3339 in
    let notAfter =
      let enc = Lun.get Optics.notAfter in
      Object.opt_mem "notAfter" ~enc rfc3339 in
    let error =
      let enc = Lun.get Optics.error in
      Object.opt_mem "error" ~enc (Object.as_string_map json) in
    let authorizations =
      let enc = Lun.get Optics.authorizations in
      Object.mem "authorizations" ~enc (list string) in
    let finalize =
      let enc = Lun.get Optics.finalize in
      Object.mem "finalize" ~enc string in
    let certificate =
      let enc = Lun.get Optics.certificate in
      Object.opt_mem "certificate" ~enc string in
    let fn status expires identifiers notBefore notAfter error authorizations finalize certificate =
      { status; expires; identifiers; notBefore; notAfter; error; authorizations; finalize; certificate } in
    Object.map fn
    |> status
    |> expires
    |> identifiers
    |> notBefore
    |> notAfter
    |> error
    |> authorizations
    |> finalize
    |> certificate
    |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid order object"
end

module Challenge = struct
  type typ = DNS | HTTP | ALPN | Unknown of string

  let pp_typ ppf t =
    Fmt.string ppf (match t with DNS -> "DNS" | HTTP -> "HTTP" | ALPN -> "ALPN"
                               | Unknown s -> s)

  let typ =
    let dec s = match s with
      | "dns-01" -> DNS
      | "http-01" -> HTTP
      | "tls-alpn-01" -> ALPN
      | s -> Unknown s in
    let enc = function
      | DNS -> "dns-01"
      | HTTP -> "http-01"
      | ALPN -> "tls-alpn-01"
      | Unknown s -> s in
    Jsont.map ~dec ~enc Jsont.string

  type status =
    | Pending
    | Processing
    | Valid
    | Invalid

  let status =
    let pending = "pending", Pending
    and processing = "processing", Processing
    and valid = "valid", Valid
    and invalid = "invalid", Invalid in
    Jsont.enum [ pending; processing; valid; invalid ]

  type t =
    { typ : typ
    ; url : string
    ; status : status
    ; validated : Ptime.t option
    ; error : Jsont.json S.t option
    ; token : string }
  (* NOTE(dinosaure): [token] is common even if we do a DNS or an HTTP challenge. *)

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | Pending -> "pending"
        | Processing -> "processing"
        | Valid -> "valid"
        | Invalid -> "invalid")

  let pp ppf c =
    Fmt.pf ppf "status %a@,typ %a@,token %s@,url %s@,validated %a@,error %a"
      pp_status c.status
      pp_typ c.typ
      c.token
      c.url
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) c.validated
      Fmt.(option ~none:(any "no error") pp_json) c.error

  module Optics = struct
    let typ () =
      Lun.lense
        (fun { typ; _ } -> typ)
        (fun t typ -> { t with typ })

    let url () =
      Lun.lense
        (fun { url; _ } -> url)
        (fun t url -> { t with url })

    let status () =
      Lun.lense
        (fun { status; _ } -> status)
        (fun t status -> { t with status })

    let validated () =
      Lun.lense
        (fun { validated; _ } -> validated)
        (fun t validated -> { t with validated })

    let error () =
      Lun.lense
        (fun { error; _ } -> error)
        (fun t error -> { t with error })

    let token () =
      Lun.lense
        (fun { token; _ } -> token)
        (fun t token -> { t with token })
  end

  let t =
    let open Jsont in
    let typ =
      let enc = Lun.get Optics.typ in
      Object.mem "type" ~enc typ in
    let url =
      let enc = Lun.get Optics.url in
      Object.mem "url" ~enc string in
    let status =
      let enc = Lun.get Optics.status in
      Object.mem "status" ~enc status in
    let validated =
      let enc = Lun.get Optics.validated in
      Object.opt_mem "validated" ~enc rfc3339 in
    let error =
      let enc = Lun.get Optics.error in
      Object.opt_mem "error" ~enc (Object.as_string_map json) in
    let token =
      let enc = Lun.get Optics.token in
      let dec_absent = "" in
      let enc_omit = function "" -> true | _ -> false in
      Object.mem "token" ~enc ~dec_absent ~enc_omit string in
    let fn typ url status validated error token =
      { typ; url; status; validated; error; token } in
    Object.map fn
    |> typ
    |> url
    |> status
    |> validated
    |> error
    |> token
    |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid challenge object"
end

module Authorization = struct
  type status =
    | Pending
    | Valid
    | Invalid
    | Deactivated
    | Expired
    | Revoked

  let status =
    let pending = "pending", Pending
    and valid = "valid", Valid
    and invalid = "invalid", Invalid
    and deactivated = "deactivated", Deactivated
    and expired = "expired", Expired
    and revoked = "revoked", Revoked in
    Jsont.enum [ pending; valid; invalid; deactivated; expired; revoked ]

  type t =
    { identifier : string
    ; status : status
    ; expires : Ptime.t option
    ; challenges : Challenge.t list
    ; wildcard : bool }

  let pp_status ppf s =
    Fmt.string ppf (match s with
        | Pending -> "pending"
        | Valid -> "valid"
        | Invalid -> "invalid"
        | Deactivated -> "deactivated"
        | Expired -> "expired"
        | Revoked -> "revoked")

  let pp ppf a =
    Fmt.pf ppf "status %a@,identifier %a@,expires %a@,challenges %a@,wildcard %a"
      pp_status a.status pp_id a.identifier
      Fmt.(option ~none:(any "no") (Ptime.pp_rfc3339 ())) a.expires
      Fmt.(list ~sep:(any ",") Challenge.pp) a.challenges
      Fmt.bool a.wildcard

  module Optics = struct
    let identifier () =
      Lun.lense
        (fun { identifier; _ } -> identifier)
        (fun t identifier -> { t with identifier })

    let status () =
      Lun.lense
        (fun { status; _ } -> status)
        (fun t status -> { t with status })

    let expires () =
      Lun.lense
        (fun { expires; _ } -> expires)
        (fun t expires -> { t with expires })

    let challenges () =
      Lun.lense
        (fun { challenges; _ } -> challenges)
        (fun t challenges -> { t with challenges })

    let wildcard () =
      Lun.lense
        (fun { wildcard; _ } -> wildcard)
        (fun t wildcard -> { t with wildcard })
  end

  let identifier =
    let open Jsont in
    let enc = Fun.const "dns" in
    let t = Object.mem "type" ~enc (const string "dns") in
    let identifier = Object.mem "value" ~enc:Fun.id string in
    Object.map (fun _ value -> value)
    |> t |> identifier |> Object.finish

  let t =
    let open Jsont in
    let identifier =
      let enc = Lun.get Optics.identifier in
      Object.mem "identifier" ~enc identifier in
    let status =
      let enc = Lun.get Optics.status in
      Object.mem "status" ~enc status in
    let expires =
      let enc = Lun.get Optics.expires in
      Object.opt_mem "expires" ~enc rfc3339 in
    let challenges =
      let enc = Lun.get Optics.challenges in
      Object.mem "challenges" ~enc (list Challenge.t) in
    let wildcard =
      let enc = Lun.get Optics.wildcard in
      let dec_absent = false in
      let enc_omit = Fun.negate Fun.id in
      Object.mem "wildcard" ~enc ~dec_absent ~enc_omit bool in
    let fn identifier status expires challenges wildcard =
      { identifier; status; expires; challenges; wildcard } in
    Object.map fn
    |> identifier
    |> status
    |> expires
    |> challenges
    |> wildcard
    |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid authorization object"
end

module Error = struct
  type error =
    [ `Account_does_not_exist
    | `Already_revoked
    | `Bad_csr
    | `Bad_nonce
    | `Bad_public_key
    | `Bad_revocation_reason
    | `Bad_signature_algorithm
    | `CAA
    | `Connection
    | `DNS
    | `External_account_required
    | `Incorrect_response
    | `Invalid_contact
    | `Malformed
    | `Order_not_ready
    | `Rate_limited
    | `Rejected_identifier
    | `Server_internal
    | `TLS
    | `Unauthorized
    | `Unsupported_contact
    | `Unsupported_identifier
    | `User_action_required ]

  let error =
    [ "accountDoesNotExist", `Account_does_not_exist
    ; "alreadyRevoked", `Already_revoked
    ; "badCSR", `Bad_csr
    ; "badNonce", `Bad_nonce
    ; "badPublicKey", `Bad_public_key
    ; "badRevocationReason", `Bad_revocation_reason
    ; "badSignatureAlgorithm", `Bad_signature_algorithm
    ; "caa", `CAA
    ; "connection", `Connection
    ; "dns", `DNS
    ; "externalAccountRequired", `External_account_required
    ; "incorrectResponse", `Incorrect_response
    ; "invalidContact", `Invalid_contact
    ; "malformed", `Malformed
    ; "orderNotReady", `Order_not_ready
    ; "rateLimited", `Rate_limited
    ; "rejectedIdentifier", `Rejected_identifier
    ; "serverInternal", `Server_internal
    ; "tls", `TLS
    ; "unauthorized", `Unauthorized
    ; "unsupportedContact", `Unsupported_contact
    ; "unsupportedIdentifier", `Unsupported_identifier
    ; "userActionRequired", `User_action_required ]
    |> List.map (fun (str, value) -> "urn:ietf:params:acme:error:" ^ str, value)
    |> Jsont.enum

  type t =
    { error : error
    ; detail : string }

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
    Fmt.pf ppf "%s, detail: %s" (err_typ_to_string e.error) e.detail

  module Optics = struct
    let error () =
      Lun.lense
        (fun { error; _ } -> error)
        (fun t error -> { t with error })

    let detail () =
      Lun.lense
        (fun { detail; _ } -> detail)
        (fun t detail -> { t with detail })
  end

  let t =
    let open Jsont in
    let error =
      let enc = Lun.get Optics.error in
      Object.mem "type" ~enc error in
    let detail =
      let enc = Lun.get Optics.detail in
      Object.mem "detail" ~enc string in
    Object.map (fun error detail -> { error; detail })
    |> error |> detail |> Object.finish

  let decode str =
    match Jsont_bytesrw.decode_string t str with
    | Ok t -> Ok t
    | Error _ -> error_msgf "Invalid error object"
end
