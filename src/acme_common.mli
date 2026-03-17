val letsencrypt_production_url : string
val letsencrypt_staging_url : string

val sha256_and_base64 : string -> string

type json = Yojson.Basic.t

val json_to_string : ?comma:string -> ?colon:string -> json -> string

module S : module type of Map.Make (String)

module Directory : sig
  type meta =
    { termsOfService : string option
    ; website : string option
    ; caaIdentities : string list
    ; externalAccountRequired : bool }

  type t =
    { newAccount : string
    ; newNonce : string
    ; newOrder : string 
    ; revokeCert : string
    ; keyChange : string
    ; newAuthz : string option
    ; meta : meta option }

  val decode : string -> (t, [> `Msg of string ]) result
end

module Account : sig
  type status =
    | Valid
    | Deactivated
    | Revoked

  type t =
    { status : status
    ; contact : string list
    ; termsOfServiceAgreed : bool
    ; orders : string }

  val pp : t Fmt.t
  val decode : string -> (t, [> `Msg of string ]) result
end

module Order : sig
  type status =
    | Pending
    | Ready
    | Processing
    | Valid
    | Invalid

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

  val pp : t Fmt.t
  val decode : string -> (t, [> `Msg of string ]) result
end

module Challenge : sig
  type typ = DNS | HTTP | ALPN

  type status =
    | Pending
    | Processing
    | Valid
    | Invalid

  type t =
    { typ : typ
    ; url : string
    ; status : status
    ; validated : Ptime.t option
    ; error : Jsont.json S.t option
    ; token : string }

  val pp : t Fmt.t
  val decode : string -> (t, [> `Msg of string ]) result
end

module Authorization : sig
  type status =
    | Pending
    | Valid
    | Invalid
    | Deactivated
    | Expired
    | Revoked

  type t =
    { identifier : string
    ; status : status
    ; expires : Ptime.t option
    ; challenges : Challenge.t list
    ; wildcard : bool }

  val pp : t Fmt.t
  val decode : string -> (t, [> `Msg of string ]) result
end

module Error : sig
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

  type t =
    { error : error
    ; detail : string }

  val pp : t Fmt.t
  val decode : string -> (t, [> `Msg of string ]) result
end
