(** [Jwk]: Json Web Key.

    Jwk is an implementation of the Json Web Key standard (RFC7638).
 *)


(** [key_t] identifies a key.
    At present, this implementation only manages RSA keys. *)
type key_t = [ `Null | `Rsa of Nocrypto.Rsa.pub ]


val encode : key_t -> string
(** [encode key] produces the JWK-encoding of [key]. *)

val decode : string -> key_t
(** [decode jwk_string] reads [jwk_string] as a json and extracts the public
    key previously JWK-encoded. If the string is not correctly formatted,
    outputs `Null. *)

val decode_json : Json.t -> key_t
(** [decode jwk] extracts the public key previously JWK-encoded. If the json
    is not correctly formatted, outputs `Null. *)

val thumbprint : key_t -> string
(** [thumbprint key] produces the JWK thumbprint of [key]. *)
