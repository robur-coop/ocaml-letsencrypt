(** [Jwk]: Json Web Key.

    Jwk is an implementation of the Json Web Key standard (RFC7638).
 *)


(** [key_t] identifies a key.
    At present, this implementation only manages RSA keys. *)
type key_t = [ `Rsa of Nocrypto.Rsa.pub ]


val encode : key_t -> string
(** [encode key] produces the JWK-encoding of [key]. *)

val decode : string -> (key_t, string) result
(** [decode jwk_string] reads [jwk_string] as a json and extracts the public
    key previously JWK-encoded. If the string is not correctly formatted,
    errors. *)

val decode_json : Json.t -> (key_t, string) result
(** [decode jwk] extracts the public key previously JWK-encoded. If the json
    is not correctly formatted, errors. *)

val thumbprint : key_t -> string
(** [thumbprint key] produces the JWK thumbprint of [key]. *)
