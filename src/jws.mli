(** [Jws]: Json Web Signatures.

    Jws is an implementation of the Json Web Signature Standard (RFC7515).
    Currently, encoding and decoding operations only support the RS256
    algorithm; specifically the encoding operation is a bit rusty, and probably
    its interface will change in the future.  *)

(** type [jws_header_t] records information about the header. *)
type jws_header_t = {
  alg : string;
  nonce : string option;
  jwk : Jwk.key_t option;
}


val encode : Nocrypto.Rsa.priv -> string -> string -> string
(** [encode private_key data nonce] produces the RS256, JWS-encoding of [data].
    The protected header will include the nonce [nonce]. *)

val decode : ?pub:Jwk.key_t ->  string -> (jws_header_t * string, string) result
(** [decode public_key data] verifies the JWS-signature of [data] using
    [public_key] and returns a pair [(header, content)] if the signature was
    valid.  If [public_key] is not provided, then it will look for it
    JWK-encoded in the header, as a "jwk" argument.  If the signature was not
    valid, we return None. *)
