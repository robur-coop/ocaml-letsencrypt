module Jwk

type key_t = | Null | Rsa of Primitives.pub

val encode_rsa : Primitives.pub -> Tot string
let encode_rsa key =
  let e, n =  Primitives.pub_to_z key in
  "{\"e\":\"" ^
 (B64u.urlencodez e) ^
 "\",\"kty\":\"RSA\",\"n\":\"" ^
 (B64u.urlencodez n) ^
 "\"}"

val encode : key_t -> Tot string
let encode key =
  match key with
  | Rsa key -> encode_rsa key
  | Null -> "I cannot encode `Null keys."

val thumbprint: key_t -> Tot string
let thumbprint pub_key =
  let jwk = encode pub_key in
  let h = Primitives.sha256 jwk in
  B64u.urlencode h

val stupid_proof: unit -> Lemma (requires True) (ensures (
forall (k:Primitives.pub). exists (kk:Primitives.pub). thumbprint (Rsa k) = thumbprint (Rsa kk))
)
