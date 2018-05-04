open Rresult.R.Infix

type key_t = [ `Rsa of Nocrypto.Rsa.pub]

(** RSA operations *)
let encode_rsa key =
  let e, n = Primitives.pub_to_z key in
  Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|}
    (B64u.urlencodez e)
    (B64u.urlencodez n)

let decode_rsa j =
  Json.b64_z_member "e" j >>= fun e ->
  Json.b64_z_member "n" j >>= fun n ->
  Ok (`Rsa (Primitives.pub_of_z ~e ~n))

let encode = function
  | `Rsa key -> encode_rsa key

let thumbprint pub_key =
  let jwk = encode pub_key in
  let h = Primitives.sha256 jwk in
  B64u.urlencode h

let decode_json json =
  Json.string_member "kty" json >>= function
  | "RSA" -> decode_rsa json
  | x -> Error ("unknown key type " ^ x)

let decode data =
  Json.of_string data >>= fun json ->
  decode_json json
