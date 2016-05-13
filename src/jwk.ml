type key_t = [`Null | `Rsa of Primitives.pub]


(** RSA operations *)
let encode_rsa key =
  let e, n = Primitives.pub_to_z key in
  Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|}
                 (B64u.urlencodez e)
                 (B64u.urlencodez n)

let decode_rsa j =
  let maybe_e = Json.b64_z_member "e" j in
  let maybe_n = Json.b64_z_member "n" j in
  match maybe_e, maybe_n with
  | Some e, Some n ->  `Rsa (Primitives.pub_of_z e n)
  | _, _ -> `Null

let encode key =
  match key with
  | `Rsa key -> encode_rsa key
  | `Null -> raise (Failure "I cannot encode `Null keys.")

let thumbprint pub_key =
  let jwk = encode pub_key in
  let h = Primitives.sha256 jwk in
  B64u.urlencode h


let decode_json json =
  match Json.string_member "kty" json with
  | Some "RSA" -> decode_rsa json
  | _ -> `Null

let decode data =
  match Json.of_string data with
  | Some json -> decode_json json
  | None -> `Null
