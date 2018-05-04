open Rresult.R.Infix

type jws_header_t = {
  alg : string;
  nonce : string option;
  jwk : Jwk.key_t option;
}

let encode priv data nonce =
  let pub = Primitives.pub_of_priv priv in
  let jwk = Jwk.encode (`Rsa pub) in
  let protected =
    Printf.sprintf {|{"alg":"RS256","jwk":%s,"nonce":"%s"}|} jwk nonce
    |> B64u.urlencode
  in
  let payload = B64u.urlencode data in
  let signature =
    let m = protected ^ "." ^ payload in
    Primitives.rs256_sign priv m |> B64u.urlencode
  in
  Printf.sprintf {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
    protected payload signature

let decode_header protected_header =
  Json.of_string protected_header >>= fun protected ->
  (match Json.json_member "jwk" protected with
   | Ok key -> Jwk.decode_json key >>| fun k -> Some k
   | Error _ -> Ok None) >>= fun jwk ->
  Json.string_member "alg" protected >>= fun alg ->
  let nonce = match Json.string_member "nonce" protected with
    | Ok nonce -> Some nonce
    | Error _ -> None
  in
  Ok { alg ; nonce ; jwk }

let decode ?pub data =
  Json.of_string data >>= fun jws ->
  Json.string_member "protected" jws >>= fun protected64 ->
  Json.string_member "payload" jws >>= fun payload64 ->
  Json.b64_string_member "signature" jws >>= fun signature ->
  B64u.urldecode protected64 >>= fun protected ->
  decode_header protected >>= fun header ->
  B64u.urldecode payload64 >>= fun payload ->
  (match pub, header.jwk with
   | Some pub, _ -> Ok pub
   | None, Some pub -> Ok pub
   | None, None -> Error "no public key found") >>= fun pub ->
  let verify m s =
    match header.alg, pub with
    | "RS256", `Rsa pub -> Primitives.rs256_verify pub m s
    | _ -> false
  in
  let m = protected64 ^ "." ^ payload64 in
  if verify m signature then
    Ok (header, payload)
  else
    Error "signature verification failed"
