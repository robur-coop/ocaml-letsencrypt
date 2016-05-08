module Json = Yojson.Basic

let encode priv data nonce =
  let pub = Primitives.pub_of_priv priv in
  let jwk = Jwk.encode pub in
  let protected =
    Printf.sprintf {|{"alg":"RS256","jwk":%s,"nonce":"%s"}|}
                   jwk nonce
    |> B64u.urlencode in
  let payload = B64u.urlencode data in
  let signature =
    let m = Cstruct.of_string (protected ^ "." ^ payload) in
    Primitives.sign priv m |> Cstruct.to_string |> B64u.urlencode in
  Printf.sprintf {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
                 protected payload signature

(* There are tons of things that are wrong with this function.
 * First of all, we assume the protected header is being sent
 * already lexicographically ordered and without spaces.
 * Then, it's difficult to understand which exceptions might be raised
 * Also, I wonder the current type signature is good. Probably we need to check
 * for the nonce, but probably then also all other headers.
 * Finally, there is a subtle difference between
 * Json.Util.to/from_string and Json.to/from_string and having the two
 * mixed like this doesn't seem a good idea.
 *)
let decode_unsafe data =
  let jws = Json.from_string data in
  let protected64 = Json.Util.member "protected" jws |> Json.Util.to_string in
  let protected = B64u.urldecode protected64 |> Json.from_string in
  let payload64 = Json.Util.member "payload" jws |> Json.Util.to_string in
  let payload = B64u.urldecode payload64 in
  let jwk = Json.Util.member "jwk" protected |> Json.to_string in
  let signature = Json.Util.member "signature" jws
                  |> Json.Util.to_string
                  |> B64u.urldecode
                  |> Cstruct.of_string
  in
  match Jwk.decode jwk with
  | None -> None
  | Some pub ->
     let m = Cstruct.of_string (protected64 ^ "." ^ payload64) in
     (* here we should reprocess to remove spaces *)
     if Primitives.verify pub m signature then
       Some (pub, payload)
     else
       None

let decode data =
  try
    decode_unsafe data
  with
  | Failure _
  | Json.Util.Type_error _
  | Yojson.Json_error _ -> None
