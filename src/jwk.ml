open Nocrypto

module Json = Yojson.Basic

let encode (key: Rsa.pub) =
  let e = B64u.urlencodez key.Rsa.e in
  let n = B64u.urlencodez key.Rsa.n in
  Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|} e n

let decode data =
  let j = Json.from_string data in
  let kty = Json.Util.member "kty" j |> Json.Util.to_string in
  if kty = "RSA" then
    (* XXX. here we fail immediately if keys are not valid.
     * Instead, we should return None. *)
    let e = Json.Util.member "e" j |> Json.Util.to_string |> B64u.urldecodez in
    let n = Json.Util.member "n" j |> Json.Util.to_string |> B64u.urldecodez in
    Some Rsa.{e=e; n=n}
  else
    None

let thumbprint pub_key =
  let jwk = encode pub_key |> Cstruct.of_string in
  let h = Hash.SHA256.digest jwk |> Cstruct.to_string in
  B64u.urlencode h
