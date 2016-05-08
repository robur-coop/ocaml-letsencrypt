module Json = Yojson.Basic

let encode key =
  let e, n = Primitives.pub_to_z key in
  Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|}
                 (B64u.urlencodez e)
                 (B64u.urlencodez n)

let decode data =
  let j = Json.from_string data in
  let kty = Json.Util.member "kty" j |> Json.Util.to_string in
  if kty = "RSA" then
    (* XXX. here we fail immediately if keys are not valid.
     * Instead, we should return None. *)
    let e = Json.Util.member "e" j |> Json.Util.to_string |> B64u.urldecodez in
    let n = Json.Util.member "n" j |> Json.Util.to_string |> B64u.urldecodez in
    Some (Primitives.pub_of_z e n)
  else
    None

let thumbprint pub_key =
  let jwk = encode pub_key |> Cstruct.of_string in
  let h = Primitives.hash jwk |> Cstruct.to_string in
  B64u.urlencode h
