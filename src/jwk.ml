open Nocrypto

let encode (key: Rsa.pub) =
  let e = B64u.urlencodez key.Rsa.e in
  let n = B64u.urlencodez key.Rsa.n in
  Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|} e n

let thumbprint pub_key =
  let jwk = encode pub_key |> Cstruct.of_string in
  let h = Hash.SHA256.digest jwk |> Cstruct.to_string in
  B64u.urlencode h
