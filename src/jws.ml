open Nocrypto


let sign priv data =
  let h = Hash.SHA256.digest data in
  let pkcs1_digest = X509.Encoding.pkcs1_digest_info_to_cstruct (`SHA256, h) in
  Rsa.PKCS1.sig_encode priv pkcs1_digest

let encode priv data nonce =
  let pub = Rsa.pub_of_priv priv in
  let jwk = Jwk.encode pub in
  let protected =
    Printf.sprintf {|{"alg":"RS256","jwk":%s,"nonce":"%s"}|}
                   jwk nonce
    |> B64u.urlencode in
  let payload = B64u.urlencode data in
  let signature =
    let m = Cstruct.of_string (protected ^ "." ^ payload) in
    sign priv m |> Cstruct.to_string |> B64u.urlencode in
  Printf.sprintf {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
                 protected payload signature
