open Mirage_crypto_pk

let pub_of_priv = Rsa.pub_of_priv
let pub_of_z ~e ~n = Rsa.pub ~e ~n
let pub_to_z (key : Rsa.pub) = Rsa.(key.e, key.n)

let rs256_sign priv data =
  let data = Cstruct.of_string data in
  let h = Mirage_crypto.Hash.SHA256.digest data in
  let pkcs1_digest = X509.Certificate.encode_pkcs1_digest_info (`SHA256, h) in
  Rsa.PKCS1.sig_encode ~key:priv pkcs1_digest |> Cstruct.to_string

let rs256_verify pub data signature =
  let data = Cstruct.of_string data in
  match Rsa.PKCS1.sig_decode ~key:pub (Cstruct.of_string signature) with
  | Some pkcs1_digest ->
     begin
       match X509.Certificate.decode_pkcs1_digest_info pkcs1_digest with
       | Ok (`SHA256, hash) -> hash = Mirage_crypto.Hash.SHA256.digest data
       | _  -> false
     end
  | _ -> false

let sha256 x =
  Cstruct.of_string x |> Mirage_crypto.Hash.SHA256.digest |> Cstruct.to_string
