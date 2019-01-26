open Nocrypto

module Pem = X509.Encoding.Pem

let priv_of_pem rsa_pem =
  try
    match Pem.Private_key.of_pem_cstruct1 (Cstruct.of_string rsa_pem) with
    | `RSA priv -> Ok priv
  with  Invalid_argument e -> Error e

let csr_of_pem pem =
  try Ok (Pem.Certificate_signing_request.of_pem_cstruct1 (Cstruct.of_string pem))
  with Invalid_argument i -> Error i

let pub_of_priv = Rsa.pub_of_priv
let pub_of_z ~e ~n = Rsa.{e; n}
let pub_to_z (key : Rsa.pub) = Rsa.(key.e, key.n)

let rs256_sign priv data =
  let data = Cstruct.of_string data in
  let h = Hash.SHA256.digest data in
  let pkcs1_digest = X509.Encoding.pkcs1_digest_info_to_cstruct (`SHA256, h) in
  Rsa.PKCS1.sig_encode priv pkcs1_digest |> Cstruct.to_string

let rs256_verify pub data signature =
  let data = Cstruct.of_string data in
  match Rsa.PKCS1.sig_decode pub (Cstruct.of_string signature) with
  | Some pkcs1_digest ->
     begin
       match X509.Encoding.pkcs1_digest_info_of_cstruct pkcs1_digest with
       | Some (`SHA256, hash) -> hash = Hash.SHA256.digest data
       | _  -> false
     end
  | _ -> false

let sha256 x = x |> Cstruct.of_string |> Hash.SHA256.digest |> Cstruct.to_string
