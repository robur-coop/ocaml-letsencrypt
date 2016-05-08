open Nocrypto

type pub = Rsa.pub
type priv = Rsa.priv

module Pem = X509.Encoding.Pem

let priv_of_pem rsa_pem =
  let maybe_rsa = Pem.Private_key.of_pem_cstruct rsa_pem in
  match maybe_rsa with
  | [`RSA key] -> Some key
  | _ -> None


let pub_of_priv = Rsa.pub_of_priv
let pub_of_z e n = Rsa.{e; n}
let pub_to_z (key: pub) = Rsa.(key.e, key.n)

let sign priv data =
  let h = Hash.SHA256.digest data in
  let pkcs1_digest = X509.Encoding.pkcs1_digest_info_to_cstruct (`SHA256, h) in
  Rsa.PKCS1.sig_encode priv pkcs1_digest

let verify pub data signature =
  let maybe_pkcs1_digest = Rsa.PKCS1.sig_decode pub signature in
  match maybe_pkcs1_digest with
  | Some pkcs1_digest ->
     begin
       match X509.Encoding.pkcs1_digest_info_of_cstruct pkcs1_digest with
       | Some (`SHA256, hash) -> hash = Hash.SHA256.digest data
       | _  -> false
     end
  | _ -> false

let hash = Hash.SHA256.digest
