open Cohttp
open Cohttp_lwt_unix
open Lwt
open Nocrypto

let acme_ca = "https://acme-v01.api.letsencrypt.org"

module Pem = X509.Encoding.Pem

type client_t = {
    skey: Rsa.priv;
    csr:  X509.CA.signing_request;
  }

let new_cli rsa_pem csr_pem =
  let maybe_rsa = Pem.Private_key.of_pem_cstruct rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct csr_pem in
  let ret = match maybe_rsa, maybe_csr with
    | [`RSA skey], [csr] ->
       `Ok {skey=skey; csr=csr}
    | _ ->
       `Error "I cannot parse those inputs." in
  Lwt.return ret

let http_get url =
  Client.get (Uri.of_string url) >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  let body = body |> Cohttp_lwt_body.to_string in
  Lwt.return (code, headers, body)

let discover =
  let url = acme_ca ^ "/directory" in
  http_get url >>= fun (code, headers, body) ->
  Lwt.return (headers, body)

let new_nonce () =
  discover >>= fun (headers, body) ->
  match Header.get headers "Replay-Nonce" with
  | Some nonce -> Lwt.return nonce
  | None -> Lwt.fail End_of_file

let http_post_jws key data url =
  new_nonce () >>= fun nonce ->
  let body = Jws.encode key data nonce  in
  let body_len = string_of_int (String.length body) in
  let header = Header.init () in
  let header = Header.add header "Content-Length" body_len in
  let body = Cohttp_lwt_body.of_string body in
  let url = Uri.of_string url in
  Client.post ~body:body ~headers:header url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >|= fun body ->
  code, headers, body

let new_reg cli =
  let url = acme_ca ^ "/acme/new-reg" in
  let body =
    {|{"resource": "new-reg", "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"}|}
  in
  http_post_jws cli.skey body url

let new_authz cli domain =
  let url = acme_ca ^ "/acme/new-authz" in
  let body = Printf.sprintf
    {|{"resouce": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
    domain in
  http_post_jws cli.skey body url

type challenge_t = {
    uri: string;
    token: string;
  }

let challenge_met cli challenge =
  let token = challenge.token in
  let pub = Rsa.pub_of_priv cli.skey in
  let thumbprint = Jwk.thumbprint pub in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  let data =
    Printf.sprintf {|{"resource": "challenge", "keyAuthorization": "%s"}|}
                   key_authorization in
  http_post_jws cli.skey data challenge.uri

let new_cert cli =
  let url = acme_ca ^ "/acme/new-cert" in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string in
  let body = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  http_post_jws cli.skey body url
