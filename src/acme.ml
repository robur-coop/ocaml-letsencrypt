open Cohttp
open Cohttp_lwt_unix
open Lwt
open Nocrypto


module Pem = X509.Encoding.Pem

type client_t = {
    ca: string;
    skey: Rsa.priv;
    csr:  X509.CA.signing_request;
    mutable next_nonce: string;
  }

type challenge_t = {
    uri: string;
    token: string;
  }

let http_get url =
  Client.get (Uri.of_string url) >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  let body = body |> Cohttp_lwt_body.to_string in
  Lwt.return (code, headers, body)

let http_post_jws key nonce data url =
  let body = Jws.encode key data nonce  in
  let body_len = string_of_int (String.length body) in
  let header = Header.init () in
  let header = Header.add header "Content-Length" body_len in
  let body = Cohttp_lwt_body.of_string body in
  let url = Uri.of_string url in
  Client.post ~body:body ~headers:header url

let discover ca =
  let url = ca ^ "/directory" in
  http_get url >>= fun (code, headers, body) ->
  Lwt.return (headers, body)

let extract_nonce headers =
  match Header.get headers "Replay-Nonce" with
  | Some nonce -> return nonce
  | None -> fail_with "Error: I could not fetch a new nonce."

let new_nonce from =
    discover from >>= fun (headers, body) ->
    extract_nonce headers

let new_cli ?(ca="https://acme-v01.api.letsencrypt.org") rsa_pem csr_pem =
  let maybe_rsa = Pem.Private_key.of_pem_cstruct rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct csr_pem in
  match maybe_rsa, maybe_csr with
    | [`RSA skey], [csr] ->
       new_nonce ca >>= fun nonce ->
       `Ok {skey=skey; csr=csr; ca=ca; next_nonce=nonce} |> return
    | _ ->
       fail_with "Error: there's a problem paring those pem files."

let cli_recv = http_get

let cli_send cli data url =
  http_post_jws cli.skey cli.next_nonce data url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  extract_nonce headers >>= fun next_nonce ->
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  if Code.is_error code then
    let err_msg = Printf.sprintf
                    "Error: HTTP response code %d. \n %s\n %s"
                    code (Header.to_string headers) body in
    fail_with err_msg
  else
    (* XXX: is this like cheating? *)
    (cli.next_nonce <- next_nonce; return body)

let new_reg cli =
  let url = cli.ca ^ "/acme/new-reg" in
  let body =
    {|{"resource": "new-reg", "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"}|}
  in
  cli_send cli body url

let new_authz cli domain =
  let url = cli.ca ^ "/acme/new-authz" in
  let body = Printf.sprintf
    {|{"resouce": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
    domain in
  cli_send cli body url

let challenge_met cli challenge =
  let token = challenge.token in
  let pub = Rsa.pub_of_priv cli.skey in
  let thumbprint = Jwk.thumbprint pub in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  let data =
    Printf.sprintf {|{"resource": "challenge", "keyAuthorization": "%s"}|}
                   key_authorization in
  cli_send cli data challenge.uri

let new_cert cli =
  let url = cli.ca ^ "/acme/new-cert" in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string in
  let body = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  cli_send cli body url
