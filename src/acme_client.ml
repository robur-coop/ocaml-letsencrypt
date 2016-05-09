open Cohttp
open Cohttp_lwt_unix
open Lwt
open Nocrypto

module Json = Yojson.Basic
module Pem = X509.Encoding.Pem

type client_t = {
    ca: string;
    account_key: Primitives.priv;
    csr:  X509.CA.signing_request;
    mutable next_nonce: string;
  }

type challenge_t = {
    uri: string;
    token: string;
  }

(** I guess for now we can leave a function here of type
 * bytes -> bytes -> unit
 * to handle the writing of the challenge into a file. *)
let write_string filename data =
  let oc = open_out filename in
  Printf.fprintf oc "%s" data;
  close_out oc

let http_get url =
  Client.get (Uri.of_string url) >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >>= fun body ->
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

let get_header_or_fail name headers =
  match Header.get headers name with
  | Some nonce -> return nonce
  | None -> fail_with "Error: I could not fetch a new nonce."

let extract_nonce =
  get_header_or_fail "Replay-Nonce"

let new_nonce from =
    discover from >>= fun (headers, body) ->
    extract_nonce headers

let new_cli ?(ca="https://acme-v01.api.letsencrypt.org") rsa_pem csr_pem =
  let maybe_rsa = Primitives.priv_of_pem rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct csr_pem in
  match maybe_rsa, maybe_csr with
    | Some account_key, [csr] ->
       new_nonce ca >>= fun next_nonce ->
       `Ok {account_key; csr; ca; next_nonce} |> return
    | _ ->
       fail_with "Error: there's a problem paring those pem files."

let cli_recv = http_get

let cli_send cli data url =
  http_post_jws cli.account_key cli.next_nonce data url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  extract_nonce headers >>= fun next_nonce ->
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  (* XXX: is this like cheating? *)
  cli.next_nonce <- next_nonce;
  return (code, headers, body)

let new_reg cli =
  let url = cli.ca ^ "/acme/new-reg" in
  let body =
    {|{"resource": "new-reg", "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"}|}
  in
  cli_send cli body url >>= fun (code, headers, body) ->
  (* here the "Location" header contains the registration uri.
   * However, it seems for a simple client this information is not necessary.
   * Also, in a bright future these prints should be transformed in logs.*)
  match code with
  | 201 -> Logs.info (fun m -> m "Account created."); return_nil
  | 409 -> Logs.info (fun m -> m "Already registered."); return_nil
  | _   ->
     let err_msg = Printf.sprintf "Error: shit happened in registration. Error code %d; body %s"
                                  code body in
     fail_with err_msg

let get_http01_challenge authorization =
  let challenges = Json.Util.member "challenges" authorization |> Json.Util.to_list in
  let is_http01 c = Json.Util.member "type" c = `String "http-01" in
  match List.filter is_http01 challenges with
  | []  -> fail_with "No supported challenges found."
  | challenge :: _ ->
     let token = Json.Util.member "token" challenge |> Json.Util.to_string in
     let uri = Json.Util.member "uri" challenge |> Json.Util.to_string in
     return {token; uri}

let do_http01_challenge cli challenge =
  let token = challenge.token in
  let pk = Rsa.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint pk in
  let path = token in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  Printf.printf "Now put %s in a file named \"%s\"" key_authorization path;
  return_nil

let new_authz cli domain =
  let url = cli.ca ^ "/acme/new-authz" in
  let body = Printf.sprintf
    {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
    domain in
  cli_send cli body url >>= fun (code, headers, body) ->
  let authorization = Json.from_string body in
  get_http01_challenge authorization

let challenge_met cli challenge =
  let token = challenge.token in
  let pub = Rsa.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint pub in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  let data =
    Printf.sprintf {|{"resource": "challenge", "keyAuthorization": "%s"}|}
                   key_authorization in
  cli_send cli data challenge.uri

let pool_challenge_status cli challenge =
  cli_recv challenge.uri >>= fun (code, headers, body) ->
  let challenge_status = Json.from_string body in
  let status = Json.Util.member "status" challenge_status |> Json.Util.to_string in
  match status with
  | "valid" -> return_true
  | "pending" -> return_false
  | _ -> fail_with "I got gibberish while polling for challange status."

let new_cert cli =
  (* formulate the request *)
  let url = cli.ca ^ "/acme/new-cert" in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  cli_send cli data url >>= fun (code, headers, body) ->
  (* process the response *)
  let der = B64u.urldecode body |> Cstruct.of_string in
  match X509.Encoding.parse der with
  | Some crt ->
     let pem = Pem.Certificate.to_pem_cstruct [crt] |> Cstruct.to_string in
     print_endline pem |> return
  | None -> fail_with "I got gibberish while trying to decode the new certificate."
