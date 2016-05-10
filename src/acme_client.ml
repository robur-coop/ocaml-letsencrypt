open Cohttp
open Cohttp_lwt_unix
open Lwt
open Nocrypto

open Acme_common

module Json = Yojson.Basic
module Pem = X509.Encoding.Pem

type client_t = {
    account_key: Primitives.priv;
    csr:  X509.CA.signing_request;
    mutable next_nonce: string;
    d: directory_t;
  }

type challenge_t = {
    url: Uri.t;
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
  Client.get url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  return (code, headers, body)

let http_post_jws key nonce data url =
  let body = Jws.encode key data nonce  in
  let body_len = string_of_int (String.length body) in
  let header = Header.init () in
  let header = Header.add header "Content-Length" body_len in
  let body = Cohttp_lwt_body.of_string body in
  Client.post ~body:body ~headers:header url

let get_header_or_fail name headers =
  match Header.get headers name with
  | Some nonce -> return nonce
  | None -> fail_with "Error: I could not fetch a new nonce."

let extract_nonce =
  get_header_or_fail "Replay-Nonce"

let discover directory_url =
  let directory_url = Uri.of_string directory_url in
  http_get directory_url >>= fun (code, headers, body) ->
  extract_nonce headers  >>= fun nonce ->
  let directory =
    let dir = Json.from_string body in
    let member m = Json.Util.member m dir |> Json.Util.to_string |> Uri.of_string in
    {
      directory = directory_url;
      new_authz = member "new-authz";
      new_reg = member "new-reg";
      new_cert = member "new-cert";
      revoke_cert = member "revoke-cert";
    }
  in
  return (nonce, directory)

let new_cli ?(directory_url="https://acme-v01.api.letsencrypt.org/directory") rsa_pem csr_pem =
  let maybe_rsa = Primitives.priv_of_pem rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct csr_pem in
  match maybe_rsa, maybe_csr with
  | Some account_key, [csr] ->
     discover directory_url >>= fun (next_nonce, d)  ->
     `Ok {account_key; csr; next_nonce; d} |> return
  | _ ->
     `Error "Error: there's a problem paring those pem files." |> return

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
  let url = cli.d.new_reg in
  let body =
    (* XXX. this is letsencrypt specific. Also they are implementing acme-01
     * so it's a pain to fetch the terms. *)
    {|{"resource": "new-reg", "agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"}|}
  in
  cli_send cli body url >>= fun (code, headers, body) ->
  (* here the "Location" header contains the registration uri.
   * However, it seems for a simple client this information is not necessary.
   * Also, in a bright future these prints should be transformed in logs.*)
  match code with
  | 201 -> Logs.info (fun m -> m "Account created.");  return (`Ok ())
  | 409 -> Logs.info (fun m -> m "Already registered."); return (`Ok ())
  | _   ->
     let err_msg = Printf.sprintf "Error: shit happened in registration. Error code %d; body %s"
                                  code body in
     return (`Error err_msg)

let malformed_json j = Printf.sprintf "malformed json: %s" (Json.to_string j)

let get_http01_challenge authorization =
  let challenges_list = Json.Util.member "challenges" authorization in
  match challenges_list with
  | `List challenges ->
     begin
       let is_http01 c = Json.Util.member "type" c = `String "http-01" in
       match List.filter is_http01 challenges with
       | []  -> `Error "No supported challenges found."
       | challenge :: _ ->
          let token = Json.Util.member "token" challenge in
          let url = Json.Util.member "uri" challenge in
          match token, url with
          | `String t, `String u -> `Ok {token=t; url=Uri.of_string u}
          | _ -> `Error (malformed_json authorization)
     end
  | _ -> `Error (malformed_json authorization)

let do_http01_challenge cli challenge =
  let token = challenge.token in
  let pk = Rsa.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint pk in
  let path = token in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  Printf.printf "Now put %s in a file named \"%s\"" key_authorization path;
  return (`Ok ())

let new_authz cli domain =
  let url = cli.d.new_authz in
  let body = Printf.sprintf
    {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
    domain in
  cli_send cli body url >>= fun (code, headers, body) ->
  match code with
  | 201 ->
     let authorization = Json.from_string body in
     return (get_http01_challenge authorization)
  (* XXX. any other codes to handle? *)
  | _ ->
     let msg = Printf.sprintf "new-authz error: code %d and body: '%s'" code body in
     return (`Error msg)

let challenge_met cli challenge =
  let token = challenge.token in
  let pub = Rsa.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint pub in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  let data =
    Printf.sprintf {|{"resource": "challenge", "keyAuthorization": "%s"}|}
                   key_authorization in
  cli_send cli data challenge.url >>= fun _ ->
  (* XXX. here we should deal with the resulting codes, at least. *)
  return (`Ok ())

let poll_challenge_status cli challenge =
  cli_recv challenge.url >>= fun (code, headers, body) ->
  let challenge_status = Json.from_string body in
  let status = Json.Util.member "status" challenge_status |> Json.Util.to_string in
  match status with
  | "valid" -> return (`Ok false)
  | "pending" -> return (`Ok true)
  | _ -> return (`Error "I got gibberish while polling for challange status.")


let der_to_pem der =
  let der = Cstruct.of_string der in
  match X509.Encoding.parse der with
  | Some crt ->
     let pem = Pem.Certificate.to_pem_cstruct [crt] |> Cstruct.to_string in
     `Ok pem
  | None ->
     `Error "I got gibberish while trying to decode the new certificate."

let new_cert cli =
  (* formulate the request *)
  let url = cli.d.new_cert in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  cli_send cli data url >>= fun (code, headers, body) ->
  match code with
  | 201 ->
     let der = B64u.urldecode body in
     return (der_to_pem der)
  | _ ->
     let msg = Printf.sprintf "code %d; body '%s'" code body in
     return (`Error msg)

let get_crt rsa_pem csr_pem =
  Nocrypto_entropy_lwt.initialize () >>= fun () ->
  new_cli (Cstruct.of_string rsa_pem) (Cstruct.of_string csr_pem) >>= function
  | `Error e -> return (`Error e)
  | `Ok cli ->
     new_reg cli >>= function
     | `Error e -> return (`Error e)
     | `Ok () ->
        new_authz cli "tumbolandia.net" >>= function
        | `Error e -> return (`Error e)
        | `Ok challenge ->
           do_http01_challenge cli challenge >>= function
           | `Error e -> return (`Error e)
           | `Ok () ->
              challenge_met cli challenge >>= function
              | `Error e -> return (`Error e)
              | `Ok () ->
                 (* poll status of request *)
                 new_cert cli >>= function
                 | `Error e -> return (`Error e)
                 | `Ok pem -> return (`Ok pem)
