open Cohttp
open Cohttp_lwt_unix
open Lwt

open Acme_common

module Pem = X509.Encoding.Pem

type t = {
    account_key: Primitives.priv;
    csr:  X509.CA.signing_request;
    mutable next_nonce: string;
    d: directory_t;
  }

type challenge_t = {
    url: Uri.t;
    token: string;
  }

let malformed_json j =
  let msg = Printf.sprintf "malformed json: %s" (Json.to_string j) in
  Error msg

let error_in endpoint code body =
  let body = String.escaped body in
  let errf = Printf.sprintf "Error at %s: code %d - body: %s" in
  let msg = errf endpoint code body in
  return_error msg

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

let get_header_or_fail name headers =
  match Header.get headers name with
  | Some nonce -> return nonce
  | None -> fail_with "Error: I could not fetch a new nonce."

let extract_nonce =
  get_header_or_fail "Replay-Nonce"

let discover directory_url =
  let directory = Uri.of_string directory_url in
  http_get directory >>= fun (code, headers, body) ->
  extract_nonce headers  >>= fun nonce ->
  match Json.of_string body with
  | None -> error_in "discovery" code body
  | Some edir ->
     let p m = Json.string_member m edir in
     match p "new-authz", p "new-reg", p "new-cert", p "revoke-cert" with
     | Some new_authz, Some new_reg, Some new_cert, Some revoke_cert ->
        let u = Uri.of_string in
        let directory_t = {
            directory = directory;
            new_authz = u new_authz;
            new_reg = u new_reg;
            new_cert = u new_cert;
            revoke_cert = u revoke_cert} in
        return_ok (nonce, directory_t)
     | _, _, _, _ ->
        return (malformed_json edir)

let new_cli directory_url rsa_pem csr_pem =
  let maybe_rsa = Primitives.priv_of_pem rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct (Cstruct.of_string csr_pem) in
  match maybe_rsa, maybe_csr with
  | None, _ -> return_error "Error parsing account key."
  | Some x, [] -> return_error "Error parsing signing request."
  | Some x, y0 :: y1 :: ys -> return_error "Error: too many signing requests."
  | Some account_key, [csr] ->
       discover directory_url >>= function
       | Error e -> return_error e
       | Ok (next_nonce, d)  ->
          return_ok {account_key; csr; next_nonce; d}


let http_post_jws cli data url =

  let http_post key nonce data url =
    let body = Jws.encode key data nonce  in
    let body_len = string_of_int (String.length body) in
    let header = Header.init () in
    let header = Header.add header "Content-Length" body_len in
    let body = Cohttp_lwt_body.of_string body in
    Client.post ~body:body ~headers:header url
  in
  http_post cli.account_key cli.next_nonce data url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  Logs.debug (fun m -> m "Got code: %d - body %s" code (String.escaped body));
  extract_nonce headers >>= fun next_nonce ->
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
  http_post_jws cli body url >>= fun (code, headers, body) ->
  (* here the "Location" header contains the registration uri.
   * However, it seems for a simple client this information is not necessary.
   * Also, in a bright future these prints should be transformed in logs.*)
  match code with
  | 201 -> Logs.info (fun m -> m "Account created.");  return_ok ()
  | 409 -> Logs.info (fun m -> m "Already registered."); return_ok ()
  | _   -> error_in "new-reg" code body


let get_http01_challenge authorization =
  match Json.list_member "challenges" authorization with
  | None -> malformed_json authorization
  | Some challenges ->
     let is_http01 c = Json.string_member "type" c = Some"http-01" in
     match List.filter is_http01 challenges with
     | []  -> Error "No supported challenges found."
     | challenge :: _ ->
        let token = Json.string_member "token" challenge in
        let url = Json.string_member "uri" challenge in
        match token, url with
        | Some t, Some u -> Ok {token=t; url=Uri.of_string u}
        | _, _ -> malformed_json authorization


let do_http01_challenge cli challenge acme_dir =
  let token = challenge.token in
  let pk = Primitives.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint (`Rsa pk) in
  let path = acme_dir ^ token in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  write_string path key_authorization;
  return_ok ()


let new_authz cli domain =
  let url = cli.d.new_authz in
  let body = Printf.sprintf
    {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
    domain in
  http_post_jws cli body url >>= fun (code, headers, body) ->
  match code with
  | 201 ->
     begin
       match Json.of_string body with
       | Some authorization -> return (get_http01_challenge authorization)
       | None -> error_in "new-auth" code body
     end
  (* XXX. any other codes to handle? *)
  | _ -> error_in "new-authz" code body


let challenge_met cli challenge =
  let token = challenge.token in
  let pub = Primitives.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint (`Rsa pub) in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  let data =
    Printf.sprintf {|{"resource": "challenge", "keyAuthorization": "%s"}|}
                   key_authorization in
  http_post_jws cli data challenge.url >>= fun _ ->
  (* XXX. here we should deal with the resulting codes, at least. *)
  return_ok ()


let poll_challenge_status cli challenge =
  http_get challenge.url >>= fun (code, headers, body) ->
  match Json.of_string body with
  | Some challenge_status ->
     begin
       let status =  Json.string_member "status" challenge_status in
       match status with
       | Some "valid" -> return_ok false
       | Some "pending"
       (* «If this field is missing, then the default value is "pending".» *)
       | None -> return_ok true
       | Some status -> error_in "polling" code body
     end
  | _ -> error_in "polling" code body


let rec poll_until ?(sec=10) cli challenge =
  poll_challenge_status cli challenge >>= function
  | Error e  -> return_error e
  | Ok false -> return_ok ()
  | Ok true  ->
     Logs.info (fun m -> m "Polling...");
     Unix.sleep sec;
     poll_until cli challenge


let der_to_pem der =
  let der = Cstruct.of_string der in
  match X509.Encoding.parse der with
  | Some crt ->
     let pem = Pem.Certificate.to_pem_cstruct [crt] |> Cstruct.to_string in
     Ok pem
  | None ->
     Error "I got gibberish while trying to decode the new certificate."


let new_cert cli =
  let url = cli.d.new_cert in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  http_post_jws cli data url >>= fun (code, headers, body) ->
  match code with
  | 201 -> return (der_to_pem body)
  | _ -> error_in "new-cert" code body


let get_crt directory_url rsa_pem csr_pem acme_dir domain =
  Nocrypto_entropy_lwt.initialize () >>= fun () ->
  let open Lwt_result in
  new_cli directory_url rsa_pem csr_pem >>= fun cli ->
  new_reg cli >>= fun () ->
  new_authz cli domain >>= fun challenge ->
  do_http01_challenge cli challenge acme_dir >>= fun () ->
  challenge_met cli challenge >>= fun () ->
  poll_until cli challenge >>= fun () ->
  new_cert cli >>= fun pem -> return_ok pem
