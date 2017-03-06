open Cmdliner
open Lwt


let default_directory_url = Acme_common.letsencrypt_staging_url

(* XXX. Perhaps there's a more decent way in OCaml for reading a file? *)
(* XXX. we are not dealing with exceptions here. *)
let read_file filename =
  let bufsize = 32768 in
  let ic = open_in filename in
  let ret = Bytes.make bufsize '\000' in
  input ic ret 0 bufsize |> ignore;
  ret

let prettify_dns_solver printf token key =
  let dns_string data =
    Printf.sprintf "_acme-challenge.DOMAIN. 300 IN TXT \"%s\"\n" data
  in
  let ka_hash = Primitives.sha256 key in
  let b64_ka_hash = B64u.urlencode ka_hash in
  dns_string b64_ka_hash |> printf

let default_dns_solver = prettify_dns_solver print_endline

let default_http_solver token key =
  let write_string filename data =
    let oc = open_out filename in
    Printf.fprintf oc "%s" data;
    close_out oc
  in
  let path = (*acme_dir ^ *) token in
  write_string path key

let rsa_pem_arg =
  let doc = "File containing the PEM-encoded RSA private key." in
  Arg.(value & opt string "priv.key" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem_arg =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "certificate.csr" & info ["csr"] ~docv:"FILE" ~doc)

let acme_dir_arg =
  let default_path = "/var/www/html/.well-known/acme-challenge/" in
  let doc =
    "Base path for where to write challenges. " ^
    "For letsencrypt, it must be the one serving " ^
    "http://example.com/.well-known/acme-challenge/" in
  Arg.(value & opt string default_path & info ["acme_dir"] ~docv:"DIR" ~doc)

let debug_arg =
  let doc = "Turn on debug logging." in
  Arg.(value & flag & info ["v"] ~doc)

let main rsa_pem csr_pem acme_dir debug =
  let log_level = if debug then Logs.Debug else Logs.Info in
  let rsa_pem = read_file rsa_pem in
  let csr_pem = read_file csr_pem in
  let f =
    Acme.Client.get_crt default_directory_url rsa_pem csr_pem default_dns_solver
  in
  Logs.set_level (Some log_level);
  Logs.set_reporter (Logs_fmt.reporter ());
  match Lwt_main.run f with
  | Error e ->
     Logs.err (fun m -> m "Error: %s" e)
  | Ok pem ->
     Logs.info (fun m -> m "Certificate downloaded");
     print_endline pem

let info =
  let doc = "just another ACME client" in
  let man = [
      `S "DESCRIPTION"; `P "This is software is experimental. Don't use it.";
      `S "BUGS"; `P "Email bug reports to <maker@tumbolandia.net>";
    ] in
  Term.info "oacmel" ~version:"0.1" ~doc ~man

let () =
  let cli = Term.(const main
                  $ rsa_pem_arg
                  $ csr_pem_arg
                  $ acme_dir_arg
                  $ debug_arg) in
  match Term.eval (cli, info) with
  | `Error _ -> exit 1
  | _        -> exit 0
