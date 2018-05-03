open Lwt


(* XXX. Perhaps there's a more decent way in OCaml for reading a file? *)
(* XXX. we are not dealing with exceptions here. *)
let read_file filename =
  let bufsize = 32768 in
  let ic = open_in filename in
  let ret = Bytes.make bufsize '\000' in
  input ic ret 0 bufsize |> ignore;
  Bytes.to_string ret

module Acme_cli = Acme_client.Make(Cohttp_lwt_unix.Client)


let run rsa_pem csr_pem directory solver =
  Nocrypto_entropy_lwt.initialize () >>= fun () ->
  Acme_cli.get_crt rsa_pem csr_pem ~directory ~solver

let main _ rsa_pem csr_pem acme_dir ip key =
  let rsa_pem = read_file rsa_pem in
  let csr_pem = read_file csr_pem in
  match Astring.String.cut ~sep:":" key with
  | None -> Logs.err (fun m -> m "couldn't parse key")
  | Some (name, key) -> match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
    | _, None | Error _, _ -> Logs.err (fun m -> m "no key")
    | Ok name, Some key ->
      let solver = Acme_client.default_dns_solver (Unix.inet_addr_of_string ip) name key in
      let directory = Acme_common.letsencrypt_url in
      match Lwt_main.run (run rsa_pem csr_pem directory solver) with
      | Error e ->
        Logs.err (fun m -> m "Error: %s" e)
      | Ok pem ->
        Logs.info (fun m -> m "Certificate downloaded");
        print_endline pem

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ())

open Cmdliner

let rsa_pem =
  let doc = "File containing the PEM-encoded RSA private key." in
  Arg.(value & opt string "priv.key" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "certificate.csr" & info ["csr"] ~docv:"FILE" ~doc)

let acme_dir =
  let default_path = "/var/www/html/.well-known/acme-challenge/" in
  let doc =
    "Base path for where to write challenges. " ^
    "For letsencrypt, it must be the one serving " ^
    "http://example.com/.well-known/acme-challenge/" in
  Arg.(value & opt string default_path & info ["acme_dir"] ~docv:"DIR" ~doc)

let ip =
  let doc = "ip address of DNS server" in
  Arg.(value & opt string "" & info ["ip"] ~doc)

let key =
  let doc = "nsupdate key" in
  Arg.(value & opt string "" & info ["key"] ~doc)

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let info =
  let doc = "just another ACME client" in
  let man = [
      `S "DESCRIPTION"; `P "This is software is experimental. Don't use it.";
      `S "BUGS"; `P "Email bug reports to <maker@tumbolandia.net>";
    ] in
  Term.info "oacmel" ~version:"%%VERSION%%" ~doc ~man

let () =
  let cli = Term.(const main $ setup_log $ rsa_pem $ csr_pem $ acme_dir $ ip $ key) in
  match Term.eval (cli, info) with
  | `Error _ -> exit 1
  | _        -> exit 0
