open Acme.Client
open Cmdliner
open Lwt

(* XXX. Perhaps there's a more decent way in OCaml for reading a file? *)
let read_file filename =
  let bufsize = 32768 in
  let ic = open_in filename in
  let ret = Bytes.make bufsize '\000' in
  input ic ret 0 bufsize |> ignore;
  ret

let rsa_pem_arg =
  let doc = "File containing the PEM-encoded RSA private key." in
  Arg.(value & opt string "priv.key" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem_arg =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "certificate.csr" & info ["csr"] ~docv:"FILE" ~doc)

let main rsa_pem csr_pem  =
  let rsa_pem = read_file rsa_pem in
  let csr_pem = read_file csr_pem in
  let domain = "www.tumbolandia.net" in
  match Lwt_main.run (get_crt rsa_pem csr_pem domain) with
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
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Info);
  let acme_client_t = Term.(const main $ rsa_pem_arg $ csr_pem_arg) in
  match Term.eval (acme_client_t, info) with
  | `Error _ -> exit 1
  | _        -> exit 0
