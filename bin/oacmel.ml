open Lwt.Infix

module C : Letsencrypt.Client.C
  with type 'a t = 'a Lwt.t
= struct
  type 'a t = 'a Lwt.t
  type ctx = unit
  type error = [ `Exn of exn ]
  type meth = [ `HEAD | `GET | `POST ]

  type response =
    { headers : (string * string) list
    ; status : int }

  let request ?ctx:_ ?meth ?headers ?body uri =
    let open Cohttp in
    let open Cohttp_lwt_unix in
    let uri = Uri.of_string uri in
    let headers = match headers with
      | Some hs -> Some (Header.of_list hs)
      | None -> None in
    Lwt.catch (fun () ->
      begin match meth with
      | Some `HEAD | None ->
        begin match meth with
        | Some `HEAD ->
          Client.head ?headers uri >>= fun resp ->
          let status = Code.code_of_status (Response.status resp) in
          let hdrs = Header.to_list (Response.headers resp) in
          let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) hdrs in
          Lwt.return_ok ({ headers = hdrs; status }, "")
        | _ ->
          Client.get ?headers uri >>= fun (resp, body) ->
          Cohttp_lwt.Body.to_string body >>= fun body_str ->
          let status = Code.code_of_status (Response.status resp) in
          let hdrs = Header.to_list (Response.headers resp) in
          let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) hdrs in
          Lwt.return_ok ({ headers = hdrs; status }, body_str)
        end
      | Some `GET ->
        Client.get ?headers uri >>= fun (resp, body) ->
        Cohttp_lwt.Body.to_string body >>= fun body_str ->
        let status = Code.code_of_status (Response.status resp) in
        let hdrs = Header.to_list (Response.headers resp) in
        let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) hdrs in
        Lwt.return_ok ({ headers = hdrs; status }, body_str)
      | Some `POST ->
        let body = Option.map Cohttp_lwt.Body.of_string body in
        Client.post ?headers ?body uri >>= fun (resp, body) ->
        Cohttp_lwt.Body.to_string body >>= fun body_str ->
        let status = Code.code_of_status (Response.status resp) in
        let hdrs = Header.to_list (Response.headers resp) in
        let hdrs = List.map (fun (k, v) -> String.lowercase_ascii k, v) hdrs in
        Lwt.return_ok ({ headers = hdrs; status }, body_str)
      end)
    (fun exn -> Lwt.return_error (`Exn exn))
end

module Acme_cli = Letsencrypt.Client.Make (Lwt) (C)
module Solver_cli = Letsencrypt.Client.Solver (Lwt)
module Dns_cli = Letsencrypt_dns.Make (Lwt)

let ( let* ) = Result.bind

let dns_out ip buf =
  let out = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let server = Lwt_unix.ADDR_INET (ip, 53) in
  Lwt_unix.sendto out (Bytes.unsafe_of_string buf) 0 (String.length buf) [] server >>= fun n ->
  (* TODO should listen for a reply from NS, report potential errors and retransmit if UDP frame got lost *)
  if n = String.length buf then Lwt.return_ok () else Lwt.return_error (`Msg "couldn't send nsupdate")

let sleep x = Lwt_unix.sleep (float_of_int x)

let doit email endpoint account_key solver sleep csr =
  Logs.app (fun m -> m "doit %s" endpoint);
  Acme_cli.initialise ~endpoint ?email account_key >>= function
  | Ok t -> Acme_cli.sign_certificate solver t sleep csr
  | Error (`Msg _ as e) -> Lwt.return_error e
  | Error (`HTTP _) -> Lwt.return_error (`Msg "HTTP error during ACME operation")

let main _ priv_pem csr_pem email solver acme_dir ip key endpoint cert zone =
  Mirage_crypto_rng_unix.use_default ();
  let r =
    let ( let* ) = Result.bind in
    let priv_pem, csr_pem, cert = Fpath.(v priv_pem, v csr_pem, v cert) in
    let* priv_pem = Bos.OS.File.read priv_pem in
    let* csr_pem = Bos.OS.File.read csr_pem in
    let* f_exists = Bos.OS.File.exists cert in
    if f_exists then
      Error (`Msg (Fmt.str "output file %a already exists" Fpath.pp cert))
    else
      let* account_key = X509.Private_key.decode_pem priv_pem in
      let* request = X509.Signing_request.decode_pem csr_pem in
      let solver =
        match solver, acme_dir, ip, key with
        | _, Some path, None, None -> (* using http solver! *)
          Logs.app (fun m -> m "using http solver, writing to %s" path);
          let solve_challenge _ ~prefix:_ ~token ~content =
            (* now, resource has .well-known/acme-challenge prepended *)
            let path = Fpath.(v path / token) in
            Lwt_result.lift (Bos.OS.File.write path content)
          in
          Solver_cli.http_solver solve_challenge
        | _, None, Some ip, Some (keyname, key) ->
          Logs.app (fun m -> m "using dns solver, writing to %a" Ipaddr.V4.pp ip);
          let ip' = Ipaddr_unix.V4.to_inet_addr ip in
          let zone = match zone with
            | None -> Domain_name.(host_exn (drop_label_exn ~amount:2 keyname))
            | Some x -> Domain_name.(host_exn (of_string_exn x))
          in
          let random_id = Randomconv.int16 Mirage_crypto_rng.generate in
          Dns_cli.nsupdate random_id Ptime_clock.now (dns_out ip') ~keyname key ~zone
        | Some `Dns, None, None, None ->
          Logs.app (fun m -> m "using dns solver");
          Dns_cli.print_dns
        | Some `Http, None, None, None ->
          Logs.app (fun m -> m "using http solver");
          Solver_cli.print_http
        | Some `Alpn, None, None, None ->
          Logs.app (fun m -> m "using alpn solver");
          Solver_cli.print_alpn
        | _ ->
          invalid_arg "unsupported combination of acme_dir, ip, and key"
      in
      match Lwt_main.run (doit email endpoint account_key solver sleep request) with
      | Error e -> Error e
      | Ok t ->
        Logs.info (fun m -> m "Certificates downloaded");
        Bos.OS.File.write cert (X509.Certificate.encode_pem_multiple t)
  in
  match r with
  | Ok _ -> Ok ()
  | Error (`Msg e) -> Error (Fmt.str "Error: %s" e)
  | Error (`HTTP _) -> Error "HTTP error"

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ())

open Cmdliner

let priv_pem =
  let doc = "File containing the PEM-encoded private key." in
  Arg.(value & opt string "account.pem" & info ["account-key"] ~docv:"FILE" ~doc)

let csr_pem =
  let doc = "File containing the PEM-encoded CSR." in
  Arg.(value & opt string "csr.pem" & info ["csr"] ~docv:"FILE" ~doc)

let acme_dir =
  let doc =
    "Base path for where to write challenges. " ^
    "For letsencrypt, it must be the one serving " ^
    "http://example.com/.well-known/acme-challenge/" in
  Arg.(value & opt (some string) None & info ["acme_dir"] ~docv:"DIR" ~doc)

let ip =
  let doc = "ip address of authoritative DNS server" in
  let ip = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  Arg.(value & opt (some ip) None & info ["ip"] ~doc)

let key =
  let doc = "nsupdate key (name:hash:b64-encoded-value)" in
  let pp_name_dnskey ppf (name, key) =
    Fmt.pf ppf "%a %a" Domain_name.pp name Dns.Dnskey.pp key
  in
  let dnskey = Arg.conv (Dns.Dnskey.name_key_of_string, pp_name_dnskey) in
  Arg.(value & opt (some dnskey) None & info ["key"] ~doc)

let endpoint =
  let doc = "ACME endpoint" in
  Arg.(value & opt string Letsencrypt.letsencrypt_staging_url & info ["endpoint"] ~doc)

let zone =
  let doc = "Zone for nsupdate packet (defaults to key with first two labels dropped)" in
  Arg.(value & opt (some string) None & info ["zone"] ~doc)

let cert =
  let doc = "filename where to store the certificate" in
  Arg.(value & opt string "certificate.pem" & info ["cert"] ~doc)

let email =
  let doc = "Contact eMail for registering new keys" in
  Arg.(value & opt (some string) None & info ["email"] ~doc)

let solver =
  let doc = "Which solver to use (printing instructions and awaits user setup). Possible values are dns, http, or alpn. Only required if acme-dir or dns credentials are not provided." in
  let solvers =
    [ ("dns", `Dns) ; ("http", `Http) ; ("alpn", `Alpn) ]
  in
  Arg.(value & opt (some (enum solvers)) None & info ["solver"] ~doc)

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
  Cmd.info "oacmel" ~version:"%%VERSION%%" ~doc ~man

let () =
  Printexc.record_backtrace true;
  let cli = Term.(const main $ setup_log $ priv_pem $ csr_pem $ email $ solver $ acme_dir $ ip $ key $ endpoint $ cert $ zone) in
  exit (Cmd.eval_result (Cmd.v info cli))
