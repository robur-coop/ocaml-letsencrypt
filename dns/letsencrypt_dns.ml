let src = Logs.Src.create "letsencrypt.dns" ~doc:"let's encrypt library"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (S : Letsencrypt.Client.S) = struct
include Letsencrypt.Client.Solver (S)

let ( let* ) x fn = S.bind x @@ function
  | Ok v -> fn v
  | Error _ as err -> S.return err

let ok v = S.return (Ok v)
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> S.return (Error (`Msg msg))) fmt

let dns_solver writef =
  let solve_challenge ~token:_ ~key_authorization domain =
    let solution = Letsencrypt.sha256_and_base64 key_authorization in
    let domain_name = Domain_name.prepend_label_exn domain "_acme-challenge" in
    writef domain_name solution
  in
  { challenge = Letsencrypt.Client.DNS; solve_challenge }

let print_dns =
  let solve domain solution =
    Log.warn (fun f -> f "Setup a TXT record for %a to return %s and press enter to continue"
                 Domain_name.pp domain solution);
    ignore (read_line ());
    ok ()
  in
  dns_solver solve

let nsupdate ?proto id now out ?recv ~zone ~keyname key =
  let open Dns in
  let nsupdate name record =
    Log.info (fun m -> m "solving dns by update to! %a (name %a)"
                 Domain_name.pp zone Domain_name.pp name);
    let zone = Packet.Question.create zone Rr_map.Soa
    and update =
      let up =
        Domain_name.Map.singleton name
          [
            Packet.Update.Remove (Rr_map.K Txt) ;
            Packet.Update.Add Rr_map.(B (Txt, (3600l, Txt_set.singleton record)))
      ]
      in
      (Domain_name.Map.empty, up)
    and header = (id, Packet.Flags.empty)
    in
    let packet = Packet.create header zone (`Update update) in
    let* (data, mac) =
      Dns_tsig.encode_and_sign ?proto packet (now ()) key keyname
      |> Result.map_error (msgf "%a" Dns_tsig.pp_s)
      |> S.return in
    let* () = out data in
    match recv with
    | None -> (ok () : (unit, [ `Msg of string ]) result S.t)
    | Some recv ->
        let* data = recv () in
        let* res, _, _ =
          Dns_tsig.decode_and_verify (now ()) key keyname ~mac data
          |> Result.map_error (msgf "%a" Dns_tsig.pp_e)
          |> S.return in
        match Packet.reply_matches_request ~request:packet res with
        | Ok _ -> (ok () : (unit, [ `Msg of string ]) result S.t)
        | Error mismatch ->
          error_msgf "error %a expected reply to %a, got %a"
            Packet.pp_mismatch mismatch
            Packet.pp packet
            Packet.pp res
  in
  dns_solver nsupdate
end
