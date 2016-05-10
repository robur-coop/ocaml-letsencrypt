let encode priv data nonce =
  let pub = Primitives.pub_of_priv priv in
  let jwk = Jwk.encode pub in
  let protected =
    Printf.sprintf {|{"alg":"RS256","jwk":%s,"nonce":"%s"}|}
                   jwk nonce
    |> B64u.urlencode in
  let payload = B64u.urlencode data in
  let signature =
    let m = Cstruct.of_string (protected ^ "." ^ payload) in
    Primitives.sign priv m |> Cstruct.to_string |> B64u.urlencode in
  Printf.sprintf {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
                 protected payload signature

let jws_protected maybe_protected =
  let header_error = fun m s -> false in
  match Json.of_string maybe_protected with
  | None -> header_error
  | Some protected ->
     match Json.json_member "jwk" protected with
     | None -> header_error
     | Some jwk ->
        match Jwk.decode_json jwk with
        | None -> header_error
        | Some pub -> Primitives.verify pub


let decode data =
  match Json.of_string data with
  | None -> None
  | Some jws ->
     let maybe_protected64 = Json.string_member "protected" jws in
     let maybe_payload64 = Json.string_member "payload" jws in
     let maybe_signature = Json.b64_string_member "signature" jws in
     match maybe_protected64, maybe_payload64, maybe_signature with
     | Some protected64, Some payload64, Some signature ->
        let jws_verify = jws_protected (B64u.urldecode protected64) in
        let m = Cstruct.of_string (protected64 ^ "." ^ payload64) in
        let signature = Cstruct.of_string signature in
        if jws_verify m signature then
          Some (B64u.urldecode payload64)
        else
          None
     | _ -> None
