type jws_header_t = {
    alg: string;
    nonce: string option;
    jwk: Jwk.key_t;
  }

let encode priv data nonce =
  let pub = Primitives.pub_of_priv priv in
  let jwk = Jwk.encode pub in
  let protected =
    Printf.sprintf {|{"alg":"RS256","jwk":%s,"nonce":"%s"}|}
                   jwk nonce
    |> B64u.urlencode in
  let payload = B64u.urlencode data in
  let signature =
    let m = protected ^ "." ^ payload in
    Primitives.rs256_sign priv m |> B64u.urlencode in
  Printf.sprintf {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
                 protected payload signature

let decode_header protected_header =
  match Json.of_string protected_header with
  | None -> None
  | Some protected ->
     let maybe_jwk = Json.json_member "jwk" protected in
     let maybe_alg = Json.string_member "alg" protected in
     let nonce = Json.string_member "nonce" protected in
     match maybe_jwk, maybe_alg with
     | _, None -> None
     | None, Some alg -> Some {alg; nonce; jwk=`Null}
     | Some jwk, Some alg -> Some {alg; nonce; jwk= Jwk.decode_json jwk}

let decode ?(pub=`Null) data =
  match Json.of_string data with
  | None -> None
  | Some jws ->
     let maybe_protected64 = Json.string_member "protected" jws in
     let maybe_payload64 = Json.string_member "payload" jws in
     let maybe_signature = Json.b64_string_member "signature" jws in
     match maybe_protected64, maybe_payload64, maybe_signature with
     | None, _, _
     | _, None, _
     | _, _, None -> None
     | Some protected64, Some payload64, Some signature ->
        let maybe_protected = decode_header (B64u.urldecode protected64) in
        match maybe_protected with
        | None -> None
        | Some protected ->
          let m = protected64 ^ "." ^ payload64 in
          let signature = signature in
          let pub = if pub != `Null then pub else protected.jwk in
          let verify =
            match protected.alg, pub with
            | "RS256", `Rsa pub ->
               Primitives.rs256_verify pub
            | _ -> (fun m s -> false)
          in
          if verify m signature then
            Some (protected, B64u.urldecode payload64)
          else
            None
