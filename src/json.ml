module J = Yojson.Basic

let of_string s =
  try
    Some (J.from_string s)
  with
  | Yojson.Json_error _ -> None

let string_member member json =
  match J.Util.member member json with
  | `String s -> Some s
  | _ -> None

let json_member member json =
  match J.Util.member member json with
  | `Assoc j -> Some (`Assoc j)
  | _ -> None

let b64_z_member member json =
  match string_member member json with
  | Some s -> Some (B64u.urldecodez s)
  | None -> None

let b64_string_member member json =
  match string_member member json with
  | Some s -> Some (B64u.urldecode s)
  | None -> None
