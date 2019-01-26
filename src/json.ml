open Rresult.R.Infix
open Astring

module J = Yojson.Basic

type t = J.json

let of_string s =
  try Ok (J.from_string s) with
    Yojson.Json_error str -> Error str

let err_msg typ name json =
  Printf.sprintf "couldn't find %s %s in %s" typ name (J.to_string json)

let string_member member json =
  match J.Util.member member json with
  | `String s -> Ok s
  | _ -> Error (err_msg "string" member json)

let list_member member json =
  match J.Util.member member json with
  | `List l -> Ok l
  | _ -> Error (err_msg "list" member json)

let json_member member json =
  match J.Util.member member json with
  | `Assoc j -> Ok (`Assoc j)
  | _ -> Error (err_msg "json object" member json)

let b64_z_member member json =
  string_member member json >>= fun s ->
  B64u.urldecodez s

let b64_string_member member json =
  string_member member json >>= fun s ->
  B64u.urldecode s

(* Serialize a json object without having spaces around. Dammit Yojson. *)
(* XXX. I didn't pay enough attention on escaping.
 * It is possible that this is okay; however, our encodings are nice. *)
let rec to_string ?(comma = ",") ?(colon = ":") = function
  | `Null -> ""
  | `String s -> Printf.sprintf {|"%s"|} (String.Ascii.escape s)
  | `Stringlit s -> s
  | `Bool b -> if b then "true" else "false"
  | `Float f -> string_of_float f
  | `Floatlit s -> s
  | `Int i -> string_of_int i
  | `Intlit s -> s
  | `Tuple l
  | `List l ->
    let s = List.map (to_string ~comma ~colon) l in
     "[" ^ (String.concat ~sep:comma s) ^ "]"
  | `Assoc a ->
    let serialize_pair (key, value) =
      let sval = (to_string ~comma ~colon) value in
      "\"" ^ key ^ "\"" ^ colon ^ sval
    in
    let s = List.map serialize_pair a in
    "{" ^ (String.concat ~sep:comma s) ^ "}"
  | `Variant -> "WHAT IS THIS"
