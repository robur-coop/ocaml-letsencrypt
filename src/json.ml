module J = Yojson.Basic

type t = J.json

let of_string s =
  try
    Some (J.from_string s)
  with
  | Yojson.Json_error _ -> None

let string_member member json =
  match J.Util.member member json with
  | `String s -> Some s
  | _ -> None

let list_member member json =
  match J.Util.member member json with
  | `List l -> Some l
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

let rec string_of_list sep = function
  | [] -> ""
  | [x] -> x
  | x :: xs -> x ^ sep ^ (string_of_list sep xs)

(* Serialize a json object without having spaces around. Dammit Yojson. *)
(* XXX. I didn't pay enough attention on escaping.
 * It is possible that this is okay; however, our encodings are nice. *)
let rec to_string ?(comma = ",") ?(colon = ":") = function
  | `Null -> ""
  | `String s -> Printf.sprintf {|"%s"|} (String.escaped s)
  | `Stringlit s -> s
  | `Bool b -> if b then "true" else "false"
  | `Float f -> string_of_float f
  | `Floatlit s -> s
  | `Int i -> string_of_int i
  | `Intlit s -> s
  | `Tuple l
  | `List l ->
    let s = List.map (to_string ~comma ~colon) l in
     "[" ^ (string_of_list comma s) ^ "]"
  | `Assoc a ->
    let serialize_pair (key, value) =
      let sval = (to_string ~comma ~colon) value in
      "\"" ^ key ^ "\"" ^ colon ^ sval
    in
    let s = List.map serialize_pair a in
    "{" ^ (string_of_list comma s) ^ "}"
  | `Variant -> "WHAT IS THIS"
