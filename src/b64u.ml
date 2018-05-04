open Astring

let trim_leading_null s =
  String.trim ~drop:(function '\000' -> true | _ -> false) s

(** byte reversing *)
let rev s = Astring.String.(fold_left (fun acc c -> of_char c ^ acc) "" s)

let urlencode = B64.encode ~pad:false ~alphabet:B64.uri_safe_alphabet

let urldecode s =
  try Ok (B64.decode ~alphabet:B64.uri_safe_alphabet s)
  with Not_found -> Error ("bad base64 encoding " ^ s)

let urlencodez z = urlencode (trim_leading_null (rev (Z.to_bits z)))

let urldecodez z64 =
  let open Rresult.R.Infix in
  urldecode z64 >>| fun bits ->
  Z.of_bits (rev bits)
