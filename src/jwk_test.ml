open Nocrypto
open OUnit2

let n64 =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86" ^
  "zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5" ^
  "JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ" ^
  "MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr" ^
  "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4" ^
  "4-csFCur-kEgU8awapJzKnqDKgw"
let n = B64u.urldecodez n64

let e64 = "AQAB"
let e = B64u.urldecodez e64

let pub_key = Rsa.{n; e}


let test_encode text_ctx =
  let got = Jwk.encode pub_key in
  let expected = Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|} e64 n64 in
  assert_equal got expected

let test_thumbprint test_ctx =
  let got = Jwk.thumbprint pub_key in
  let expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" in
  assert_equal got expected

let decode_example =
  let maybe_pub = Printf.sprintf {|{"e":"%s","kty":"RSA","n":"%s"}|} e64 n64
                  |> Jwk.decode in
  match maybe_pub with
  | Some pub -> pub
  | None     -> assert_failure "Error decoding."

let test_decode_e text_ctx =
  let pub = decode_example in
  assert_equal pub.Rsa.e e

let test_decode_n text_ctx =
  let pub = decode_example in
  assert_equal pub.Rsa.n n

let test_decode_badformed test_ctx =
  let s = "{" in
  assert_equal (Jwk.decode s) None

let test_decode_invalid_n test_ctx =
  let s = {|{"kty": "RSA", "e": "AQAB"}|} in
  assert_equal (Jwk.decode s) None

let test_decode_invalid_e test_ctx =
  let s = {|{"kty": "RSA", "e": 1}|} in
  assert_equal (Jwk.decode s) None

let test_decode_invalid_kty test_ctx =
  let s = {|{"kty": "invalid"}|} in
  assert_equal (Jwk.decode s) None

let all_tests = [
      "test_encode" >:: test_encode;
      "test_thumbprint" >:: test_thumbprint;
      "test_decode_e" >:: test_decode_e;
      "test_decode_n" >:: test_decode_n;
      "test_decode_invalid_kty" >:: test_decode_invalid_kty;
      "test_decode_invalid_e" >:: test_decode_invalid_e;
      "test_decode_invalid_n" >:: test_decode_invalid_n;
  ]
