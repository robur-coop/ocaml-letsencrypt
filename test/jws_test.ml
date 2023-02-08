open OUnit2

open Letsencrypt__Acme_common

let testkey_pem = "
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjGBnd5E+TChG/
Lup5FRuYwN7RX7Ef15Yt27SKF54uWuYPaapZd8/0h5IoCluffiDxO4BL2DnOGrwQ
tDeSaOv4pXzoYAyAjpUBwaWrdCvOlMJ//fQBvv7NrCt9FoU41rUfATM9jUoecZWT
ElzzmA2TBgj1JjZEde2+WffOznAhM2t2iyoRd5oiRVgESFuE27nimneTGjpO5YuL
17qld5Z60TCaUHC1ZmU+iJvaPdPEsGSwpl+jIXJ6TfzSYeAkC6ZD8jZ+OP3z/3ua
TeKE5jgCBV0IOPXP8YKhmQblGrudsIbKizIpbINfTRmz6c2pWGgt4i9cLiedZ0kx
nquiDHJBAgMBAAECggEABaFh98xKtEe0QbAXOGYPc3m5tIl5teNFmhC30NIt1fKj
QFfTdUkpDuQjGarLE4DgLnb2EvtTEJL9XXEobRD8o8Mvnf/Oo4vVcjATzFTSprot
udhpKbdrcBxADkeGCU8aecCw/WpQv4E7rwQuKYx4LrBgPbrDLu6ZFMZ8hEQ+R7Zn
j0jWswOZEwM5xNHZ8RlwP4xsyFChvBR43lymHwDwQegd7ukbY0OcwXZ+2sxcKltr
LBZKKFPzMugKnMbZtwm3TRIUTDGjB+IZGU7dPXgF8cK4KR4yDRZ5HKIZWbqxCPCP
6TphI+Jz83OxpXU9R8rfPgUhnBgqwTdDpc5pGfmyiQKBgQD+I1TKDW5tF0fXWnza
Xwoe0ULUM8TRXWBJmxfb1OkzmNLiq/jor6zxibXOas5EzzH5zKd8/HVVBlDfgRh4
IwhfbXavIn7MMBOXg0TQjia4y9KIf2/HpdzsWaE2dpjM+wEvlOb2ea1C4/T1gSfy
miI4kWIOz/iiWcPmiADk7hMcaQKBgQDkwgupZgFS6psRYtG0yu5S2kBJyWsGo02w
kSwwZt6oEmagzF0d5JlyRss6uqbsaUzI1Ek17/m5ZEZLNoxi4abCw+kRHOoS9gWd
KumNbli1dn4m3EVc1V+b1nWAsuC8ak5QIhRFumgNyQN7W+BS6TfLn4ONmKGz6uog
njlfNdPMGQKBgFa5/ex6Cu4lnLmsQqFO/6gmp5S9GfSM1hgoWksF7JNUGtuJ7oaR
tQY0hZusrTmkL5zcr2eiy/O5FQ5BAvW0lt3iADeiIP1ThswU2v4FFMfJns5AFwhd
3Pe3WqG4dUq2eeAgA3Wnbm4+VtEVQ2myGe2OB5WgeWwGEClyzkNRz6nJAoGAPN4c
+D/6DjP6es/OeMqeS1FjVb7QSX3eSCL4nRBiIlpzEEoQZMnUwoFvxfqwO6txEObb
bAykZ930jkK/a/gaxSwXscP9zHnF2KH4bvdzhyU2P+TQV/k2bWLM9SejgL7Qg6Xt
uvf0g+Z+lK5HrAf+HqIdAOoh7JuPHIq9PUY3StECgYEAoYP7hkj8TUygnkJcHxwM
MwdqBsTdyr8O2ZjMTa/UMWlBi7kjg8KblzsRB4g/p1m2/wgyC0Yhv3VBf2le8/Rr
OfNArBggDydmCgQ0I9+IxM+IQNP17/SU5s71daxeltJOxE+PSy/WsH5TMEnQ+CMr
irbM4XSw2jtvX7qeUzcFY/E=
-----END PRIVATE KEY-----
"

let expected_protected =
  "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZuaWN4emg2V0VUUWxydmRj" ^
  "aGt6LVUzZTNET1FaNGhlSktVNjNyZnFNcVEiLCJqd2siOnsiZSI6" ^
  "IkFRQUIiLCJuIjoiNHhnWjNlUlBrd29Sdnk3cWVSVWJtTURlMFYt" ^
  "eEg5ZVdMZHUwaWhlZUxscm1EMm1xV1hmUDlJZVNLQXBibjM0ZzhU" ^
  "dUFTOWc1emhxOEVMUTNrbWpyLUtWODZHQU1nSTZWQWNHbHEzUXJ6" ^
  "cFRDZl8zMEFiNy16YXdyZlJhRk9OYTFId0V6UFkxS0huR1ZreEpj" ^
  "ODVnTmt3WUk5U1kyUkhYdHZsbjN6czV3SVROcmRvc3FFWGVhSWtW" ^
  "WUJFaGJoTnU1NHBwM2t4bzZUdVdMaTllNnBYZVdldEV3bWxCd3RX" ^
  "WmxQb2liMmozVHhMQmtzS1pmb3lGeWVrMzgwbUhnSkF1bVFfSTJm" ^
  "amo5OF85N21rM2loT1k0QWdWZENEajF6X0dDb1prRzVScTduYkNH" ^
  "eW9zeUtXeURYMDBacy1uTnFWaG9MZUl2WEM0bm5XZEpNWjZyb2d4" ^
  "eVFRIiwia3R5IjoiUlNBIiwia2lkIjoiNm5pY3h6aDZXRVRRbHJ2" ^
  "ZGNoa3otVTNlM0RPUVo0aGVKS1U2M3JmcU1xUSIsIng1dCI6Ijk4" ^
  "WEZNbUZxRWtrb0RudTdHSjhjRFdGaTJJWSJ9LCJub25jZSI6Im5v" ^
  "bmNlIn0"

let expected_payload = "eyJNc2ciOiJIZWxsbyBKV1MifQ"

let expected_signature =
  "qv79C1SFoz_7EWt7WVIhg5kVBPbCK__Xa1kFtodtS7hD78KvRQrU" ^
  "Cx4Usa5T6PrFKmutXumyArjW3RxwRa1ATKo7g8k-F0TeUELXsZic" ^
  "fLs_5jHu8vj3g47_mlhjMg9oJ6YNDVdhg3Gm19ZXgm6W_WlnM8wC" ^
  "2dUVVSVYLxP7Hk2b6urM_tXJ3HtWRHbmQtD8hxQaMCNzz99usPvA" ^
  "I1SW5b-I1rK0dxIOZ205Kce4VtLgEVs9hz45b4t93-g0bP1clHCU" ^
  "iNKf-vzOs_45H1EKkxEpGDO5fQkeNfoQxTsE03AnB9SZXiF-ApDW" ^
  "QMz_4f3YJ9YhRVB1iXx9vgAMkqhTaQ"

let rsa_key () =
  match X509.Private_key.decode_pem (Cstruct.of_string testkey_pem) with
  | Ok `RSA skey -> `RSA skey
  | Ok _ -> assert_failure "unsupported key type"
  | Error `Msg e -> assert_failure e

let string_member key json =
  match Yojson.Safe.Util.member key json with
  | `String s -> Ok s
  | _ -> Error (`Msg (Fmt.str "couldn't find string %s in %a"
                        key Yojson.Safe.pp json))

let json_of_string s =
  try Ok (Yojson.Safe.from_string s) with
    Yojson.Json_error str -> Error (`Msg str)

let decode_printer = function
| Error `Invalid_signature -> "invalid signature"
| Error `Not_json -> "not json"
| Error `Not_supported -> "format not supported"
| Error (`Msg e) -> e
| Ok (_, payload) -> payload

let jws_encode_somedata () =
  let priv_key = rsa_key () in
  let data  = {|{"Msg":"Hello JWS"}|} in
  let nonce = "nonce" in

  let jwk = Jose.Jwk.of_priv_x509 priv_key |> Result.get_ok in
  let protected = [ "jwk", Jwk.encode jwk ] in
  let jws = Jws.encode ~protected ~data ~nonce jwk in
  match json_of_string jws with
  | Ok json -> json
  | Error (`Msg e) -> assert_failure e

let test_member member expected _ctx =
  let jws = jws_encode_somedata () in
  match string_member member jws with
  | Ok protected -> assert_equal expected protected ~printer:(fun s -> s)
  | Error (`Msg e) -> assert_failure e

let test_encode_protected = test_member "protected" expected_protected
let test_encode_payload = test_member "payload" expected_payload
let test_encode_signature = test_member "signature" expected_signature

let test_decode_null _ctx =
  assert_equal (Jws.decode "{}") (Error (`Msg "token didn't include header, payload or signature"))

let jws_decode_somedata () =
  let data = Printf.sprintf
      {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
      expected_protected expected_payload expected_signature in
  Jws.decode data

let test_decode_rsakey _ctx =
  let jws = jws_decode_somedata () in
  let key = rsa_key () in
  match jws with
  | Error `Invalid_signature -> assert_failure "invalid signature"
  | Error `Not_json -> assert_failure "not json"
  | Error `Not_supported -> assert_failure "format not supported"
  | Error (`Msg e) -> assert_failure e
  | Ok (protected, _payload) ->
    let pub = X509.Private_key.public key |> Jose.Jwk.of_pub_x509 |> Result.get_ok in
    assert_equal protected.Jose.Header.jwk (Some pub)

(* XXX. at this stage we probably wont the expected payload to be on some
 * global variable. *)
let test_decode_payload _ctx =
  match jws_decode_somedata () with
  | Error `Invalid_signature -> assert_failure "invalid signature"
  | Error `Not_json -> assert_failure "not json"
  | Error `Not_supported -> assert_failure "format not supported"
  | Error (`Msg e) -> assert_failure e
  | Ok (_, payload) ->
    assert_equal payload {|{"Msg":"Hello JWS"}|} ~printer:(fun s -> s)

let rfc7520_payload =
  "It\xe2\x80\x99s a dangerous business, Frodo, going out your " ^
  "door. You step onto the road, and if you don't keep your feet, " ^
  "there\xe2\x80\x99s no knowing where you might be swept off " ^
  "to."

let rfc7520_4_1_rsa_pkcs_sign _ctx =
  let key =
    (* Section 3.4, Figure 4 *)
    let decode_z str =
      match Letsencrypt__B64u.urldecodez str with Ok x -> x | Error _ -> assert false
    in
    let e = decode_z "AQAB"
    and p = decode_z
        ("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" ^
         "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" ^
         "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" ^
         "bUq0k")
    and q = decode_z
        ("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" ^
         "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" ^
         "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" ^
         "s7pFc")
    in
    match Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q with
    | Ok p -> Jose.Jwk.make_priv_rsa ~use:`Sig p
    | Error _ -> assert false
  in
  let b64_payload =
    "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" ^
    "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" ^
    "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" ^
    "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
  in
  assert_equal b64_payload (Letsencrypt__B64u.urlencode rfc7520_payload);
  let protected = [ "kid", `String "bilbo.baggins@hobbiton.example" ] in
  let rfc_out =
    let signature =
      "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK" ^
      "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J" ^
      "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w" ^
      "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP" ^
      "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f" ^
      "cIe8u9ipH84ogoree7vjbU5y18kDquDg"
    and prot_header =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" ^
      "hhbXBsZSJ9"
    in
    json_to_string (`Assoc [
        ("payload", `String b64_payload) ;
        ("protected", `String prot_header) ;
        ("signature", `String signature) ;
      ])
  in
  let signature = Jws.encode ~protected ~data:rfc7520_payload key in
  assert_equal rfc_out signature ~printer:(fun a -> a)
let rfc7520_4_3_es512_sign _ctx =
  let key =
    let d =
      match Letsencrypt__B64u.urldecode
        ("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" ^
         "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")
      with
      | Ok d -> Cstruct.of_string d
      | Error _ -> assert false
    in
    match Mirage_crypto_ec.P521.Dsa.priv_of_cstruct d with
    | Ok k -> k
    | Error _ -> assert false
  in
  let pub = Mirage_crypto_ec.P521.Dsa.pub_of_priv key in
  let cs = Mirage_crypto_ec.P521.Dsa.pub_to_cstruct pub in
  let x, y = Cstruct.split cs ~start:1 66 in
  let rfc_x = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"
  and rfc_y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
  in
  assert_equal rfc_x (Letsencrypt__B64u.urlencode (Cstruct.to_string x)) ~printer:(fun a -> a);
  assert_equal rfc_y (Letsencrypt__B64u.urlencode (Cstruct.to_string y)) ~printer:(fun a -> a);
  let rfc_signature =
    "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNl" ^
    "aAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mt" ^
    "PBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBp" ^
    "HABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
  in
  let data =
    let prot_header =
      `Assoc [ "alg", `String "ES512" ; "kid", `String "bilbo.baggins@hobbiton.example" ]
      |> json_to_string |> Letsencrypt__B64u.urlencode
    in
    assert_equal "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" prot_header ~printer:(fun a -> a);
    json_to_string ~comma:", " ~colon:": " (`Assoc [
        ("protected", `String prot_header) ;
        ("payload", `String (Letsencrypt__B64u.urlencode rfc7520_payload)) ;
        ("signature", `String rfc_signature) ;
      ])
  in
  print_endline data;
  let jwk = Jose.Jwk.of_pub_x509 (`P521 pub) |> Result.get_ok in
  match Jws.decode ~pub:jwk data with
  | Ok _ -> ()
  | Error `Invalid_signature -> print_endline "invalid signature"; assert_failure "invalid signature"
  | Error `Not_json -> print_endline "not json";  assert_failure "not json"
  | Error `Not_supported -> print_endline "format not supported";  assert_failure "format not supported"
  | Error (`Msg e) -> print_endline e;  assert_failure e


let all_tests = [
  "test_encode_protected" >:: test_encode_protected;
  "test_encode_payload" >:: test_encode_payload;
  "test_encode_signature" >:: test_encode_signature;

  "test_decode_null" >:: test_decode_null;
  "test_decode_rsakey" >:: test_decode_rsakey;
  "test_decode_payload" >:: test_decode_payload;

  "rfc_7520_4_1_rsa_pkcs_sign" >:: rfc7520_4_1_rsa_pkcs_sign;
  "rfc_7520_4_3_es512_sign" >:: rfc7520_4_3_es512_sign;
]
