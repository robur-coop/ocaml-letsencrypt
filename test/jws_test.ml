open OUnit2

let testkey_pem = "
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4xgZ3eRPkwoRvy7qeRUbmMDe0V+xH9eWLdu0iheeLlrmD2mq
WXfP9IeSKApbn34g8TuAS9g5zhq8ELQ3kmjr+KV86GAMgI6VAcGlq3QrzpTCf/30
Ab7+zawrfRaFONa1HwEzPY1KHnGVkxJc85gNkwYI9SY2RHXtvln3zs5wITNrdosq
EXeaIkVYBEhbhNu54pp3kxo6TuWLi9e6pXeWetEwmlBwtWZlPoib2j3TxLBksKZf
oyFyek380mHgJAumQ/I2fjj98/97mk3ihOY4AgVdCDj1z/GCoZkG5Rq7nbCGyosy
KWyDX00Zs+nNqVhoLeIvXC4nnWdJMZ6rogxyQQIDAQABAoIBACIEZTOI1Kao9nmV
9IeIsuaR1Y61b9neOF/MLmIVIZu+AAJFCMB4Iw11FV6sFodwpEyeZhx2WkpWVN+H
r19eGiLX3zsL0DOdqBJoSIHDWCCMxgnYJ6nvS0nRxX3qVrBp8R2g12Ub+gNPbmFm
ecf/eeERIVxfifd9VsyRu34eDEvcmKFuLYbElFcPh62xE3x12UZvV/sN7gXbawpP
G+w255vbE5MoaKdnnO83cTFlcHvhn24M/78qP7Te5OAeelr1R89kYxQLpuGe4fbS
zc6E3ym5Td6urDetGGrSY1Eu10/8sMusX+KNWkm+RsBRbkyKq72ks/qKpOxOa+c6
9gm+Y8ECgYEA/iNUyg1ubRdH11p82l8KHtFC1DPE0V1gSZsX29TpM5jS4qv46K+s
8Ym1zmrORM8x+cynfPx1VQZQ34EYeCMIX212ryJ+zDATl4NE0I4muMvSiH9vx6Xc
7FmhNnaYzPsBL5Tm9nmtQuP09YEn8poiOJFiDs/4olnD5ogA5O4THGkCgYEA5MIL
qWYBUuqbEWLRtMruUtpASclrBqNNsJEsMGbeqBJmoMxdHeSZckbLOrqm7GlMyNRJ
Ne/5uWRGSzaMYuGmwsPpERzqEvYFnSrpjW5YtXZ+JtxFXNVfm9Z1gLLgvGpOUCIU
RbpoDckDe1vgUuk3y5+DjZihs+rqIJ45XzXTzBkCgYBWuf3segruJZy5rEKhTv+o
JqeUvRn0jNYYKFpLBeyTVBrbie6GkbUGNIWbrK05pC+c3K9nosvzuRUOQQL1tJbd
4gA3oiD9U4bMFNr+BRTHyZ7OQBcIXdz3t1qhuHVKtnngIAN1p25uPlbRFUNpshnt
jgeVoHlsBhApcs5DUc+pyQKBgDzeHPg/+g4z+nrPznjKnktRY1W+0El93kgi+J0Q
YiJacxBKEGTJ1MKBb8X6sDurcRDm22wMpGfd9I5Cv2v4GsUsF7HD/cx5xdih+G73
c4clNj/k0Ff5Nm1izPUno4C+0IOl7br39IPmfpSuR6wH/h6iHQDqIeybjxyKvT1G
N0rRAoGBAKGD+4ZI/E1MoJ5CXB8cDDMHagbE3cq/DtmYzE2v1DFpQYu5I4PCm5c7
EQeIP6dZtv8IMgtGIb91QX9pXvP0aznzQKwYIA8nZgoENCPfiMTPiEDT9e/0lObO
9XWsXpbSTsRPj0sv1rB+UzBJ0PgjK4q2zOF0sNo7b1+6nlM3BWPx
-----END RSA PRIVATE KEY-----
"

let expected_protected =
  "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6" ^
  "IlJTQSIsIm4iOiI0eGdaM2VSUGt3b1J2eTdxZVJVYm1NRGUwVi14" ^
  "SDllV0xkdTBpaGVlTGxybUQybXFXWGZQOUllU0tBcGJuMzRnOFR1" ^
  "QVM5ZzV6aHE4RUxRM2ttanItS1Y4NkdBTWdJNlZBY0dscTNRcnpw" ^
  "VENmXzMwQWI3LXphd3JmUmFGT05hMUh3RXpQWTFLSG5HVmt4SmM4" ^
  "NWdOa3dZSTlTWTJSSFh0dmxuM3pzNXdJVE5yZG9zcUVYZWFJa1ZZ" ^
  "QkVoYmhOdTU0cHAza3hvNlR1V0xpOWU2cFhlV2V0RXdtbEJ3dFda" ^
  "bFBvaWIyajNUeExCa3NLWmZveUZ5ZWszODBtSGdKQXVtUV9JMmZq" ^
  "ajk4Xzk3bWszaWhPWTRBZ1ZkQ0RqMXpfR0NvWmtHNVJxN25iQ0d5" ^
  "b3N5S1d5RFgwMFpzLW5OcVZob0xlSXZYQzRubldkSk1aNnJvZ3h5" ^
  "UVEifSwibm9uY2UiOiJub25jZSJ9"

let expected_payload = "eyJNc2ciOiJIZWxsbyBKV1MifQ"

let expected_signature =
  "eAGUikStX_UxyiFhxSLMyuyBcIB80GeBkFROCpap2sW3EmkU_ggF" ^
  "knaQzxrTfItICSAXsCLIquZ5BbrSWA_4vdEYrwWtdUj7NqFKjHRa" ^
  "zpLHcoR7r1rEHvkoP1xj49lS5fc3Wjjq8JUhffkhGbWZ8ZVkgPdC" ^
  "4tMBWiQDoth-x8jELP_3LYOB_ScUXi2mETBawLgOT2K8rA0Vbbmx" ^
  "hWNlOWuUf-8hL5YX4IOEwsS8JK_TrTq5Zc9My0zHJmaieqDV0UlP" ^
  "k0onFjPFkGm7MrPSgd0MqRG-4vSAg2O4hDo7rKv4n8POjjXlNQvM" ^
  "9IPLr8qZ7usYBKhEGwX3yq_eicAwBw"

let rsa_key () =
  match Primitives.priv_of_pem testkey_pem with
  | Some skey -> skey
  | _ -> raise (Failure "Unable to parse test RSA key.")

let jws_encode_somedata () =
  let priv_key = rsa_key () in
  let data  = {|{"Msg":"Hello JWS"}|} in
  let nonce = "nonce" in
  let jws = Jws.encode priv_key data nonce in
  match Json.of_string jws with
  | Ok json -> json
  | Error e -> assert_failure e


let test_member member expected test_ctx =
  let jws = jws_encode_somedata () in
  match Json.string_member member jws with
  | Ok protected -> assert_equal protected expected
  | Error e -> assert_failure e

let test_encode_protected = test_member "protected" expected_protected
let test_encode_payload = test_member "payload" expected_payload
let test_encode_signature = test_member "signature" expected_signature

let test_decode_null test_ctx =
  assert_equal (Jws.decode "{}") (Error "couldn't find string protected in {}")

let jws_decode_somedata () =
  let data = Printf.sprintf
      {|{"protected": "%s", "payload": "%s", "signature": "%s"}|}
      expected_protected expected_payload expected_signature in
  Jws.decode data

let test_decode_rsakey text_ctx =
  let jws = jws_decode_somedata () in
  let key = rsa_key () in
  match jws with
  | Error e -> assert_failure e
  | Ok (protected, payload) ->
    let pub = Primitives.pub_of_priv key in
    assert_equal protected.Jws.jwk (Some (`Rsa pub))

(* XXX. at this stage we probably wont the expected payload to be on some
 * global variable. *)
let test_decode_payload text_ctx =
  match jws_decode_somedata () with
  | Error e -> assert_failure e
  | Ok (_, payload) ->
    assert_equal payload {|{"Msg":"Hello JWS"}|}


let all_tests = [
  "test_encode_protected" >:: test_encode_protected;
  "test_encode_payload" >:: test_encode_payload;
  "test_edincode_signature" >:: test_encode_signature;

  "test_decode_null" >:: test_decode_null;
  "test_decode_rsakey" >:: test_decode_rsakey;
  "test_decode_payload" >:: test_decode_payload;
]
