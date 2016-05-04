open Acme
open Lwt

let rsa_pem = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvdRJgNJ9FC1+MiGqzFA3U+qyKH4+uELs5kAZxu110vHvAbja
7F7H3xBa1fn1B08nqI1nZVhEprTG7X4JmIKC1F+zNxzY2ySSl1uzVHvI1MkEAmpv
nydqGXX/QJ4JHSblzQM0QrybJZv9DHXNN8iU2qJoH1PCUw3F7O1OQlrVYjslXZoU
YQgH+jtPtEY+7dEZdMXzD9Xe5Fa5GSu+r+fFBKcAiaKdfB6bXm7j4m0XjVFbYefi
TtPYY0qAqMqb1kQJ1mwlRaRIrXBxitX9rAkPiZedTU9zdjVK3/AZOcUTjxPKoHUW
FpZ26Tw2JJEVLxwDm240QaU7R7B9SMMwXS995wIDAQABAoIBAQCDye0Z1YhmyMqz
DTKh1BMFXIxBlpv+muATXm9G7zb8s2BGZsr+jTLgB1+47GcTov2ahElDT8uhnSH6
YaVRz1H7FVG7snhPdA2drVlMDwA30jLJZpGGAfwkHwqOFumm5olmEpJmvsBLlQdS
bjqCPuww+c2l6iWgOZCu03WglaVNIyU7dd6yJDGI7lIlei3AZ+QwnlDuNwpzT1ua
BoHLpM7MMNTDiUNo5lD1OYoH4/py0v6UfICOqkBS7BcLJ7SSUwEwc/btQgdzoHbq
9WSH6ii4Hnf1AdRKfd9ZGasc2SlpZbXNCyPSc5L9PdsHRIFbK4Lmy5n+aR8n8mP7
yZWtWW4pAoGBAPP7ySHdgOWu9Tp1+EReqZ4uBCQBVhirmr4rqVBEtvXPUcYNT1ga
Ky67ufkOVQSpV5jU0c7Lc7uXwqUCVg+wIHP+mIJ0LamBr4eo9ZVPRfnxUP4h5Jc0
HaD9UVcwZNLMda3DXP3oJiRbK/1PeyPp95So/tTr+IoSIE6G53Jc6hBTAoGBAMct
tWkNgdAoYQiRaWmJ33nVSN6qzDkxBX2ptDcwK8KMePq/IlfjIwULB8ndtaz6mOc1
7mug+j6r1CRqlFmWz98UoxPDZboePqyLphYVmB9a8Lub3qs9AsMXk582GXbsYecJ
TUVwB72EA+vD+miTf2b2FuWcZ5Wa8al/kFPf2zmdAoGABSQoH9uQDMb8CehUe/RW
tKuZkLyqeMic8SbwYW2hQVrGCVtccanTgR+ZkqL3rap32xOY/DeTT7+p7Vo4QAph
FLCnvBAAqlK+RSiNTEEoY1TvdPt32qvReAP+g8zUQxDl5ex4+Cy9KQT2z1aubJpQ
ikRpYkk6qoYpQh5boDBPClsCgYEAkpRa2xLro6rzrgCFWPv0EI8b73I2lSg0aERJ
sgurSKNkLPQYbCFmFkIF21NkbgaGHDGeYmq3fwOpPZuJzVylYgCn+tVjudKkQQsM
kVgW+YxNeWO+PLrLm5NwOkzv9IsFiadYzG8j4x6SXCF/2RIjQjx8oUG3IWxDyH9u
Uat+hCkCgYBRfwK7usbZWP4YfzmnQc3BP4RRfPl3bTBqkUu2IsB6lU9J7NjVP+62
oWu3/HQxkbjaBDOCCyQm7gOrF3Na1uclfNdIYhK94w1TQnWBaM3MYRHGjAYm1XNU
KQG6J8U2wCaf+W2C4gyEih9ygAaqIRQvFDwOz2QB3BSrmjO5380J2A==
-----END RSA PRIVATE KEY-----"
let csr_pem = "-----BEGIN CERTIFICATE REQUEST-----
MIICoTCCAYkCAQAwXDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEVMBMGA1UEAwwMdGVz
dHRlc3QuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvdRJgNJ9
FC1+MiGqzFA3U+qyKH4+uELs5kAZxu110vHvAbja7F7H3xBa1fn1B08nqI1nZVhE
prTG7X4JmIKC1F+zNxzY2ySSl1uzVHvI1MkEAmpvnydqGXX/QJ4JHSblzQM0Qryb
JZv9DHXNN8iU2qJoH1PCUw3F7O1OQlrVYjslXZoUYQgH+jtPtEY+7dEZdMXzD9Xe
5Fa5GSu+r+fFBKcAiaKdfB6bXm7j4m0XjVFbYefiTtPYY0qAqMqb1kQJ1mwlRaRI
rXBxitX9rAkPiZedTU9zdjVK3/AZOcUTjxPKoHUWFpZ26Tw2JJEVLxwDm240QaU7
R7B9SMMwXS995wIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAJpmMQZLIanx4de0
ZZyr4ii8G8QvGSwcQYaFA6LfgqCG9D8Gc2gv2x9LxdH8RKaUGhxyGG0c0UIrn9Cj
YQtt7/CHzA6qtXNXG/tGpSBQt0dFoiMqv20zKgbsXtaMkYQEt0cdIaCAfzCwvcqa
LHCzKk8o6JX1a36zO17Pi59gEhLO9lB9G1yUQbO9fIqH0xrTuiW1wa70jxcf+YRy
lMFWuFwR6Vox1rREdvDzLUGbFgO55vS6rbR8Izy36g3TNk1frDzWiHWu/LObK6eM
a/iy9uSmi/dfYHsuegl8+wVOZ4XZVZYPkY1W8+uF/eGFKCgoGCDO+nmRpnl3uk+N
yI1yUP0=
-----END CERTIFICATE REQUEST-----"

let () =
  let main =
    Nocrypto_entropy_lwt.initialize () >>= fun () ->
    new_cli (Cstruct.of_string rsa_pem) (Cstruct.of_string csr_pem) >>= function
    | `Error _ -> Lwt.fail End_of_file
    | `Ok cli -> new_reg cli >>= fun (code, headers, body) ->
                 (Printf.sprintf "Code: %d\n Headers: %s\n Body: %s"
                                 code (Cohttp.Header.to_string headers) body) |> Lwt.return

  in
  let message = Lwt_main.run main in
  print_endline message
