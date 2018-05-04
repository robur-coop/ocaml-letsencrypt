open Nocrypto.Rsa

val priv_of_pem : string -> (priv, string) result

val pub_of_priv : priv -> pub
val pub_of_z : e:Z.t -> n:Z.t -> pub
val pub_to_z : pub -> Z.t * Z.t

val rs256_sign : priv -> string -> string
val rs256_verify : pub -> string -> string -> bool

val sha256 : string -> string
