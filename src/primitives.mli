open Mirage_crypto_pk.Rsa

val pub_of_priv : priv -> pub
val pub_of_z : e:Z.t -> n:Z.t -> (pub, [> `Msg of string ]) result
val pub_to_z : pub -> Z.t * Z.t

val rs256_sign : priv -> string -> string
val rs256_verify : pub -> string -> string -> bool

val sha256 : string -> string
